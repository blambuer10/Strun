use anchor_lang::prelude::*;
use anchor_lang::solana_program::{ed25519_program, sysvar::instructions as ix_sysvar};
use anchor_spl::token::{self, Mint, Token, TokenAccount, Transfer};
use std::convert::TryInto;

declare_id!("14QZkEhSgwPK3cWqHeSkgpGBscibYuEWyJ1BVEGJqfbC"); // değiştir deploy ID ile

#[program]
pub mod strun {
    use super::*;

    /// Create an on-chain Task (sponsored or metadata-only).
    /// - `task_seed` (arbitrary bytes) is used so the client can choose a stable PDA.
    /// - Long text / media are stored off-chain; on-chain we store short meta and hash.
    pub fn create_task(
        ctx: Context<CreateTask>,
        bump: u8,
        task_type: TaskKind,
        reward_amount: u64, // lamports for SOL reward if using SOL; if using SPL then handled via pool funding
        max_winners: u32,
        metadata_hash: [u8; 32], // e.g. blake3/sha256 hash of task JSON stored off-chain
    ) -> Result<()> {
        let task = &mut ctx.accounts.task;
        task.creator = ctx.accounts.creator.key();
        task.bump = bump;
        task.kind = task_type;
        task.reward_lamports = reward_amount;
        task.max_winners = max_winners;
        task.metadata_hash = metadata_hash;
        task.pool = Pubkey::default();
        task.status = TaskStatus::Pending;
        task.created_at = Clock::get()?.unix_timestamp;
        Ok(())
    }

    /// Create a Pool PDA tied to a task and optionally fund it (in SOL lamports).
    /// To fund with SOL: caller must sign and the lamports will be moved into the pool PDA.
    /// For SPL token funding, use `fund_pool_spl`.
    pub fn create_and_fund_pool(
        ctx: Context<CreateFundPool>,
        pool_bump: u8,
        min_participants: u32,
        backend_pubkey: Pubkey,
        fund_amount_lamports: u64, // amount to transfer into pool (in lamports)
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        pool.task = ctx.accounts.task.key();
        pool.creator = ctx.accounts.funder.key();
        pool.bump = pool_bump;
        pool.total_funded = 0;
        pool.total_claimed = 0;
        pool.min_participants = min_participants;
        pool.backend_pubkey = backend_pubkey;
        pool.closed = false;
        pool.created_at = Clock::get()?.unix_timestamp;

        // Transfer lamports from funder (signer) to pool PDA by direct lamports mutation
        if fund_amount_lamports > 0 {
            let funder_info = ctx.accounts.funder.to_account_info();
            let pool_info = ctx.accounts.pool.to_account_info();
            **funder_info.try_borrow_mut_lamports()? = funder_info
                .lamports()
                .checked_sub(fund_amount_lamports)
                .ok_or(ErrorCode::InsufficientFunds)?;
            **pool_info.try_borrow_mut_lamports()? = pool_info
                .lamports()
                .checked_add(fund_amount_lamports)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            pool.total_funded = pool
                .total_funded
                .checked_add(fund_amount_lamports)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
        }
        // Link pool to task
        let task = &mut ctx.accounts.task;
        task.pool = ctx.accounts.pool.key();
        task.status = TaskStatus::Active;
        Ok(())
    }

    /// Fund pool with SOL (additional funds)
    pub fn fund_pool(ctx: Context<FundPool>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::InvalidAmount);
        let funder_info = ctx.accounts.funder.to_account_info();
        let pool_info = ctx.accounts.pool.to_account_info();
        **funder_info.try_borrow_mut_lamports()? = funder_info
            .lamports()
            .checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;
        **pool_info.try_borrow_mut_lamports()? = pool_info
            .lamports()
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        let pool = &mut ctx.accounts.pool;
        pool.total_funded = pool
            .total_funded
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        Ok(())
    }

    /// Fund pool with SPL token (ex: USDC or custom reward token).
    /// Here we do CPI to token program (transfer from funder token account -> pool_token_account PDA).
    pub fn fund_pool_spl(ctx: Context<FundPoolSPL>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::InvalidAmount);
        let cpi_accounts = token::Transfer {
            from: ctx.accounts.funder_token_account.to_account_info(),
            to: ctx.accounts.pool_token_account.to_account_info(),
            authority: ctx.accounts.funder.to_account_info(),
        };
        let cpi_program = ctx.accounts.token_program.to_account_info();
        let signer_seeds: &[&[&[u8]]] = &[];
        token::transfer(CpiContext::new(cpi_program, cpi_accounts), amount)?;
        let pool = &mut ctx.accounts.pool;
        pool.spl_total_funded = pool
            .spl_total_funded
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        Ok(())
    }

    /// Claim reward: requires an ed25519 verification instruction in the same tx that proves
    /// the backend (oracle) signed the canonical payload.
    /// nonce prevents replay — Claim PDA must not exist before (we create it with init here).
    pub fn claim_reward(
        ctx: Context<ClaimReward>,
        amount: u64,
        nonce: u64,
        ed_ix_index: u8,
    ) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        require!(!pool.closed, ErrorCode::PoolClosed);
        // Check availability (for SOL)
        require!(pool.total_funded >= amount, ErrorCode::InsufficientFunds);

        // Build expected message bytes
        let mut expected_msg: Vec<u8> = b"claim:".to_vec();
        expected_msg.extend_from_slice(ctx.accounts.pool.key.as_ref()); // pool pubkey 32 bytes
        expected_msg.extend_from_slice(ctx.accounts.recipient.key.as_ref()); // recipient pubkey 32 bytes
        expected_msg.extend_from_slice(&amount.to_le_bytes()); // 8 bytes
        expected_msg.extend_from_slice(&nonce.to_le_bytes()); // 8 bytes

        // Extract ed25519 instruction at given index
        let ix_data =
            ix_sysvar::load_instruction_at(ed_ix_index as usize, &ctx.accounts.instructions_sysvar)
                .map_err(|_| error!(ErrorCode::InvalidEd25519Instruction))?;
        require!(
            ix_data.program_id == ed25519_program::id(),
            ErrorCode::InvalidEd25519Instruction
        );

        // Robust parse of ed25519 instruction to get message bytes
        let data = &ix_data.data;
        if data.len() < 12 {
            return err!(ErrorCode::InvalidEd25519Instruction);
        }
        let sig_count = data[0] as usize;
        require!(sig_count >= 1, ErrorCode::InvalidEd25519Instruction);

        // parse first signature entry (same format as ed25519_program instruction)
        let header_entry_start = 1usize;
        let entry_len = 11usize; // 2+1 +2+1 +2+2+1 = 11
        if data.len() < header_entry_start + entry_len {
            return err!(ErrorCode::InvalidEd25519Instruction);
        }

        fn read_u16_le(slice: &[u8], i: usize) -> Result<u16> {
            if slice.len() < i + 2 {
                return Err(error!(ErrorCode::InvalidEd25519Instruction));
            }
            Ok(u16::from_le_bytes([slice[i], slice[i + 1]]))
        }

        let sig_offset = read_u16_le(data, 1)? as usize;
        let _sig_inst_idx = data[3];
        let pubkey_offset = read_u16_le(data, 4)? as usize;
        let _pubkey_inst_idx = data[6];
        let msg_offset = read_u16_le(data, 7)? as usize;
        let msg_len = read_u16_le(data, 9)? as usize;
        let _msg_inst_idx = data[11];

        if data.len() < msg_offset + msg_len {
            return err!(ErrorCode::InvalidEd25519Instruction);
        }
        let msg_slice = &data[msg_offset..msg_offset + msg_len];

        // exact match
        require!(
            msg_slice == expected_msg.as_slice(),
            ErrorCode::Ed25519MsgMismatch
        );

        // check backend pubkey presence match (if pool has backend_pubkey set)
        if pool.backend_pubkey != Pubkey::default() {
            if data.len() < pubkey_offset + 32 {
                return err!(ErrorCode::InvalidEd25519Instruction);
            }
            let instr_pubkey_slice = &data[pubkey_offset..pubkey_offset + 32];
            require!(
                instr_pubkey_slice == pool.backend_pubkey.as_ref(),
                ErrorCode::Ed25519PubkeyMismatch
            );
        }

        // All good - transfer lamports from pool PDA to recipient
        let pool_info = ctx.accounts.pool.to_account_info();
        let recipient_info = ctx.accounts.recipient.to_account_info();
        **pool_info.try_borrow_mut_lamports()? = pool_info
            .lamports()
            .checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;
        **recipient_info.try_borrow_mut_lamports()? = recipient_info
            .lamports()
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        pool.total_funded = pool
            .total_funded
            .checked_sub(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        pool.total_claimed = pool
            .total_claimed
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;

        // The Claim PDA (init in accounts) is filled to prevent replay
        let claim = &mut ctx.accounts.claim;
        claim.pool = ctx.accounts.pool.key();
        claim.nonce = nonce;
        claim.recipient = ctx.accounts.recipient.key();
        claim.amount = amount;
        claim.issued_at = Clock::get()?.unix_timestamp;

        Ok(())
    }

    /// Stake SOL into pool for optional benefits (off-chain boost, on-chain recognition)
    pub fn stake(ctx: Context<StakeIntoPool>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::InvalidAmount);
        let staker_info = ctx.accounts.staker.to_account_info();
        let stake_acc_info = ctx.accounts.stake_acc.to_account_info();

        **staker_info.try_borrow_mut_lamports()? = staker_info
            .lamports()
            .checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;
        **stake_acc_info.try_borrow_mut_lamports()? = stake_acc_info
            .lamports()
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;

        let stake_acc = &mut ctx.accounts.stake_acc;
        stake_acc.owner = ctx.accounts.staker.key();
        stake_acc.pool = ctx.accounts.pool.key();
        stake_acc.amount = stake_acc
            .amount
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        stake_acc.updated_at = Clock::get()?.unix_timestamp;
        Ok(())
    }

    /// Unstake (withdraw) staked SOL back to staker (basic logic; can include slashing/lockups)
    pub fn unstake(ctx: Context<UnstakeFromPool>, amount: u64) -> Result<()> {
        require!(amount > 0, ErrorCode::InvalidAmount);
        let stake_acc = &mut ctx.accounts.stake_acc;
        require!(stake_acc.amount >= amount, ErrorCode::InsufficientFunds);

        let stake_acc_info = ctx.accounts.stake_acc.to_account_info();
        let receiver_info = ctx.accounts.receiver.to_account_info();

        **stake_acc_info.try_borrow_mut_lamports()? = stake_acc_info
            .lamports()
            .checked_sub(amount)
            .ok_or(ErrorCode::InsufficientFunds)?;
        **receiver_info.try_borrow_mut_lamports()? = receiver_info
            .lamports()
            .checked_add(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;

        stake_acc.amount = stake_acc
            .amount
            .checked_sub(amount)
            .ok_or(ErrorCode::ArithmeticOverflow)?;
        stake_acc.updated_at = Clock::get()?.unix_timestamp;
        Ok(())
    }

    /// Close pool and refund remaining lamports to creator (only creator)
    pub fn close_pool(ctx: Context<ClosePool>) -> Result<()> {
        let pool = &mut ctx.accounts.pool;
        require!(
            ctx.accounts.creator.key == pool.creator,
            ErrorCode::Unauthorized
        );
        require!(!pool.closed, ErrorCode::PoolClosed);

        let pool_info = ctx.accounts.pool.to_account_info();
        let creator_info = ctx.accounts.creator.to_account_info();
        let remaining = pool_info.lamports();
        if remaining > 0 {
            **pool_info.try_borrow_mut_lamports()? = pool_info
                .lamports()
                .checked_sub(remaining)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
            **creator_info.try_borrow_mut_lamports()? = creator_info
                .lamports()
                .checked_add(remaining)
                .ok_or(ErrorCode::ArithmeticOverflow)?;
        }
        pool.closed = true;
        Ok(())
    }

    /// Admin function: mark task as archived/disabled (only task creator or admin)
    pub fn close_task(ctx: Context<CloseTask>) -> Result<()> {
        let task = &mut ctx.accounts.task;
        require!(
            ctx.accounts.authority.key() == task.creator,
            ErrorCode::Unauthorized
        );
        task.status = TaskStatus::Closed;
        Ok(())
    }
}

/// Accounts and state definitions

#[account]
pub struct Task {
    pub creator: Pubkey,
    pub bump: u8,
    pub kind: TaskKind,
    pub reward_lamports: u64,
    pub max_winners: u32,
    pub metadata_hash: [u8; 32],
    pub pool: Pubkey, // pool PDA if created
    pub status: TaskStatus,
    pub created_at: i64,
    pub _reserved: [u8; 64],
}

#[account]
pub struct Pool {
    pub task: Pubkey,
    pub creator: Pubkey,
    pub bump: u8,
    pub total_funded: u64,
    pub total_claimed: u64,
    pub min_participants: u32,
    pub backend_pubkey: Pubkey, // ed25519 pubkey of backend oracle
    pub spl_mint: Pubkey,       // optional SPL mint if pool funded in token
    pub spl_total_funded: u64,
    pub created_at: i64,
    pub closed: bool,
    pub _reserved: [u8; 32],
}

#[account]
pub struct Claim {
    pub pool: Pubkey,
    pub nonce: u64,
    pub recipient: Pubkey,
    pub amount: u64,
    pub issued_at: i64,
    pub _reserved: [u8; 32],
}

#[account]
pub struct StakeAccount {
    pub owner: Pubkey,
    pub pool: Pubkey,
    pub amount: u64,
    pub updated_at: i64,
    pub _reserved: [u8; 32],
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub enum TaskKind {
    Personal,  // AI-generated personal tasks (only visible to user)
    Sponsored, // visible to all
    QRCheckin,
}

#[derive(AnchorSerialize, AnchorDeserialize, Clone, PartialEq, Eq)]
pub enum TaskStatus {
    Pending,
    Active,
    Closed,
}

#[derive(Accounts)]
#[instruction(bump: u8)]
pub struct CreateTask<'info> {
    #[account(mut)]
    pub creator: Signer<'info>,

    /// Task PDA: seeds = ["task", creator_pubkey, task_seed_pubkey]
    #[account(
        init,
        payer = creator,
        space = 8 + std::mem::size_of::<Task>(),
        seeds = [b"task", creator.key.as_ref(), task_seed.key.as_ref()],
        bump = bump
    )]
    pub task: Account<'info, Task>,

    /// a 32-byte account used as opaque seed (can be any Keypair.pubkey)
    /// CHECK: seed only
    pub task_seed: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
#[instruction(pool_bump: u8)]
pub struct CreateFundPool<'info> {
    #[account(mut)]
    pub funder: Signer<'info>,

    /// Pool PDA seeds: ["pool", task_pubkey]
    #[account(
        init,
        payer = funder,
        space = 8 + std::mem::size_of::<Pool>(),
        seeds = [b"pool", task.key().as_ref()],
        bump = pool_bump
    )]
    pub pool: Account<'info, Pool>,

    #[account(mut, has_one = creator)]
    pub task: Account<'info, Task>,

    /// CHECK: used as seed only in task creation; here pass same seed account used earlier
    pub task_seed: UncheckedAccount<'info>,

    #[account(mut)]
    pub creator: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FundPool<'info> {
    #[account(mut)]
    pub funder: Signer<'info>,

    #[account(mut)]
    pub pool: Account<'info, Pool>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct FundPoolSPL<'info> {
    #[account(mut)]
    pub funder: Signer<'info>,

    #[account(mut)]
    pub funder_token_account: Account<'info, TokenAccount>,

    /// Pool PDA has an associated token account (pool_token_account) controlled by program (PDA owner)
    #[account(mut)]
    pub pool_token_account: Account<'info, TokenAccount>,

    #[account(mut)]
    pub pool: Account<'info, Pool>,

    pub token_program: Program<'info, Token>,
}

#[derive(Accounts)]
#[instruction(amount: u64, nonce: u64)]
pub struct ClaimReward<'info> {
    #[account(mut)]
    pub recipient: Signer<'info>,

    /// Pool PDA account (escrow)
    #[account(mut, has_one = creator)]
    pub pool: Account<'info, Pool>,

    /// Claim PDA: seeds = ["claim", pool_pubkey, nonce_le_bytes]
    #[account(
        init,
        payer = recipient,
        space = 8 + std::mem::size_of::<Claim>(),
        seeds = [b"claim", pool.key().as_ref(), &nonce.to_le_bytes()],
        bump
    )]
    pub claim: Account<'info, Claim>,

    /// Sysvar instructions (to find ed25519 instruction)
    #[account(address = ix_sysvar::id())]
    pub instructions_sysvar: UncheckedAccount<'info>,

    /// CHECK: pool.creator (used for has_one check above)
    pub creator: UncheckedAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct StakeIntoPool<'info> {
    #[account(mut)]
    pub staker: Signer<'info>,

    #[account(mut)]
    pub stake_acc: Account<'info, StakeAccount>,

    #[account(mut)]
    pub pool: Account<'info, Pool>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct UnstakeFromPool<'info> {
    #[account(mut, has_one = owner)]
    pub stake_acc: Account<'info, StakeAccount>,

    #[account(mut)]
    pub owner: Signer<'info>,

    /// receiver of unstaked lamports
    #[account(mut)]
    pub receiver: SystemAccount<'info>,

    pub system_program: Program<'info, System>,
}

#[derive(Accounts)]
pub struct ClosePool<'info> {
    #[account(mut, has_one = creator)]
    pub pool: Account<'info, Pool>,

    #[account(mut)]
    pub creator: Signer<'info>,
}

#[derive(Accounts)]
pub struct CloseTask<'info> {
    #[account(mut)]
    pub task: Account<'info, Task>,

    /// authority must be creator (or admin in off-chain logic)
    pub authority: Signer<'info>,
}

/// Errors
#[error_code]
pub enum ErrorCode {
    #[msg("Pool closed")]
    PoolClosed,
    #[msg("Insufficient funds")]
    InsufficientFunds,
    #[msg("Invalid ed25519 instruction")]
    InvalidEd25519Instruction,
    #[msg("ed25519 message mismatch")]
    Ed25519MsgMismatch,
    #[msg("ed25519 pubkey mismatch")]
    Ed25519PubkeyMismatch,
    #[msg("Arithmetic overflow")]
    ArithmeticOverflow,
    #[msg("Unauthorized")]
    Unauthorized,
    #[msg("Invalid amount")]
    InvalidAmount,
}

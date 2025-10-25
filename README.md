Strun — Move. Play. Earn. 🚀🏃‍♂️

A location-based Web3 app that turns real-world movement into rewards. Users complete geo-tasks (QR check-ins, selfie meetups, partner visits), earn XP, mint NFTs tied to map areas, and claim on-chain rewards on Solana. This repo contains the backend APIs, DB migrations, and mobile components (Expo / React Native) for QR and Selfie modules — ready to run, extend, and deploy.

Project: Strun Tagline: Move. Play. Earn. Network: Solana (mainnet/devnet) Off-chain proofs & media: IPFS (Pinata by default). Optional: Walrus integration for alternative metadata hosting (docs & examples included).

Table of contents

Key features

Architecture & components

Tech stack

Quick start (dev)

Environments & .env template

Database migrations

Backend API endpoints (summary)

Mobile (Expo) overview

Solana integration & minting

IPFS / Pinata integration

Security & anti-cheat notes

Testing & deployment checklist

Roadmap

Contributing

License & credits

Key features

Geo-task engine: QR check-ins, selfie meetups, partner tasks.

IPFS-backed immutable proofs (images, JSON proofs).

Off-chain XP ledger; on-chain minting for NFTs / token rewards on Solana.

Grouping worker: automatically groups selfie submissions and approves when rules match.

Admin/dev endpoints to create partners, tasks and generate signed QR tokens.

Mobile-ready camera flows with nonce overlay to prevent simple replay attacks.

Optional Walrus/alternative metadata hosting integration (examples included).

Architecture & components Mobile (Expo/React Native) ↕ HTTPS (mobile → backend) Backend (Node.js / Express) ↔ Postgres (users, tasks, claims) ↔ IPFS (Pinata) - pins images & proofs ↔ Solana RPC (Helius / QuickNode) - mint & rewards ↔ Worker (grouping) - approves selfie groups

Tech stack

Frontend (mobile): React Native (Expo), expo-location, expo-camera, expo-barcode-scanner

Backend: Node.js, Express, PostgreSQL, formidable (multipart), Axios

IPFS pinning: Pinata (default) — Walrus optional

Blockchain: Solana (@solana/web3.js, Metaplex example / voucher pattern) + Helius RPC

Optional infra: Redis (nonce store, rate limit), Sentry for errors

Quick start (dev)

These steps assume you have Node.js, PostgreSQL and Expo installed locally.

Clone

git clone https://github.com/blambuer10/strun.git cd strun

Server (backend)

cd server cp .env.example .env

edit .env with your values (see template below)
npm install

apply DB migrations (or run 001_init.sql / 002_selfie.sql)
npm run migrate npm run dev

Mobile (Expo)

cd mobile npm install expo start

run on device or simulator
Dev flow

Create a dev user & partner:

POST /api/dev/create-user → returns user_id

POST /api/dev/create-partner → returns partner_location_id

POST /api/dev/create-task → create a task (type qr or selfie)

Generate QR token: node server/tools/generate_qr_token.js <TASK_ID> <QR_SECRET>

On mobile: use the QR scanner or selfie flow.

Environments & .env template

Create a .env in server/ (never commit secrets):

server/.env
PORT=4000 DATABASE_URL=postgresql://postgres:password@localhost:5432/strun PINATA_API_KEY=your_pinata_api_key PINATA_API_SECRET=your_pinata_api_secret GLOBAL_QR_SECRET=some_random_secret_for_hmac NONCE_TTL_SEC=120 GROUPING_INTERVAL_SEC=30 SOLANA_RPC_URL=https://api.devnet.solana.com SOLANA_KEYPAIR_PATH=path/to/payer-keypair.json

Optional: Helius or QuickNode
HELIUS_RPC=https://mainnet.helius-rpc.com/?api-key=YOUR_HELIUS_KEY

WALRUS optional: WALRUS_NODE_URL=...
Important: Do not commit .env or any secret keys. Use secret management in production.

Database migrations

Migrations are provided under server/migrations/:

001_init.sql — core tables: users, partner_locations, tasks, user_tasks.

002_selfie.sql — indices and optional schema updates.

Apply using psql or npm run migrate (configured to run psql $DATABASE_URL -f ...).

Backend API endpoints (summary)

Important endpoints (see implementation server/routes/*.js):

GET /api/tasks/nearby?lat=&lon=&radius_m= — list nearby tasks

POST /api/tasks/qr/claim — submit a QR claim (token, location, timestamp)

GET /api/tasks/:id/nonce — request a nonce for selfie task

POST /api/tasks/selfie/submit — submit selfie (multipart: image, user_id, task_id, lat, lon, timestamp, nonce)

Dev endpoints: /api/dev/create-user, /api/dev/create-partner, /api/dev/create-task

Health: GET /health

Mobile (Expo) overview

Mobile modules include:

ScanQR.js — in-app QR scanner and submit payload (captures location).

SelfieTask.js — in-app camera with nonce overlay, capture + multipart upload.

Map pages use MapLibre or MapTiler-compatible styles (recommended).

Integrate serverUrl, userId and taskId into components. Use high-accuracy GPS for claims, and ensure camera overlay is enforced on selfie tasks.

Solana integration & minting

XP is stored off-chain (Postgres). Use XP as platform currency to enable mints, rentals, or airdrops.

NFT minting approaches:

Server-side mint (platform mints on behalf): easier but server holds payer key (custodial).

Voucher redemption (recommended): server issues signed voucher + metadata IPFS; user redeems in their wallet to mint on-chain (user pays txn).

Example libs: @solana/web3.js, Metaplex JS SDK. Use Helius / QuickNode RPC for reliability.

Place payer key securely in production (KMS / secret manager). Never commit keypairs.

IPFS / Pinata integration

Backend pins proofs (images & JSON) to IPFS via Pinata REST endpoints. server/pinata.js shows helper wrappers.

Store ipfs://CID or https://gateway.pinata.cloud/ipfs/CID in DB as immutable proof.

Optionally run your own IPFS node or use Walrus for metadata hosting — Walrus examples provided in /integrations/walrus/.

Security & anti-cheat notes

Nonce overlay for selfie tasks: server issues a short-lived nonce to be shown in the photo to prevent gallery replays.

HMAC-signed QR tokens: tokens include task_id|timestamp|sig — signature verified on backend.

Distance & timestamp checks: the backend validates user GPS vs partner location and token freshness.

Rate limiting & device attestation: consider Redis-based rate limiter and SafetyNet/DeviceCheck for production.

Manual review queue: provide admin UI for flagged submissions.

Testing & deployment checklist

Run DB migrations on target DB.

Ensure Pinata / IPFS credentials are set and tested.

Validate Solana RPC endpoint and payer account.

Test QR flow end-to-end: generate token → scan → claim → XP increment.

Test Selfie flow: nonce → capture → submit → worker grouping → approval.

Configure logging & monitoring (Sentry / Prometheus).

Use HTTPS and set proper CORS for mobile/web origins.

Store secrets with secure vault (AWS Secrets Manager, GCP Secret Manager, etc.)

Roadmap

✅ QR check-in module (backend + mobile)

✅ Selfie meetup module with grouping worker

🔜 NFT voucher model + user redemption (Metaplex)

🔜 Group runs, area-claim NFTs (map drawing & mint)

🔜 Marketplace for renting/ trading area NFTs & XP → token conversion (Pumpfun)

🔜 Walrus optional integration for decentralized metadata hosting

Troubleshooting (common issues)

redirect_uri_mismatch (OAuth / zkLogin): ensure the redirect URI set in Google Console exactly matches the one used in the OAuth request (including trailing slash and scheme).

Location not found on mobile: enable high accuracy GPS, check app permissions, and ensure the Expo app is allowed to access location in device settings.

IPFS pin fails: confirm Pinata API key/secret and rate limits.

Worker not approving: ensure user_tasks contains start_lat/start_lon and grouping worker has access to DB; check GROUPING_INTERVAL_SEC.

Contributing

Fork the repo

Create a branch: feature/your-feature

Commit & push changes, open a PR with description and testing steps

We use lint, prettier and unit tests; run before PR

License & credits

License: MIT

Credits: inspired by Walrus & Sui community tooling; Solana ecosystem (Helius, Metaplex); mapping by MapTiler / MapLibre.

Contact

Questions, issues, or ideas? Open an issue or ping the maintainers at info@strun.fun (or the GitHub repo).

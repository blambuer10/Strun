# Solana Mobile dApp Store Deployment Guide

This guide covers the complete process of deploying STRUN to Solana Mobile dApp Store.

## Prerequisites

- [x] PWA built and deployed to production domain (strun.app)
- [x] Node.js LTS installed
- [x] Java JDK 17+ installed
- [x] Android SDK installed (via Android Studio or sdkmanager)
- [x] Solana CLI installed
- [x] dApp Store Publisher CLI installed

## Step 1: Install Required Tools

```bash
# Install Bubblewrap CLI (for TWA generation)
npm install -g @bubblewrap/cli

# Install dApp Store Publisher CLI
npm install -g @solana-mobile/dapp-store-cli

# Verify installations
bubblewrap --version
dapp-store --version
```

## Step 2: Generate Android Signing Key

```bash
# Generate keystore (keep this secure!)
keytool -genkey -v \
  -keystore android.keystore \
  -alias strun-key \
  -keyalg RSA \
  -keysize 2048 \
  -validity 10000

# Get SHA-256 fingerprint
keytool -list -v -keystore android.keystore -alias strun-key
```

**Important:** Save the keystore password and alias securely. Store the `android.keystore` file in a secure location (NOT in git).

## Step 3: Update Digital Asset Links

1. Copy the SHA-256 fingerprint from the previous step
2. Update `public/.well-known/assetlinks.json` with your fingerprint
3. Deploy to production so it's accessible at:
   ```
   https://strun.app/.well-known/assetlinks.json
   ```

## Step 4: Initialize TWA Project

```bash
# Initialize TWA from manifest
bubblewrap init --manifest https://strun.app/manifest.webmanifest

# This creates a TWA project in ./twa directory
```

Or use the pre-configured `twa-manifest.json`:

```bash
bubblewrap init --manifest ./twa-manifest.json
```

## Step 5: Build Android APK

```bash
cd twa
./gradlew assembleRelease

# APK will be in: app/build/outputs/apk/release/app-release.apk
```

## Step 6: Test APK Locally

```bash
# Install on connected device or emulator
adb install -r app/build/outputs/apk/release/app-release.apk

# Test all features:
# - Wallet connection (Phantom, Solflare mobile)
# - Location permissions
# - x402 payment flow
# - Task completion
```

## Step 7: Create Publisher NFTs (On-Chain)

### 7.1 Create Publisher Account

```bash
# Initialize publisher (one-time)
dapp-store create publisher \
  --name "Strun Team" \
  --website "https://strun.app" \
  --contact "support@strun.app" \
  --keypair ~/.config/solana/id.json \
  --network devnet
```

This creates a publisher NFT and saves metadata to `publisher.json`.

### 7.2 Create dApp Account

```bash
# Create dApp NFT
dapp-store create app \
  --name "Strun" \
  --android-package "app.strun.mobile" \
  --website "https://strun.app" \
  --category "Fitness" \
  --publisher-address <PUBLISHER_ADDRESS_FROM_STEP_7.1> \
  --keypair ~/.config/solana/id.json \
  --network devnet
```

This creates an app NFT and saves metadata to `app.json`.

### 7.3 Create Release NFT

```bash
# Create release NFT
dapp-store create release \
  --app-address <APP_ADDRESS_FROM_STEP_7.2> \
  --version-name "1.0.0" \
  --version-code 1 \
  --apk ./twa/app/build/outputs/apk/release/app-release.apk \
  --keypair ~/.config/solana/id.json \
  --network devnet
```

This uploads APK to decentralized storage and creates release NFT with `release.json`.

## Step 8: Submit to dApp Store

```bash
# Submit for review
dapp-store submit release \
  --release-address <RELEASE_ADDRESS_FROM_STEP_7.3> \
  --keypair ~/.config/solana/id.json \
  --network devnet
```

## Step 9: Publisher Portal Review

1. Go to [Solana dApp Store Publisher Portal](https://dapp-store.solanamobile.com/)
2. Connect wallet (same keypair used for publishing)
3. View submitted releases
4. Wait for Solana Mobile team review (typically 1-3 business days)

## Step 10: Monitor & Update

After approval, monitor:

- Crash reports via Play Console (if also published to Google Play)
- User feedback from dApp Store reviews
- On-chain metrics (downloads, active users)

### Update Process

For new releases:

```bash
# Build new APK with incremented version
# Update twa-manifest.json: appVersionCode + 1

bubblewrap update
./gradlew assembleRelease

# Create new release NFT
dapp-store create release \
  --app-address <APP_ADDRESS> \
  --version-name "1.0.1" \
  --version-code 2 \
  --apk ./twa/app/build/outputs/apk/release/app-release.apk \
  --keypair ~/.config/solana/id.json \
  --network devnet

# Submit new release
dapp-store submit release \
  --release-address <NEW_RELEASE_ADDRESS> \
  --keypair ~/.config/solana/id.json \
  --network devnet
```

## Mainnet Deployment

After successful devnet testing, repeat steps 7-9 with `--network mainnet`:

```bash
# Important: Use production APK with mainnet RPC endpoints
# Update environment variables in your PWA:
SOLANA_RPC_URL=https://api.mainnet-beta.solana.com
ANCHOR_PROGRAM_ID=<MAINNET_PROGRAM_ID>
```

## Troubleshooting

### Issue: Digital Asset Links verification fails

**Solution:**
- Ensure `assetlinks.json` is accessible via HTTPS
- Verify SHA-256 fingerprint matches your signing key
- Check package name matches exactly

### Issue: APK build fails

**Solution:**
- Update Android SDK to latest stable
- Check Java version (must be 17+)
- Clear gradle cache: `./gradlew clean`

### Issue: Wallet connection doesn't work in TWA

**Solution:**
- Mobile Wallet Adapter works automatically in Chrome (TWA)
- Ensure PWA includes proper wallet-adapter packages
- Test with Phantom or Solflare mobile apps installed

## Required Files Checklist

- [x] `twa-manifest.json` - TWA configuration
- [x] `public/.well-known/assetlinks.json` - Digital Asset Links
- [x] `android.keystore` - Signing key (secure storage)
- [x] `publisher.json` - Publisher NFT metadata
- [x] `app.json` - App NFT metadata
- [x] `release.json` - Release NFT metadata
- [x] `privacy-policy.html` - Privacy policy page
- [x] `support.html` - Support contact page

## Support & Resources

- [Solana Mobile Docs](https://docs.solanamobile.com/)
- [dApp Store Publisher Portal](https://dapp-store.solanamobile.com/)
- [Bubblewrap Documentation](https://github.com/GoogleChromeLabs/bubblewrap)
- [TWA Documentation](https://developer.chrome.com/docs/android/trusted-web-activity/)

## Security Notes

1. **Never commit** `android.keystore` or keystore passwords to git
2. Store keystore in secure secrets manager (GitHub Secrets, 1Password, etc.)
3. Backup keystore securely - losing it means you can't update your app
4. Use different keystores for dev/staging/production
5. Rotate API keys regularly
6. Monitor for security vulnerabilities in dependencies

## CI/CD Integration

Add to GitHub Actions:

```yaml
name: Build and Deploy to Solana dApp Store

on:
  push:
    tags:
      - 'v*'

jobs:
  build-and-deploy:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      
      - name: Setup Node
        uses: actions/setup-node@v3
        with:
          node-version: '18'
      
      - name: Install dependencies
        run: npm ci
      
      - name: Build PWA
        run: npm run build
      
      - name: Setup Android SDK
        uses: android-actions/setup-android@v2
      
      - name: Decode keystore
        run: echo "${{ secrets.ANDROID_KEYSTORE_BASE64 }}" | base64 -d > android.keystore
      
      - name: Install Bubblewrap
        run: npm install -g @bubblewrap/cli
      
      - name: Build APK
        run: |
          cd twa
          ./gradlew assembleRelease
      
      - name: Install dApp Store CLI
        run: npm install -g @solana-mobile/dapp-store-cli
      
      - name: Create Release NFT
        env:
          SOLANA_KEYPAIR: ${{ secrets.SOLANA_KEYPAIR }}
        run: |
          echo "$SOLANA_KEYPAIR" > keypair.json
          dapp-store create release \
            --app-address ${{ secrets.APP_ADDRESS }} \
            --version-name ${{ github.ref_name }} \
            --version-code ${{ github.run_number }} \
            --apk ./twa/app/build/outputs/apk/release/app-release.apk \
            --keypair ./keypair.json \
            --network mainnet
      
      - name: Submit Release
        run: |
          dapp-store submit release \
            --release-address <RELEASE_ADDRESS> \
            --keypair ./keypair.json \
            --network mainnet
```

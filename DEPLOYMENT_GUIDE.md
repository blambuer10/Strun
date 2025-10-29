# Strun - Complete Deployment Guide

Kapsamlı deployment kılavuzu: Local build'den Solana dApp Store'a kadar her şey.

## 🎯 Deployment Seçenekleri

### Seçenek 1: Otomatik GitHub Actions (Önerilen)
✅ En kolay ve hızlı  
✅ Hata riski düşük  
✅ Her push'ta otomatik build  

### Seçenek 2: Local Build + Manuel Deploy
✅ Tam kontrol  
✅ Test için ideal  
⚠️ Daha fazla setup gerekiyor  

---

## 📋 Ön Gereksinimler

### Herkes İçin Gerekli
- ✅ GitHub hesabı
- ✅ Solana cüzdanı (en az 0.5 SOL)
- ✅ Domain: `strun.fun`

### Local Build İçin Ek Gereksinimler
- ✅ Node.js v18-20
- ✅ Java JDK 17
- ✅ Android SDK
- ✅ MacOS/Linux/Windows

---

## 🚀 Seçenek 1: GitHub Actions ile Otomatik Deployment

### 1. GitHub Secrets Ayarla

Repository Settings → Secrets and Variables → Actions → New repository secret:

**Supabase Secrets** (Zaten var):
```
VITE_SUPABASE_URL
VITE_SUPABASE_PUBLISHABLE_KEY
VITE_SUPABASE_PROJECT_ID
```

**Android Signing Secrets** (Yeni eklenecek):
```bash
# 1. Keystore oluştur (local)
./scripts/create-keystore.sh

# 2. Base64'e çevir
base64 -i strun-release.keystore | pbcopy  # MacOS
base64 -w 0 strun-release.keystore         # Linux

# 3. GitHub'a ekle:
ANDROID_KEYSTORE_BASE64=<yukarıdaki çıktı>
KEYSTORE_PASSWORD=<keystore şifren>
KEY_PASSWORD=<key şifren>
```

**Solana Secret** (Zaten var):
```
SOLANA_PUBLISHER_KEYPAIR=<solana private key JSON>
```

### 2. İlk Kez: Publisher ve App NFT Oluştur

```bash
# Local'de bir kez çalıştır:
cd publishing
npm install --save-dev @solana-mobile/dapp-store-cli

# Publisher NFT (tek seferlik)
npx dapp-store create publisher \
  -k keypair.json \
  -u https://api.mainnet-beta.solana.com

# App NFT (tek seferlik)
npx dapp-store create app \
  -k keypair.json \
  -u https://api.mainnet-beta.solana.com

# App address'i kopyala ve GitHub Secret olarak ekle:
# DAPP_STORE_APP_ADDRESS=<app_nft_address>
```

### 3. Deploy Et!

GitHub'da iki yöntem:

**Yöntem A: Manuel Trigger**
1. GitHub repo → Actions
2. "Build Android APK" workflow seç
3. "Run workflow" tıkla
4. "Deploy to Solana dApp Store" ✅
5. "Run workflow" başlat

**Yöntem B: Code Push**
```bash
git add .
git commit -m "feat: ready for dApp Store deployment"
git push origin main

# Actions sekmesinde build'i izle
```

### 4. Solana Mobile'a Bildir

1. [Solana Mobile Discord](https://discord.gg/solanamobile)'a katıl
2. #developer kanalında "Developer" rolü al
3. #dapp-store kanalına yaz:

```
📱 App Submission: Strun
Package: app.strun.mobile
Release NFT: <github_actions_output_address>
Category: Health & Fitness
Status: Ready for review
```

### 5. Onay Bekle

- Review süresi: 2-7 gün
- Eğer reddedilirse: Feedback'e göre düzelt ve tekrar submit et
- Onaylanınca: dApp Store'da canlıya geçer 🎉

---

## 🛠️ Seçenek 2: Local Build + Manuel Deploy

### 1. Geliştirme Ortamını Hazırla

```bash
# Node.js kontrol
node -v  # 18-20 arası olmalı

# Java kontrol
java -version  # 17 olmalı

# Android SDK kontrol
echo $ANDROID_HOME  # Set edilmiş olmalı
```

### 2. Keystore Oluştur

```bash
./scripts/create-keystore.sh

# Şifreni kaydet!
# Keystore dosyasını güvenli yere backup'la
```

### 3. APK Build Et

```bash
# Kolay yol - tek komut:
./scripts/local-build.sh

# Manuel yol:
npm ci
npm run build
npx cap add android
npx cap sync android
cd android
./gradlew assembleRelease
```

APK location: `android/app/build/outputs/apk/release/app-release.apk`

### 4. dApp Store'a Deploy Et

```bash
cd publishing

# .env dosyasını düzenle
cp .env.example .env
nano .env  # Pathları ayarla

# Keypair'i yerleştir
# publishing/keypair.json

# Validate et
npm run validate

# İlk kez: Publisher ve App NFT
npm run create:publisher
npm run create:app

# Her release için: Release NFT ve Submit
npm run deploy
```

### 5. Test Et

```bash
# Device'a yükle
adb devices
adb install publishing/files/strun-release.apk

# Kontrol listesi:
# ✅ Uygulama açılıyor
# ✅ Email login çalışıyor
# ✅ Wallet bağlanıyor
# ✅ GPS tracking çalışıyor
# ✅ Task oluşturuluyor
# ✅ Community feed görünüyor
```

---

## 🔄 Güncelleme Yayınlama

### GitHub Actions ile:

```bash
# config.yaml'da version güncelle
# version_code: 1 → 2
# version_name: "1.0.0" → "1.0.1"

git add publishing/config.yaml
git commit -m "chore: bump version to 1.0.1"
git push

# Actions'da "Deploy to Solana dApp Store" ✅ ile run et
```

### Local ile:

```bash
# 1. Version güncelle
nano publishing/config.yaml
# version_code: 2
# version_name: "1.0.1"

# 2. Yeni APK build et
./scripts/local-build.sh

# 3. Deploy et
cd publishing
npm run deploy
```

---

## 🐛 Sorun Giderme

### Build Hataları

**"Android SDK not found"**
```bash
export ANDROID_HOME=~/Library/Android/sdk  # MacOS
export ANDROID_HOME=~/Android/Sdk          # Linux
```

**"JAVA_HOME not set"**
```bash
export JAVA_HOME=/Library/Java/JavaVirtualMachines/jdk-17.jdk/Contents/Home
```

**"Keystore not found"**
```bash
./scripts/create-keystore.sh
cp strun-release.keystore android/app/
```

### Deployment Hataları

**"Transaction failed - priority fee too low"**
```bash
# .env'de artır:
PRIORITY_FEE_LAMPORTS=1000000
```

**"APK upload timeout"**
- İnternet bağlantını kontrol et (min 0.25 MB/s upload)
- Private RPC kullan (Helius, QuickNode)
- APK boyutunu küçült (<50MB)

**"Invalid keypair"**
```bash
# Keypair formatını kontrol et:
cat keypair.json
# [123, 45, 67, ...] array formatında olmalı
```

### Validation Hataları

**"Icon not 512x512"**
```bash
# ImageMagick ile resize et:
convert icon.png -resize 512x512 media/icon-512x512.png
```

**"Screenshots aspect ratio mismatch"**
```bash
# Tüm screenshot'ları aynı aspect ratio'ya getir:
for img in screenshot-*.png; do
  convert $img -resize 1920x1080! $img
done
```

---

## 📊 Deployment Checklist

### Pre-Launch
- [ ] Tüm özellikler test edildi
- [ ] Privacy policy yayında: https://strun.fun/privacy-policy.html
- [ ] Terms yayında: https://strun.fun/terms
- [ ] Support page hazır: https://strun.fun/support.html
- [ ] Asset'ler hazır (icon, banner, screenshots)
- [ ] APK signed ve test edildi
- [ ] Keypair güvenli yerde backup'landı

### Publishing
- [ ] Publisher NFT oluşturuldu
- [ ] App NFT oluşturuldu
- [ ] Release NFT oluşturuldu
- [ ] dApp Store'a submit edildi
- [ ] Solana Mobile ekibine bildirildi

### Post-Launch
- [ ] GitHub Release oluşturuldu
- [ ] Community'ye duyuruldu
- [ ] Analytics aktif
- [ ] Crash reporting aktif
- [ ] Support email hazır: info@strun.fun

---

## 📚 Kaynaklar

- [Solana dApp Store Docs](https://docs.solanamobile.com/dapp-publishing/intro)
- [Publisher Portal](https://dapp-store.solanamobile.com/)
- [Solana Mobile Discord](https://discord.gg/solanamobile)
- [Capacitor Android Docs](https://capacitorjs.com/docs/android)

---

## 🆘 Destek

**Technical Issues:**
- GitHub Issues: https://github.com/your-org/strun/issues
- Solana Mobile Discord: #dapp-store

**App-Specific:**
- Email: info@strun.fun
- Website: https://strun.fun

---

## 🎉 İlk Deploy Sonrası

Tebrikler! Uygulamanız dApp Store'da! 🚀

**Şimdi ne yapmalı:**

1. **Marketing**
   - Twitter/X duyurusu
   - Reddit (r/solana, r/SolanaMobile)
   - Crypto Discord sunucuları

2. **Community Building**
   - Discord server kur
   - Telegram group
   - Email newsletter

3. **Analytics**
   - Download sayılarını takip et
   - User retention izle
   - Crash reports kontrol et

4. **Iterate**
   - User feedback topla
   - Yeni özellikler ekle
   - Bug fix'ler yayınla

**İyi şanslar! 🏃‍♂️⚡**

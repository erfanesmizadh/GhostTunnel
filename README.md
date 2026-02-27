# GhostTunnel - راهنمای نصب و استفاده

پروتکل اختصاصی برای تانل امن بین سرور ایران و خارج.

## ویژگی‌ها
- رمزنگاری XChaCha20-Poly1305
- ترافیک شبیه HTTPS API معمولی (برای دور زدن DPI)
- Padding تصادفی روی هر پکت
- هدرهای HTTP جعلی
- پروکسی SOCKS5 روی سرور ایران

---

## ۱. نصب Go روی هر دو سرور

```bash
apt update && apt install -y golang-go git
# یا نصب آخرین نسخه:
wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz
tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz
export PATH=$PATH:/usr/local/go/bin
```

---

## ۲. کپی کردن کدها روی سرورها

```bash
# روی هر دو سرور:
mkdir -p /opt/ghosttunnel
cd /opt/ghosttunnel
# فایل‌های پروژه را کپی کنید
go mod tidy
```

---

## ۳. ساخت TLS Certificate روی سرور خارج

```bash
# Self-signed (برای شروع):
openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 365 -nodes \
  -subj "/CN=your-domain.com"
```

---

## ۴. تولید کلید مشترک

```bash
# روی سرور خارج:
cd /opt/ghosttunnel
go run server/main.go
# یک کلید hex نشون میده - این کلید رو کپی کن
```

---

## ۵. اجرا روی سرور خارج

```bash
cd /opt/ghosttunnel
go build -o ghostserver ./server/
./ghostserver -key <کلید_hex> -listen :443 -cert cert.pem -keyfile key.pem
```

### سرویس systemd:
```ini
# /etc/systemd/system/ghosttunnel.service
[Unit]
Description=GhostTunnel Server
After=network.target

[Service]
ExecStart=/opt/ghosttunnel/ghostserver -key <کلید_hex> -listen :443 -cert /opt/ghosttunnel/cert.pem -keyfile /opt/ghosttunnel/key.pem
Restart=always
User=root

[Install]
WantedBy=multi-user.target
```

```bash
systemctl daemon-reload
systemctl enable ghosttunnel
systemctl start ghosttunnel
```

---

## ۶. اجرا روی سرور ایران (کلاینت)

```bash
cd /opt/ghosttunnel
go build -o ghostclient ./client/
./ghostclient -key <کلید_hex> -server <IP_سرور_خارج>:443 -listen 127.0.0.1:1080
```

---

## ۷. استفاده از پروکسی

بعد از اجرای کلاینت، یه پروکسی SOCKS5 روی `127.0.0.1:1080` داری.

```bash
# تست:
curl --socks5 127.0.0.1:1080 https://google.com

# تنظیم در مرورگر Firefox:
# Settings > Network > Manual Proxy > SOCKS5 > 127.0.0.1:1080
```

---

## امنیت بیشتر (توصیه می‌شه)

1. **دامنه واقعی + Let's Encrypt** به جای self-signed
2. **فقط IP سرور ایران** رو در فایروال سرور خارج اجازه بده:
   ```bash
   ufw allow from <IP_ایران> to any port 443
   ufw deny 443
   ```
3. **کلید رو هرگز جایی ذخیره نکن** - فقط در environment variable:
   ```bash
   export GHOST_KEY="کلید_hex"
   ./ghostserver -key $GHOST_KEY ...
   ```

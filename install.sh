#!/bin/bash
# ============================================================
#  GhostTunnel - نصب کامل
#  روی سرور خارج: bash install.sh server
#  روی سرور ایران: bash install.sh client
# ============================================================

set -e

MODE=$1
INSTALL_DIR="/opt/ghosttunnel"
GO_VERSION="1.21.6"
GO_TAR="go${GO_VERSION}.linux-amd64.tar.gz"
GO_URL="https://go.dev/dl/${GO_TAR}"

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

info()    { echo -e "${GREEN}[✓]${NC} $1"; }
warn()    { echo -e "${YELLOW}[!]${NC} $1"; }
error()   { echo -e "${RED}[✗]${NC} $1"; exit 1; }

if [[ "$MODE" != "server" && "$MODE" != "client" ]]; then
    echo ""
    echo "  استفاده:"
    echo "    روی سرور خارج:  bash install.sh server"
    echo "    روی سرور ایران: bash install.sh client"
    echo ""
    exit 1
fi

echo ""
echo "================================================"
echo "   GhostTunnel - حالت: $MODE"
echo "================================================"
echo ""

# ── نصب وابستگی‌ها ──────────────────────────────────────
install_deps() {
    info "نصب وابستگی‌ها..."
    apt-get update -qq
    apt-get install -y -qq wget curl openssl git 2>/dev/null || true
}

# ── نصب Go ──────────────────────────────────────────────
install_go() {
    if command -v go &>/dev/null; then
        info "Go قبلاً نصب شده: $(go version)"
        return
    fi
    info "دانلود Go ${GO_VERSION}..."
    wget -q "${GO_URL}" -O "/tmp/${GO_TAR}"
    rm -rf /usr/local/go
    tar -C /usr/local -xzf "/tmp/${GO_TAR}"
    rm "/tmp/${GO_TAR}"
    export PATH=$PATH:/usr/local/go/bin
    echo 'export PATH=$PATH:/usr/local/go/bin' >> /etc/profile
    echo 'export PATH=$PATH:/usr/local/go/bin' >> ~/.bashrc
    info "Go نصب شد: $(go version)"
}

export PATH=$PATH:/usr/local/go/bin

# ── ساخت پوشه پروژه ─────────────────────────────────────
setup_dir() {
    mkdir -p "$INSTALL_DIR"/{server,client,common}
    cd "$INSTALL_DIR"
}

# ── نوشتن کدها ──────────────────────────────────────────
write_code() {
    info "نوشتن کدهای پروژه..."

    # go.mod
    cat > "$INSTALL_DIR/go.mod" << 'EOF'
module ghosttunnel

go 1.21

require golang.org/x/crypto v0.17.0
EOF

    # common/crypto.go
    cat > "$INSTALL_DIR/common/crypto.go" << 'EOF'
package common

import (
	"crypto/rand"
	"encoding/binary"
	"errors"
	"io"

	"golang.org/x/crypto/chacha20poly1305"
)

const (
	KeySize   = 32
	NonceSize = chacha20poly1305.NonceSizeX
	MaxPad    = 128
)

func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	_, err := rand.Read(key)
	return key, err
}

func Encrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	padBuf := make([]byte, 1)
	rand.Read(padBuf)
	padLen := int(padBuf[0]) % MaxPad
	pad := make([]byte, padLen)
	rand.Read(pad)
	nonce := make([]byte, NonceSize)
	if _, err := rand.Read(nonce); err != nil {
		return nil, err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, nil)
	frame := make([]byte, 2+padLen+NonceSize+len(ciphertext))
	binary.BigEndian.PutUint16(frame[0:2], uint16(padLen))
	copy(frame[2:], pad)
	copy(frame[2+padLen:], nonce)
	copy(frame[2+padLen+NonceSize:], ciphertext)
	return frame, nil
}

func Decrypt(key, frame []byte) ([]byte, error) {
	if len(frame) < 2 {
		return nil, errors.New("frame too short")
	}
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}
	padLen := int(binary.BigEndian.Uint16(frame[0:2]))
	offset := 2 + padLen
	if len(frame) < offset+NonceSize+aead.Overhead() {
		return nil, errors.New("frame too short after pad")
	}
	nonce := frame[offset : offset+NonceSize]
	ciphertext := frame[offset+NonceSize:]
	return aead.Open(nil, nonce, ciphertext, nil)
}

func WriteFrame(w io.Writer, key, data []byte) error {
	frame, err := Encrypt(key, data)
	if err != nil {
		return err
	}
	lenBuf := make([]byte, 4)
	binary.BigEndian.PutUint32(lenBuf, uint32(len(frame)))
	if _, err := w.Write(lenBuf); err != nil {
		return err
	}
	_, err = w.Write(frame)
	return err
}

func ReadFrame(r io.Reader, key []byte) ([]byte, error) {
	lenBuf := make([]byte, 4)
	if _, err := io.ReadFull(r, lenBuf); err != nil {
		return nil, err
	}
	frameLen := binary.BigEndian.Uint32(lenBuf)
	if frameLen > 4*1024*1024 {
		return nil, errors.New("frame too large")
	}
	frame := make([]byte, frameLen)
	if _, err := io.ReadFull(r, frame); err != nil {
		return nil, err
	}
	return Decrypt(key, frame)
}
EOF

    # server/main.go
    cat > "$INSTALL_DIR/server/main.go" << 'EOF'
package main

import (
	"crypto/tls"
	"encoding/hex"
	"flag"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"time"

	"ghosttunnel/common"
)

var sharedKey []byte

func main() {
	keyHex    := flag.String("key",     "",         "Shared key hex (64 chars). Empty = generate.")
	listen    := flag.String("listen",  ":443",     "Listen address")
	certFile  := flag.String("cert",    "cert.pem", "TLS cert file")
	keyFile   := flag.String("keyfile", "key.pem",  "TLS key file")
	flag.Parse()

	if *keyHex == "" {
		k, err := common.GenerateKey()
		if err != nil { log.Fatal(err) }
		log.Printf("Generated key: %s", hex.EncodeToString(k))
		log.Println("Use this key on both server and client with -key flag")
		os.Exit(0)
	}

	k, err := hex.DecodeString(*keyHex)
	if err != nil || len(k) != 32 {
		log.Fatal("Invalid key. Must be 64 hex characters.")
	}
	sharedKey = k

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/health", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"status":"ok","version":"1.0.0"}`))
	})
	mux.HandleFunc("/api/v1/data", tunnelHandler)
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		w.Write([]byte(`<html><body><h1>Welcome</h1></body></html>`))
	})

	srv := &http.Server{
		Addr:      *listen,
		Handler:   mux,
		TLSConfig: &tls.Config{MinVersion: tls.VersionTLS12},
	}

	log.Printf("[GhostTunnel Server] Listening on %s", *listen)
	log.Fatal(srv.ListenAndServeTLS(*certFile, *keyFile))
}

func tunnelHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost || r.Header.Get("X-Request-ID") == "" {
		http.NotFound(w, r)
		return
	}

	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "not supported", 500)
		return
	}
	conn, _, err := hj.Hijack()
	if err != nil { return }
	defer conn.Close()

	conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n"))

	targetAddr, err := common.ReadFrame(conn, sharedKey)
	if err != nil {
		log.Printf("read target: %v", err)
		return
	}

	target, err := net.DialTimeout("tcp", string(targetAddr), 10*time.Second)
	if err != nil {
		common.WriteFrame(conn, sharedKey, []byte("ERR:"+err.Error()))
		return
	}
	defer target.Close()

	common.WriteFrame(conn, sharedKey, []byte("OK"))
	log.Printf("Tunnel -> %s", targetAddr)

	go func() {
		defer conn.Close()
		defer target.Close()
		for {
			data, err := common.ReadFrame(conn, sharedKey)
			if err != nil { return }
			if _, err := target.Write(data); err != nil { return }
		}
	}()

	buf := make([]byte, 32*1024)
	for {
		n, err := target.Read(buf)
		if n > 0 {
			if e := common.WriteFrame(conn, sharedKey, buf[:n]); e != nil { return }
		}
		if err != nil {
			if err != io.EOF { log.Printf("target read: %v", err) }
			return
		}
	}
}
EOF

    # client/main.go
    cat > "$INSTALL_DIR/client/main.go" << 'EOF'
package main

import (
	"crypto/rand"
	"crypto/tls"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"time"

	"ghosttunnel/common"
)

var (
	sharedKey  []byte
	serverAddr string
)

func main() {
	keyHex := flag.String("key",    "",                "Shared key hex")
	server := flag.String("server", "",                "Server host:port")
	listen := flag.String("listen", "127.0.0.1:1080",  "SOCKS5 listen address")
	flag.Parse()

	if *keyHex == "" || *server == "" {
		log.Fatal("Usage: client -key <hex> -server <host:port> [-listen 127.0.0.1:1080]")
	}
	k, err := hex.DecodeString(*keyHex)
	if err != nil || len(k) != 32 { log.Fatal("Invalid key.") }
	sharedKey = k
	serverAddr = *server

	ln, err := net.Listen("tcp", *listen)
	if err != nil { log.Fatal(err) }
	log.Printf("[GhostTunnel Client] SOCKS5 on %s", *listen)

	for {
		conn, err := ln.Accept()
		if err != nil { continue }
		go handleSocks5(conn)
	}
}

func handleSocks5(conn net.Conn) {
	defer conn.Close()
	buf := make([]byte, 256)

	if _, err := io.ReadFull(conn, buf[:2]); err != nil { return }
	if buf[0] != 0x05 { return }
	nM := int(buf[1])
	if _, err := io.ReadFull(conn, buf[:nM]); err != nil { return }
	conn.Write([]byte{0x05, 0x00})

	if _, err := io.ReadFull(conn, buf[:4]); err != nil { return }
	if buf[1] != 0x01 {
		conn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	var target string
	switch buf[3] {
	case 0x01:
		addr := make([]byte, 4)
		io.ReadFull(conn, addr)
		var p [2]byte; io.ReadFull(conn, p[:])
		target = fmt.Sprintf("%s:%d", net.IP(addr), binary.BigEndian.Uint16(p[:]))
	case 0x03:
		io.ReadFull(conn, buf[:1])
		dom := make([]byte, int(buf[0]))
		io.ReadFull(conn, dom)
		var p [2]byte; io.ReadFull(conn, p[:])
		target = fmt.Sprintf("%s:%d", string(dom), binary.BigEndian.Uint16(p[:]))
	case 0x04:
		addr := make([]byte, 16)
		io.ReadFull(conn, addr)
		var p [2]byte; io.ReadFull(conn, p[:])
		target = fmt.Sprintf("[%s]:%d", net.IP(addr), binary.BigEndian.Uint16(p[:]))
	default:
		conn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}

	tunnel, err := connectServer(target)
	if err != nil {
		log.Printf("tunnel error %s: %v", target, err)
		conn.Write([]byte{0x05, 0x04, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
		return
	}
	defer tunnel.Close()

	conn.Write([]byte{0x05, 0x00, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	log.Printf("-> %s", target)

	go func() {
		defer tunnel.Close()
		b := make([]byte, 32*1024)
		for {
			n, err := conn.Read(b)
			if n > 0 {
				if e := common.WriteFrame(tunnel, sharedKey, b[:n]); e != nil { return }
			}
			if err != nil { return }
		}
	}()

	for {
		data, err := common.ReadFrame(tunnel, sharedKey)
		if err != nil { return }
		if _, err := conn.Write(data); err != nil { return }
	}
}

func connectServer(target string) (net.Conn, error) {
	conn, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp", serverAddr,
		&tls.Config{InsecureSkipVerify: true},
	)
	if err != nil { return nil, err }

	req := fmt.Sprintf(
		"POST /api/v1/data HTTP/1.1\r\nHost: %s\r\nContent-Type: application/json\r\n"+
		"X-Request-ID: %s\r\nUser-Agent: Mozilla/5.0 (compatible; API-Client/1.0)\r\n"+
		"Connection: keep-alive\r\nTransfer-Encoding: chunked\r\n\r\n",
		serverAddr, randHex(16),
	)
	if _, err := conn.Write([]byte(req)); err != nil {
		conn.Close(); return nil, err
	}

	tmp := make([]byte, 512)
	n, err := conn.Read(tmp)
	if err != nil || n == 0 {
		conn.Close(); return nil, fmt.Errorf("no response")
	}

	if err := common.WriteFrame(conn, sharedKey, []byte(target)); err != nil {
		conn.Close(); return nil, err
	}

	resp, err := common.ReadFrame(conn, sharedKey)
	if err != nil { conn.Close(); return nil, err }
	if string(resp) != "OK" {
		conn.Close(); return nil, fmt.Errorf("server: %s", resp)
	}
	return conn, nil
}

func randHex(n int) string {
	b := make([]byte, n)
	rand.Read(b)
	return hex.EncodeToString(b)
}
EOF
}

# ── ساخت TLS Certificate ─────────────────────────────────
make_cert() {
    if [[ -f "$INSTALL_DIR/cert.pem" ]]; then
        info "Certificate قبلاً وجود داره."
        return
    fi
    info "ساخت TLS certificate..."
    openssl req -x509 -newkey rsa:4096 \
        -keyout "$INSTALL_DIR/key.pem" \
        -out "$INSTALL_DIR/cert.pem" \
        -days 365 -nodes \
        -subj "/CN=api.service.local" 2>/dev/null
    chmod 600 "$INSTALL_DIR/key.pem"
    info "Certificate ساخته شد."
}

# ── تولید کلید ───────────────────────────────────────────
generate_key() {
    KEY_FILE="$INSTALL_DIR/.ghostkey"
    if [[ -f "$KEY_FILE" ]]; then
        GHOST_KEY=$(cat "$KEY_FILE")
        info "کلید قبلی استفاده میشه."
        return
    fi
    info "تولید کلید مشترک..."
    cd "$INSTALL_DIR"
    go run server/main.go 2>&1 | grep "Generated key" | awk '{print $NF}' > "$KEY_FILE" &
    sleep 3
    kill %1 2>/dev/null || true
    GHOST_KEY=$(cat "$KEY_FILE" 2>/dev/null)
    if [[ -z "$GHOST_KEY" ]]; then
        # fallback: openssl
        GHOST_KEY=$(openssl rand -hex 32)
        echo "$GHOST_KEY" > "$KEY_FILE"
    fi
    chmod 600 "$KEY_FILE"
    info "کلید تولید شد."
}

# ── Build ─────────────────────────────────────────────────
build_binary() {
    info "دانلود dependencies و build..."
    cd "$INSTALL_DIR"
    go mod tidy
    if [[ "$MODE" == "server" ]]; then
        go build -o ghostserver ./server/
        info "ghostserver ساخته شد."
    else
        go build -o ghostclient ./client/
        info "ghostclient ساخته شد."
    fi
}

# ── Systemd service ───────────────────────────────────────
install_service_server() {
    KEY_FILE="$INSTALL_DIR/.ghostkey"
    GHOST_KEY=$(cat "$KEY_FILE")

    cat > /etc/systemd/system/ghosttunnel.service << EOF
[Unit]
Description=GhostTunnel Server
After=network.target

[Service]
ExecStart=${INSTALL_DIR}/ghostserver -key ${GHOST_KEY} -listen :443 -cert ${INSTALL_DIR}/cert.pem -keyfile ${INSTALL_DIR}/key.pem
WorkingDirectory=${INSTALL_DIR}
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ghosttunnel
    systemctl start ghosttunnel
    info "سرویس ghosttunnel فعال و شروع شد."
}

install_service_client() {
    if [[ -z "$GHOST_KEY" ]]; then
        warn "کلید رو وارد کن:"
        read -rp "Key (hex): " GHOST_KEY
    fi

    warn "آدرس سرور خارج را وارد کن (مثلاً 1.2.3.4:443):"
    read -rp "Server: " SERVER_ADDR

    cat > /etc/systemd/system/ghosttunnel.service << EOF
[Unit]
Description=GhostTunnel Client
After=network.target

[Service]
ExecStart=${INSTALL_DIR}/ghostclient -key ${GHOST_KEY} -server ${SERVER_ADDR} -listen 127.0.0.1:1080
WorkingDirectory=${INSTALL_DIR}
Restart=always
RestartSec=5
User=root

[Install]
WantedBy=multi-user.target
EOF

    systemctl daemon-reload
    systemctl enable ghosttunnel
    systemctl start ghosttunnel
    info "سرویس ghosttunnel کلاینت فعال شد."
}

# ── فایروال ──────────────────────────────────────────────
setup_firewall() {
    if command -v ufw &>/dev/null; then
        if [[ "$MODE" == "server" ]]; then
            ufw allow 443/tcp 2>/dev/null || true
            info "پورت 443 در فایروال باز شد."
        fi
    fi
}

# ── اجرای اصلی ───────────────────────────────────────────
install_deps
install_go
setup_dir
write_code

if [[ "$MODE" == "server" ]]; then
    make_cert
    generate_key
    build_binary
    setup_firewall
    install_service_server

    echo ""
    echo "================================================"
    echo -e "  ${GREEN}سرور با موفقیت نصب شد!${NC}"
    echo "================================================"
    echo ""
    echo -e "  ${YELLOW}کلید مشترک (این رو کپی کن!):${NC}"
    echo -e "  ${GREEN}$(cat $INSTALL_DIR/.ghostkey)${NC}"
    echo ""
    echo "  این کلید رو موقع نصب کلاینت روی سرور ایران وارد کن."
    echo ""
    echo "  وضعیت سرویس:"
    systemctl status ghosttunnel --no-pager -l | head -10
    echo ""
else
    build_binary
    install_service_client

    echo ""
    echo "================================================"
    echo -e "  ${GREEN}کلاینت با موفقیت نصب شد!${NC}"
    echo "================================================"
    echo ""
    echo "  پروکسی SOCKS5 روی 127.0.0.1:1080 فعاله."
    echo ""
    echo "  تست:"
    echo "    curl --socks5 127.0.0.1:1080 https://google.com"
    echo ""
    echo "  وضعیت سرویس:"
    systemctl status ghosttunnel --no-pager -l | head -10
    echo ""
fi

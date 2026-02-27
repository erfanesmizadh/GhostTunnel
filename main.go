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
	keyHex := flag.String("key", "", "Shared key in hex (32 bytes = 64 hex chars). Leave empty to generate one.")
	listenAddr := flag.String("listen", ":443", "HTTPS listen address")
	certFile := flag.String("cert", "cert.pem", "TLS certificate file")
	keyFile := flag.String("keyfile", "key.pem", "TLS key file")
	flag.Parse()

	if *keyHex == "" {
		k, err := common.GenerateKey()
		if err != nil {
			log.Fatal(err)
		}
		log.Printf("[GhostTunnel Server] Generated key: %s", hex.EncodeToString(k))
		log.Println("Use this key on both server and client with -key flag")
		os.Exit(0)
	}

	k, err := hex.DecodeString(*keyHex)
	if err != nil || len(k) != 32 {
		log.Fatal("Invalid key. Must be 64 hex characters (32 bytes).")
	}
	sharedKey = k

	mux := http.NewServeMux()

	// Fake endpoints to look like a normal API
	mux.HandleFunc("/api/v1/health", fakeHealthHandler)
	mux.HandleFunc("/api/v1/data", tunnelHandler)
	mux.HandleFunc("/", fakeRootHandler)

	tlsCfg := &tls.Config{MinVersion: tls.VersionTLS12}
	srv := &http.Server{
		Addr:      *listenAddr,
		Handler:   mux,
		TLSConfig: tlsCfg,
	}

	log.Printf("[GhostTunnel Server] Listening on %s", *listenAddr)
	log.Fatal(srv.ListenAndServeTLS(*certFile, *keyFile))
}

// fakeHealthHandler returns a fake JSON response
func fakeHealthHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(200)
	w.Write([]byte(`{"status":"ok","version":"1.0.0"}`))
}

// fakeRootHandler returns a fake HTML page
func fakeRootHandler(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.WriteHeader(200)
	w.Write([]byte(`<html><body><h1>Welcome</h1></body></html>`))
}

// tunnelHandler upgrades the connection and proxies TCP traffic
func tunnelHandler(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.NotFound(w, r)
		return
	}

	// Check a simple auth header (encrypted token check would be better)
	authHeader := r.Header.Get("X-Request-ID")
	if authHeader == "" {
		http.NotFound(w, r)
		return
	}

	// Hijack the connection
	hj, ok := w.(http.Hijacker)
	if !ok {
		http.Error(w, "not supported", 500)
		return
	}

	conn, _, err := hj.Hijack()
	if err != nil {
		return
	}
	defer conn.Close()

	// Send 200 OK to signal tunnel is ready
	conn.Write([]byte("HTTP/1.1 200 OK\r\nContent-Type: application/octet-stream\r\n\r\n"))

	// Read target address from client (first encrypted frame)
	targetAddr, err := common.ReadFrame(conn, sharedKey)
	if err != nil {
		log.Printf("Failed to read target address: %v", err)
		return
	}

	// Connect to target (local service or forward)
	target, err := net.DialTimeout("tcp", string(targetAddr), 10*time.Second)
	if err != nil {
		log.Printf("Failed to connect to target %s: %v", targetAddr, err)
		common.WriteFrame(conn, sharedKey, []byte("ERR:"+err.Error()))
		return
	}
	defer target.Close()

	// Send OK
	if err := common.WriteFrame(conn, sharedKey, []byte("OK")); err != nil {
		return
	}

	log.Printf("Tunnel established to %s", targetAddr)

	// Bidirectional proxy with encryption
	go func() {
		defer conn.Close()
		defer target.Close()
		for {
			data, err := common.ReadFrame(conn, sharedKey)
			if err != nil {
				return
			}
			if _, err := target.Write(data); err != nil {
				return
			}
		}
	}()

	buf := make([]byte, 32*1024)
	for {
		n, err := target.Read(buf)
		if n > 0 {
			if writeErr := common.WriteFrame(conn, sharedKey, buf[:n]); writeErr != nil {
				return
			}
		}
		if err != nil {
			if err != io.EOF {
				log.Printf("Target read error: %v", err)
			}
			return
		}
	}
}

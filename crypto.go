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

// GenerateKey generates a random 32-byte shared key
func GenerateKey() ([]byte, error) {
	key := make([]byte, KeySize)
	_, err := rand.Read(key)
	return key, err
}

// Encrypt encrypts data with XChaCha20-Poly1305 + random padding
// Frame format: [2-byte padLen][padLen bytes pad][nonce][ciphertext]
func Encrypt(key, plaintext []byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(key)
	if err != nil {
		return nil, err
	}

	// random padding length
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

	// build frame
	frame := make([]byte, 2+padLen+NonceSize+len(ciphertext))
	binary.BigEndian.PutUint16(frame[0:2], uint16(padLen))
	copy(frame[2:], pad)
	copy(frame[2+padLen:], nonce)
	copy(frame[2+padLen+NonceSize:], ciphertext)

	return frame, nil
}

// Decrypt decrypts a frame produced by Encrypt
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

// WriteFrame writes a length-prefixed encrypted frame to w
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

// ReadFrame reads a length-prefixed encrypted frame from r
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

// Package muleaes provides basic encryption and decryption of strings or
// byte arrays using AES-128 CBC. The encryption results are compativle with
// those created via Mulesoft Anypoint Studio.
//
// By default, a random Initialization Vector (IV or salt) is use in the
// encryption process. However, there is a 'NoSalt' option which does not
// use the random IV (also compatible with Mulesoft's version with no
// random IV).
package muleaes

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
)

// The Cryptor object holds the key used for crypto operations and provides
// the methods for encryption and decryption of data.
//
// Note that the key must be exactly 16 bytes.
type Cryptor struct {
	key     []byte
	useSalt bool
}

// NewCryptor returns a Cryptor object that a random Initialization Vector.
// The key argument must be a 16-byte value.
func NewCryptor(key []byte) *Cryptor {
	ct := Cryptor{key, true}
	return &ct
}

// NewCryptorNoSalt returns a Cryptor object that does not use a random
// Initialization Vector. The key argument must be a 16-byte value.
func NewCryptorNoSalt(key []byte) *Cryptor {
	ct := Cryptor{key, false}
	return &ct
}

// Encrypt takes a byte array and returns a base64-encoded encrypted
// result as a byte array.
func (c *Cryptor) Encrypt(plaintext []byte) ([]byte, error) {
	return c._encrypt(plaintext)
}

// EncryptString takes a string and returns a base64-encoded encrypted
// result as a string.
func (c *Cryptor) EncryptString(plaintext string) (string, error) {
	res, err := c._encrypt([]byte(plaintext))
	if err != nil {
		return "", err
	}
	return string(res), nil
}

// Decrypt takes a byte array of a base64-encoded data and returns the
// orignal decrypted plaintext result as a byte array.
func (c *Cryptor) Decrypt(enctext []byte) ([]byte, error) {
	return c._decrypt(enctext)
}

// DecryptString takes a string of a base64-encoded data and returns the
// orignal decrypted plaintext result as a string.
func (c *Cryptor) DecryptString(ciphertext string) (string, error) {
	res, err := c._decrypt([]byte(ciphertext))
	if err != nil {
		return "", err
	}
	return string(res), nil
}

func (c *Cryptor) _encrypt(plaintext []byte) ([]byte, error) {
	var iv []byte
	var ciphertext []byte

	block, err := aes.NewCipher(c.key)
	if err != nil {
		panic(err)
	}

	padded := pad(plaintext)

	if c.useSalt {
		ciphertext = make([]byte, aes.BlockSize+len(padded))
		iv = ciphertext[:aes.BlockSize]
		if _, err = io.ReadFull(rand.Reader, iv); err != nil {
			return nil, fmt.Errorf("could not encrypt: %v", err)
		}
	} else {
		ciphertext = make([]byte, len(padded))
		iv = c.key
	}

	cbc := cipher.NewCBCEncrypter(block, iv)

	if c.useSalt {
		cbc.CryptBlocks(ciphertext[aes.BlockSize:], padded)
	} else {
		cbc.CryptBlocks(ciphertext, padded)
	}

	return []byte(base64.StdEncoding.EncodeToString(ciphertext)), nil
}

func (c *Cryptor) _decrypt(ciphertext []byte) ([]byte, error) {
	var iv []byte
	var plaintext []byte

	decoded, err := base64.StdEncoding.DecodeString(string(ciphertext))
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(c.key)
	if err != nil {
		return nil, err
	}

	if len(ciphertext) < aes.BlockSize {
		return nil, fmt.Errorf("ciphertext too short")
	}

	if c.useSalt {
		iv = decoded[:aes.BlockSize]
		plaintext = decoded[aes.BlockSize:]
	} else {
		iv = c.key
		plaintext = decoded
	}

	cbc := cipher.NewCBCDecrypter(block, iv)
	cbc.CryptBlocks(decoded, decoded)

	return unpad(plaintext), nil
}

func unpad(src []byte) []byte {
	length := len(src)
	unpadding := int(src[length-1])
	return src[:(length - unpadding)]
}

func pad(src []byte) []byte {
	rem := aes.BlockSize - (len(src) % aes.BlockSize)
	br := bytes.Repeat([]byte(string(rune(rem))), rem)
	return append(src, br...)
}

package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"encoding/base64"
	"fmt"
)

func encryptAES(data []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	paddedData := pkcs7Padding(data, aes.BlockSize)
	ciphertext := make([]byte, len(paddedData))

	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(ciphertext, paddedData)

	return ciphertext, nil
}

func decryptAES(ciphertext []byte, key []byte, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	plaintext := make([]byte, len(ciphertext))

	mode := cipher.NewCBCDecrypter(block, iv)
	mode.CryptBlocks(plaintext, ciphertext)

	unpaddedData := pkcs7Unpadding(plaintext)

	return unpaddedData, nil
}

func pkcs7Padding(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	pad := byte(padding)
	paddedData := append(data, bytes.Repeat([]byte{pad}, padding)...)
	return paddedData
}

func pkcs7Unpadding(data []byte) []byte {
	length := len(data)
	unpad := int(data[length-1])
	return data[:length-unpad]
}

func main() {
	plaintext := []byte("Hello, World!")
	key := []byte("0123456789ABCDEF0123456789ABCDEF")
	iv := []byte("0123456789ABCDEF")

	ciphertext, err := encryptAES(plaintext, key, iv)
	if err != nil {
		fmt.Println("Encryption error:", err)
		return
	}

	encodedCiphertext := base64.StdEncoding.EncodeToString(ciphertext)
	fmt.Println("Encrypted data:", encodedCiphertext)

	decodedCiphertext, _ := base64.StdEncoding.DecodeString(encodedCiphertext)
	decryptedPlaintext, err := decryptAES(decodedCiphertext, key, iv)
	if err != nil {
		fmt.Println("Decryption error:", err)
		return
	}

	fmt.Println("Decrypted data:", string(decryptedPlaintext))
}

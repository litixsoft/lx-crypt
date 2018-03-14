// lxcrypt en and decode strings with key generation
package lxcrypt

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"os"
)

// GenerateKey, generate a key with size
func GenerateKey(size uint) ([]byte, error) {

	// Error for return
	var err error

	// Create a key
	key := make([]byte, size)

	// Check the size
	if size == 0 || size > 32 {
		return key, fmt.Errorf("key size should be between %d and %d", 1, 32)
	}

	// Use the crypto random
	_, err = rand.Read(key)

	// Return hex string from key
	return key, err
}

// GetKeyFromFile, get key from file, when not exists create new file with key
func GetKeyFromFile(kfp string) ([]byte, error) {

	var (
		err error
		key []byte
	)

	// Generate a new key when file not exists
	if _, err = os.Stat(kfp); os.IsNotExist(err) {

		// Generate key for save in file
		key, err = GenerateKey(32)

		// When error nil write file
		if err == nil {
			err = ioutil.WriteFile(kfp, []byte(hex.EncodeToString(key)), 0644)
		}

		return key, err
	}

	// Read key from file
	dat, err := ioutil.ReadFile(kfp)

	// When error nil decode to []byte
	if err == nil {
		key, err = hex.DecodeString(string(dat))
	}

	return key, err
}

// EncryptAES, encrypt text with AES cipher
func EncryptAES(key, text []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	b := base64.StdEncoding.EncodeToString(text)
	cipherText := make([]byte, aes.BlockSize+len(b))
	iv := cipherText[:aes.BlockSize]

	_, err = io.ReadFull(rand.Reader, iv)
	if err == nil {
		cfb := cipher.NewCFBEncrypter(block, iv)
		cfb.XORKeyStream(cipherText[aes.BlockSize:], []byte(b))
	}

	return cipherText, err
}

// DecryptAES, decrypt text with AES cipher
func DecryptAES(key, text []byte) ([]byte, error) {

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	if len(text) < aes.BlockSize {
		return nil, errors.New("text too short")
	}

	iv := text[:aes.BlockSize]
	text = text[aes.BlockSize:]
	cfb := cipher.NewCFBDecrypter(block, iv)
	cfb.XORKeyStream(text, text)

	return base64.StdEncoding.DecodeString(string(text))
}
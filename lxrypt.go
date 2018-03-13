// lxcrypt en and decode strings with key generation
package lxcrypt

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha1"
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
		return key, fmt.Errorf("Key size should be between 1 and 32")
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

// GenerateSalt, generate a new salt for password save
func GenerateSalt(secret []byte, saltSize int) ([]byte, error) {

	// Salt
	var salt []byte

	// Make byte array for buffer
	buf := make([]byte, saltSize, saltSize+sha1.Size)
	_, err := io.ReadFull(rand.Reader, buf)

	if err == nil {
		// Generate hash for salt
		hash := sha1.New()
		hash.Write(buf)
		hash.Write(secret)
		salt = hash.Sum(buf)
	}

	return salt, err
}

// GenerateSha1Password, generate a password with salt
func GenerateSha1Password(salt []byte, password []byte) []byte {

	combination := string(salt) + string(password)
	passwordHash := sha1.New()
	io.WriteString(passwordHash, combination)

	return passwordHash.Sum(nil)
}

// Generate new password hash and salt
func GenerateSaltAndSha1Password(key, password []byte) ([]byte, []byte, error) {

	var passwordHash []byte

	// Salt with key
	salt, err := GenerateSalt(key, 8)
	if err == nil {
		// Generate password hash
		passwordHash = GenerateSha1Password(salt, []byte(password))
	}

	return salt, passwordHash, nil
}

// CheckSha1Password, generate passwordHash with password and hash.
// Equal this passwordHash with checkPasswordHash.
func CheckSha1Password(salt []byte, password []byte, checkPasswordHash []byte) bool {

	// Generate new password hash for equal
	passwordHash := GenerateSha1Password(salt, password)

	// Equal the new passwordHash with the checkPasswordHash
	return bytes.Equal(passwordHash, checkPasswordHash)
}

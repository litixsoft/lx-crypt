package lxcrypt_test

import (
	"crypto/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/litixsoft/lx-crypt"
	"github.com/stretchr/testify/assert"
)
const (
	TestKey = "test.key"
)

// deleteKeyFile, helper for delete generated key file
func deleteKeyFile(t *testing.T, kfp string) {
	if _, err := os.Stat(kfp); err == nil {
		if err := os.Remove(kfp); err != nil {
			t.Fatalf("Delete %s: %v", kfp, err)
		}
	}
}

// TestGenerateKey, generate a key with size 8.
func TestGenerateKey(t *testing.T) {

	const size = 8

	key, err := lxcrypt.GenerateKey(size)
	if err != nil {
		t.Fatalf("Generate key: %v", err)
	}

	assert.Equal(t, size, len(key), "should be size 8.")
}

// TestGenerateKeyError, generate a key and provoke error.
func TestGenerateKeyError(t *testing.T) {

	_, err := lxcrypt.GenerateKey(0)
	assert.NotNil(t, err, "should be return error.")
	assert.Equal(t, "key size should be between 1 and 32", err.Error(), "should be return correct error message.")
}

// TestGetKeyFromNotExistsFile, get key from not exists file.
func TestGetKeyFromNotExistsFile(t *testing.T) {

	const Size = 32
	kfp := filepath.Join(TestKey)

	// Before get key from file, delete mms-test.key if exists
	deleteKeyFile(t, kfp)

	key, err := lxcrypt.GetKeyFromFile(kfp)

	assert.Nil(t, err, "should be nil")
	assert.Equal(t, Size, len(key), "should be return a key with size 32")
}

// TestGetKeyFromFile, get key from exists file.
func TestGetKeyFromFile(t *testing.T) {

	// Create a new key file for test
	const Size = 32
	kfp := filepath.Join(TestKey)

	// Before get key from file, delete mms-test.key if exists
	deleteKeyFile(t, kfp)

	key, err := lxcrypt.GetKeyFromFile(kfp)

	if err != nil {
		t.Fatalf("GetKeyFromFile: %v", err)
	}

	existsKey, err := lxcrypt.GetKeyFromFile(kfp)

	assert.Nil(t, err, "should be nil")
	assert.Equal(t, Size, len(existsKey), "should be return a key with size 32")
	assert.Equal(t, key, existsKey, "should be equal to first generated key")
}

// TestEnAndDeCrypt, encrypt and decrypt plain text.
func TestEnAndDeCrypt(t *testing.T) {

	// Before test create a key
	key := make([]byte, 32)

	// Use the crypto random
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Create own key: %v", err)
	}

	// Text for encrypt
	testText := "test plain text for en and decrypt"

	// Encrypt text
	encryptedText, err := lxcrypt.EncryptAES(key, []byte(testText))
	if err != nil {
		t.Fatalf("EncryptAES: %v", err)
	}

	assert.NotEqual(t, testText, encryptedText, "crypted text should be not equal.")

	// Decrypt from string
	decryptedText, err := lxcrypt.DecryptAES(key, []byte(encryptedText))
	if err != nil {
		t.Fatalf("DecryptAES: %v", err)
	}

	assert.Equal(t, testText, string(decryptedText), "decrypted text should be equal original text.")
}

// TestEncryptError, encrypt plain text with wrong key.
func TestEncryptError(t *testing.T) {

	// Before create a wrong key, error by all keys do not size 16, 24 and 32
	key := make([]byte, 8)

	// Use the crypto random
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Create own key: %v", err)
	}

	// Encrypt text
	_, err := lxcrypt.EncryptAES(key, []byte("error test"))

	assert.NotNil(t, err, "should be return a error.")
	assert.Equal(t, "crypto/aes: invalid key size 8", err.Error(), "should be return correct error message.")
}

// TestDecryptKeyError, decrypt with wrong key.
func TestDecryptKeyError(t *testing.T) {

	// Before test create a new key
	key := make([]byte, 8)

	// Use the crypto random
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Create own key: %v", err)
	}

	// Decrypt short text
	_, err := lxcrypt.DecryptAES(key, []byte("error test"))
	assert.NotNil(t, err, "should be return a error.")
	assert.Equal(t, "crypto/aes: invalid key size 8", err.Error(), "should be return correct error message.")
}

// TestDecryptError, decrypt to short plain text.
func TestDecryptError(t *testing.T) {

	// Before test create a new key
	key := make([]byte, 32)

	// Use the crypto random
	if _, err := rand.Read(key); err != nil {
		t.Fatalf("Create own key: %v", err)
	}

	// Decrypt short text
	_, err := lxcrypt.DecryptAES(key, []byte("a"))
	assert.NotNil(t, err, "should be return a error.")
	assert.Equal(t, "text too short", err.Error(), "should be return correct error message.")
}
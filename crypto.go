// This package implements simple crypto function for passwords and tokens
package crypto

import (
	"crypto/rand"
	basicRand "math/rand"

	"crypto/sha256"
	"encoding/hex"

	"golang.org/x/crypto/pbkdf2"
)

const (
	ITERATION  = 1000
	HASHLENGTH = 32
)

// This function returns a new slice of n random bytes
func RandomBytes(n int) ([]byte, error) {
	randomBytes := make([]byte, n)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return nil, err
	} else {
		return randomBytes, nil
	}
}

// This function is the same as RandomBytes but converts the random bytes generated to a hexadecimal string
func RandomString(n int) (string, error) {
	randomBytes := make([]byte, n)
	_, err := rand.Read(randomBytes)
	if err != nil {
		return "", err
	} else {
		return hex.EncodeToString(randomBytes), nil
	}
}

// This function hashes a password using sha256 algorithm and pbkdf2 iteration algorithm
func HashPassword(password []byte, salt []byte) []byte {
	return pbkdf2.Key(password, salt, ITERATION, HASHLENGTH, sha256.New)
}

// This function is the same as HashPassword  but converts the hash to a hexadecimal string
func HashPasswordString(password []byte, salt []byte) string {
	hash := pbkdf2.Key(password, salt, ITERATION, HASHLENGTH, sha256.New)
	return hex.EncodeToString(hash)
}

// This function generate a simple random password - not very secure as rand is not cryptographic ready though
func RandomPassword(n int) string {
	var letters = []rune("!@#$%^&*()_-+=abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
	b := make([]rune, n)
	for i := range b {
		b[i] = letters[basicRand.Intn(len(letters))]
	}
	return string(b)
}

// usage example
//func main() {
//	str := "hello this is my password"
//	password := []byte(str)

//	// generate salt
//	salt, _ := RandomBytes(32)

//	hash := HashPassword(password, salt)
//	fmt.Println(hash)
//}

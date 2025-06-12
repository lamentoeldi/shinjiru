package argon2

import (
	"bytes"
	"fmt"
	"golang.org/x/crypto/argon2"
)

const (
	depth   = 3         // hashing depth
	memory  = 32 * 1024 // hashing memory size in kb
	threads = 4         // hashing threads number
	keyLen  = 64        // hash length in bytes
)

var (
	ErrWrongPassword = fmt.Errorf("password does not match hash")
)

func CompareHashAndPassword(password, hash []byte, salt string) error {
	pwdHash := HashPassword(password, salt)
	if !bytes.Contains(hash, pwdHash) {
		return ErrWrongPassword
	}

	return nil
}

func HashPassword(password []byte, salt string) []byte {
	hash := argon2.Key(
		password,
		[]byte(salt),
		depth,
		memory,
		threads,
		keyLen,
	)

	return hash
}

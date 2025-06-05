package utils

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"io"
)

const (
	KeyID = "kid"
)

type KeyChain map[string]*ecdsa.PublicKey

func (kc KeyChain) Add(r io.Reader) error {
	pk, err := ParsePublicKey(r)
	if err != nil {
		return fmt.Errorf("failed to add key: %w", err)
	}

	kid, err := GenerateKeyID(pk)
	if err != nil {
		return fmt.Errorf("failed to add key: %w", err)
	}

	kc[kid] = pk
	return nil
}

// GeneratePrivateKey generates *rsa.PrivateKey with KeyID
func GeneratePrivateKey() (*ecdsa.PrivateKey, error) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA key pair: %w", err)
	}

	return pk, nil
}

// GenerateKeyID generates kid from *ecdsa.PublicKey
// It is advised to call this function on init only
func GenerateKeyID(pk *ecdsa.PublicKey) (string, error) {
	b, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}

	hash := sha256.New()

	_, err = hash.Write(b)
	if err != nil {
		return "", fmt.Errorf("failed to hash private key: %w", err)
	}

	kid := hex.EncodeToString(hash.Sum(nil))

	return kid, nil
}

// EncodeKey receives either *ecdsa.PrivateKey or *ecdsa.PublicKey and writes it to writer in PEM format
func EncodeKey[T *ecdsa.PrivateKey | *ecdsa.PublicKey](w io.Writer, key T) error {
	data := make([]byte, 0)
	keyType := ""

	var err error

	switch key := any(key).(type) {
	case *ecdsa.PrivateKey:
		data, err = x509.MarshalECPrivateKey(key)

		keyType = "EC PRIVATE KEY"
	case *ecdsa.PublicKey:
		data, err = x509.MarshalPKIXPublicKey(key)
		keyType = "EC PUBLIC KEY"
	}
	if err != nil {
		return fmt.Errorf("failed to marshal key: %w", err)
	}

	block := &pem.Block{
		Type:  keyType,
		Bytes: data,
	}

	err = pem.Encode(w, block)
	if err != nil {
		return fmt.Errorf("failed to encode key: %w", err)
	}

	return nil
}

// ParsePrivateKey parses private key in PEM format
func ParsePrivateKey(r io.Reader) (*ecdsa.PrivateKey, error) {
	key, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	pk, err := parsePrivateKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return pk, nil
}

func parsePrivateKey(key []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("failed to decode private key")
	}

	pk, err := x509.ParseECPrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key: %w", err)
	}

	return pk, nil
}

// ParsePublicKey parses public key in PEM format
func ParsePublicKey(r io.Reader) (*ecdsa.PublicKey, error) {
	key, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("failed to read public key: %w", err)
	}

	pk, err := parsePublicKey(key)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	return pk, nil
}

func parsePublicKey(key []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(key)
	if block == nil {
		return nil, fmt.Errorf("failed to decode public key")
	}

	pkAny, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %w", err)
	}

	pk, ok := pkAny.(*ecdsa.PublicKey)
	if !ok {
		return nil, fmt.Errorf("parsed key is not ECDSA")
	}

	return pk, nil
}

// ParseKeychain accepts keychain in json format kid:key and maps it to KeyChain.
// This function may have bad performance due to multiple calls of ParsePublicKey. It is advised to call it only on startup
func ParseKeychain(keychain []byte) (KeyChain, error) {
	raw := make(map[string][]byte)
	err := json.Unmarshal(keychain, &raw)
	if err != nil {
		return nil, fmt.Errorf("failed to parse keychain: %w", err)
	}

	kc := make(map[string]*ecdsa.PublicKey)

	for key, val := range raw {
		pk, err := parsePublicKey(val)
		if err != nil {
			return nil, fmt.Errorf("failed to parse keychain: %w", err)
		}

		kc[key] = pk
	}

	return kc, nil
}

// KeyFunc accepts KeyChain with *rsa.PublicKey and returns jwt.Keyfunc to validate asymmetric signature
func KeyFunc(keyChain KeyChain) jwt.Keyfunc {
	return func(t *jwt.Token) (interface{}, error) {
		kid, ok := t.Header[KeyID].(string)
		if !ok {
			return nil, fmt.Errorf("keyFunc: missing kid")
		}

		key, ok := keyChain[kid]
		if !ok {
			return nil, fmt.Errorf("keyFunc: missing public key for kid %s", kid)
		}

		return key, nil
	}
}

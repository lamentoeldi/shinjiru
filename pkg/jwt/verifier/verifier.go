package verifier

import (
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/shinjiru/pkg/jwt/utils"
)

// Verifier is a struct used by token audience to verify tokens and extract their claims
type Verifier struct {
	keyChain utils.KeyChain // hashmap which contains public keys to validate tokens
}

// NewVerifier accepts a utils.KeyChain with public keys and returns new *Verifier instance
func NewVerifier(keyChain utils.KeyChain) (*Verifier, error) {
	return &Verifier{
		keyChain: keyChain,
	}, nil
}

// VerifyAndExtract validates the token and returns its claims
func (v *Verifier) VerifyAndExtract(access string) (*jwt.MapClaims, error) {
	kf := utils.KeyFunc(v.keyChain)

	token, err := jwt.ParseWithClaims(access, &jwt.MapClaims{}, kf)
	if err != nil {
		return nil, fmt.Errorf("verify and extract: %w", err)
	}

	if !token.Valid {
		return nil, fmt.Errorf("verify and extract: invalid token")
	}

	return token.Claims.(*jwt.MapClaims), nil
}

func (v *Verifier) Keychain() utils.KeyChain {
	return v.keyChain
}

package signer

import (
	"crypto/ecdsa"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/shinjiru/pkg/jwt/utils"
	"time"
)

const (
	accessType  = "access"
	refreshType = "refresh"
	tokenType   = "type"
)

// Signer is a structure used by token issuer
type Signer struct {
	accessKey  *ecdsa.PrivateKey // private key which is used to sign access tokens
	refreshKey *ecdsa.PrivateKey // private key which is used to sign refresh tokens

	keyChain utils.KeyChain // hashmap which contains public keys to validate tokens

	accessKid  string // access key id
	refreshKid string // refresh key id

	AccessTTL  time.Duration // access token TTL
	RefreshTTL time.Duration // refresh token TTL
}

// NewSigner initializes a new *Signer instance with provided private keys and token TTL.
// Note: refresh public key is automatically added to the keyChain to refresh tokens on demand
func NewSigner(access, refresh *ecdsa.PrivateKey, accessTTL, refreshTTL time.Duration, keyChain utils.KeyChain) (*Signer, error) {
	accessKid, err := utils.GenerateKeyID(&access.PublicKey)
	refreshKid, err := utils.GenerateKeyID(&refresh.PublicKey)
	if err != nil {
		return nil, fmt.Errorf("failed to generate key IDs: %w", err)
	}

	s := &Signer{
		accessKey:  access,
		refreshKey: refresh,

		accessKid:  accessKid,
		refreshKid: refreshKid,

		keyChain: keyChain,

		AccessTTL:  accessTTL,
		RefreshTTL: refreshTTL,
	}

	s.keyChain[s.refreshKid] = &s.refreshKey.PublicKey

	return s, nil
}

// IssueCouple accepts iss, sub and custom JWT claims. It generates tokens with some claims.
// Returns access, refresh token
func (s *Signer) IssueCouple(issuer, uid string, m map[string]any) (*jwt.Token, *jwt.Token, error) {
	now := time.Now()

	jti, _ := uuid.NewV7()

	accessClaims := jwt.MapClaims(m)

	accessClaims["iss"] = issuer
	accessClaims["sub"] = uid
	accessClaims["exp"] = jwt.NewNumericDate(now.Add(s.AccessTTL))
	accessClaims["iat"] = jwt.NewNumericDate(now)

	refreshClaims := jwt.MapClaims{
		"iss": issuer,
		"sub": uid,
		"exp": jwt.NewNumericDate(now.Add(s.AccessTTL)),
		"iat": jwt.NewNumericDate(now),
		"jti": jti.String(),
	}

	access := jwt.NewWithClaims(jwt.SigningMethodES256, accessClaims)
	refresh := jwt.NewWithClaims(jwt.SigningMethodES256, refreshClaims)

	access.Header[tokenType] = accessType
	refresh.Header[tokenType] = refreshType

	access.Header[utils.KeyID] = s.accessKid
	refresh.Header[utils.KeyID] = s.refreshKid

	return access, refresh, nil
}

// SignCouple signs provided access and refresh tokens
func (s *Signer) SignCouple(access, refresh *jwt.Token) (string, string, error) {
	accessStr, err := access.SignedString(s.accessKey)
	refreshStr, err := refresh.SignedString(s.refreshKey)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign tokens: %w", err)
	}

	return accessStr, refreshStr, nil
}

// ParseRefresh parses the refresh token string to *jwt.Token instance
func (s *Signer) ParseRefresh(refresh string) (*jwt.Token, error) {
	kf := utils.KeyFunc(s.keyChain)

	return jwt.ParseWithClaims(refresh, &jwt.MapClaims{}, kf)
}

// Refresh accepts refresh token, verifies it and returns a new couple of access and refresh tokens.
// Claims are not preserved between new and old token so way could be updated during refresh
func (s *Signer) Refresh(token *jwt.Token, claims *jwt.MapClaims) (string, string, error) {
	const errPattern = "cannot refresh: %w"

	issuer, err := token.Claims.GetIssuer()
	uid, err := token.Claims.GetSubject()
	if err != nil {
		return "", "", fmt.Errorf(errPattern, err)
	}

	tt, ok := token.Header[tokenType]
	if !ok || tt != refreshType {
		return "", "", fmt.Errorf("cannot refresh: invalid token type")
	}

	accessToken, refreshToken, err := s.IssueCouple(issuer, uid, *claims)
	if err != nil {
		return "", "", fmt.Errorf(errPattern, err)
	}
	return s.SignCouple(accessToken, refreshToken)
}

func (s *Signer) Keychain() utils.KeyChain {
	return s.keyChain
}

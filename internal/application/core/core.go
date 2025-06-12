package core

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/shinjiru/internal/models"
	"github.com/shinjiru/pkg/argon2"
	"time"
)

const (
	issuer       = "shinjiru"
	tokenAccess  = "access"
	tokenRefresh = "refresh"
	tokenReset   = "reset"
	headerKid    = "kid"
	headerType   = "token_type"
)

type Core struct {
	accessPK  *ecdsa.PrivateKey
	refreshPK *ecdsa.PrivateKey

	accessKid  string
	refreshKid string

	accessTTL  time.Duration
	refreshTTL time.Duration
}

func New(
	accessPK, refreshPK *ecdsa.PrivateKey,
	accessTTL, refreshTTL time.Duration,
) *Core {
	accessKid := makeKid(accessPK)
	refreshKid := makeKid(refreshPK)

	return &Core{
		accessPK:  accessPK,
		refreshPK: refreshPK,

		accessKid:  accessKid,
		refreshKid: refreshKid,

		accessTTL:  accessTTL,
		refreshTTL: refreshTTL,
	}
}

func (c *Core) CreateRealm(
	_ context.Context, realmName string,
) (*models.Realm, error) {
	id, _ := uuid.NewV7()

	realm := &models.Realm{
		ID:   id,
		Name: realmName,
	}

	return realm, nil
}

func (c *Core) CreateUser(
	_ context.Context,
	username, password string,
	realmID uuid.UUID,
) (*models.User, error) {

	id, _ := uuid.NewV7()

	hash := argon2.HashPassword(
		[]byte(password),
		id.String(),
	)

	user := &models.User{
		ID:       id,
		RealmID:  realmID,
		Username: username,
		Password: hash,
	}

	return user, nil
}

func (c *Core) VerifyPassword(
	_ context.Context, userID uuid.UUID,
	password, hash []byte,
) error {
	return argon2.CompareHashAndPassword(password, hash, userID.String())
}

func (c *Core) ResetPassword(
	_ context.Context, userID uuid.UUID,
	newPassword string,
) ([]byte, error) {
	hash := argon2.HashPassword([]byte(newPassword), userID.String())

	return hash, nil
}

func (c *Core) IssueTokens(
	_ context.Context,
	user *models.User,
) (*jwt.Token, *jwt.Token, uuid.UUID, error) {
	jti, _ := uuid.NewV7()

	claims := &models.JWTClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			ID:       jti.String(),
			Issuer:   issuer,
			Subject:  user.ID.String(),
			IssuedAt: jwt.NewNumericDate(time.Now()),
		},
		Roles: user.Roles.ToStrings(),
	}

	access := c.issueAccess(claims)
	refresh := c.issueRefresh(claims)

	access.Header[headerKid] = c.accessKid
	refresh.Header[headerKid] = c.refreshKid

	access.Header[headerType] = tokenAccess
	refresh.Header[headerType] = tokenRefresh

	return access, refresh, jti, nil
}

func (c *Core) SignTokens(
	_ context.Context,
	access, refresh *jwt.Token,
) (string, string, error) {
	accessStr, err := access.SignedString(c.accessPK)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign access token: %w", err)
	}

	refreshStr, err := refresh.SignedString(c.refreshPK)
	if err != nil {
		return "", "", fmt.Errorf("failed to sign refresh token: %w", err)
	}

	return accessStr, refreshStr, nil
}

func (c *Core) VerifyAndExtract(_ context.Context, tokenStr string) (*jwt.Token, *models.JWTClaims, error) {
	claims := models.JWTClaims{}

	token, err := jwt.ParseWithClaims(tokenStr, &claims, c.keyFunc)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to parse token: %w", err)
	}

	return token, &claims, nil
}

func (c *Core) GetPublicKey(_ context.Context) ([]byte, error) {
	pub := c.accessPK.PublicKey

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %w", err)
	}

	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}

	return pem.EncodeToMemory(block), nil
}

func (c *Core) issueAccess(claims *models.JWTClaims) *jwt.Token {
	claims.
		RegisteredClaims.
		ExpiresAt = jwt.NewNumericDate(claims.RegisteredClaims.IssuedAt.Add(c.accessTTL))
	return jwt.NewWithClaims(jwt.SigningMethodES256, claims)
}

func (c *Core) issueRefresh(claims *models.JWTClaims) *jwt.Token {
	claims.
		RegisteredClaims.
		ExpiresAt = jwt.NewNumericDate(claims.RegisteredClaims.IssuedAt.Add(c.refreshTTL))
	return jwt.NewWithClaims(jwt.SigningMethodES256, claims)
}

func (c *Core) keyFunc(token *jwt.Token) (interface{}, error) {
	tokenType, ok := token.Header[headerType].(string)
	if !ok {
		return nil, fmt.Errorf("failed to parse token type")
	}

	switch tokenType {
	case tokenAccess:
		return c.accessPK, nil
	case tokenReset:
		return c.accessPK, nil
	case tokenRefresh:
		return c.refreshPK, nil
	}

	return nil, fmt.Errorf("invalid token headers")
}

func makeKid(key *ecdsa.PrivateKey) string {
	pub := key.PublicKey
	bytes := elliptic.MarshalCompressed(pub.Curve, pub.X, pub.Y)
	hash := sha256.Sum256(bytes)

	return hex.EncodeToString(hash[:])
}

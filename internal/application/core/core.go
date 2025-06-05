package core

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/shinjiru/internal/models"
	"github.com/shinjiru/pkg/argon2"
	"github.com/shinjiru/pkg/jwt/signer"
)

const (
	issuer = "shinjiru"
)

type Core struct {
	signer *signer.Signer
}

func New(signer *signer.Signer) *Core {
	return &Core{
		signer: signer,
	}
}

func (c *Core) CreateRealm(
	_ context.Context, realmName string,
) (models.Realm, error) {
	id, _ := uuid.NewV7()

	realm := models.Realm{
		ID:   id,
		Name: realmName,
	}

	return realm, nil
}

func (c *Core) CreateUser(
	_ context.Context,
	username, password string,
	realmID uuid.UUID,
) (models.User, error) {

	id, _ := uuid.NewV7()

	hash := argon2.HashPassword(
		[]byte(password),
		id.String(),
	)

	user := models.User{
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
	_ context.Context, user models.User,
	claims map[string]any,
) (*jwt.Token, *jwt.Token, error) {
	return c.signer.IssueCouple(issuer, user.ID.String(), claims)
}

func (c *Core) SignTokens(
	_ context.Context,
	access, refresh *jwt.Token,
) (string, string, error) {
	return c.signer.SignCouple(access, refresh)
}

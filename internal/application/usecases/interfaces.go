package usecases

import (
	"context"
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"github.com/shinjiru/internal/models"
)

type Core interface {
	RealmCore
	UserCore
	AuthenticationCore
	AuthorizationCore
}

type RealmCore interface {
	CreateRealm(ctx context.Context, realmName string) (models.Realm, error)
}

type UserCore interface {
	CreateUser(ctx context.Context, username, password string, realmID uuid.UUID) (models.User, error)
}

type AuthenticationCore interface {
	VerifyPassword(ctx context.Context, password, hash []byte) error
	ResetPassword(ctx context.Context, userID uuid.UUID, newPassword string) ([]byte, error)
}

type AuthorizationCore interface {
	IssueTokens(ctx context.Context, user models.User, claims map[string]any) (access, refresh models.JWTToken, err error)
	SignTokens(ctx context.Context, access, refresh jwt.Token) (string, string, error)
}

package ports

import (
	"context"
	"github.com/google/uuid"
	"github.com/shinjiru/internal/models"
)

type InboundPort interface {
	RealmManager
	UserManager
	AuthorizationManager
	RoleManager
	SessionManager
}

type RealmManager interface {
	CreateRealm(ctx context.Context, realmName string) (uuid.UUID, error)
	GetRealm(ctx context.Context, realmID uuid.UUID) (*models.Realm, error)
	GetRealms(ctx context.Context) ([]*models.Realm, error)
	UpdateRealm(ctx context.Context, realm *models.Realm) error
	DeleteRealm(ctx context.Context, realmID uuid.UUID) error
}

type UserManager interface {
	CreateUser(ctx context.Context, user *models.User) (uuid.UUID, error)
	GetUser(ctx context.Context, userID uuid.UUID) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	DeleteUser(ctx context.Context, userID uuid.UUID) error
}

type AuthorizationManager interface {
	StartAuthentication(ctx context.Context, creds *models.BaseCredentials) (*models.AuthStep, error)
	Authenticate(ctx context.Context, auth *models.AuthSession) (*models.AuthStep, error)
	Authorize(ctx context.Context, authID uuid.UUID) (*models.TokenCouple, error)

	RequestPasswordReset(ctx context.Context, username string) (*models.AuthStep, error)
	ConfirmPasswordReset(ctx context.Context, resetToken string) error

	RefreshTokens(ctx context.Context, refreshToken string) (*models.TokenCouple, error)
	GetPublicKey(ctx context.Context) ([]byte, error)
}

type RoleManager interface {
	AddRole(ctx context.Context, userID uuid.UUID, roleName string) error
	RemoveRole(ctx context.Context, userID uuid.UUID, roleName string) error
}

type SessionManager interface {
	GetSessions(ctx context.Context, userID uuid.UUID) ([]*models.Session, error)
	TerminateSession(ctx context.Context, sessionID uuid.UUID) error
	TerminateAllSessions(ctx context.Context, userID uuid.UUID) error
}

package ports

import (
	"context"
	"github.com/google/uuid"
	"github.com/shinjiru/internal/models"
)

type ResourceStoragePort interface {
	RealmStorage
	UserStorage
	SessionsStoragePort
}

type RealmStorage interface {
	AddRealm(ctx context.Context, realm *models.Realm) error
	GetRealm(ctx context.Context, id uuid.UUID) (*models.Realm, error)
	GetRealms(ctx context.Context) ([]*models.Realm, error)
	UpdateRealm(ctx context.Context, realm *models.Realm) error
	DeleteRealm(ctx context.Context, id uuid.UUID) error
}

type UserStorage interface {
	AddUser(ctx context.Context, user *models.User) error
	GetUser(ctx context.Context, id uuid.UUID) (*models.User, error)
	GetByUsername(ctx context.Context, username string) (*models.User, error)
	UpdateUser(ctx context.Context, user *models.User) error
	DeleteUser(ctx context.Context, id uuid.UUID) error

	IncVersion(ctx context.Context, userID uuid.UUID) error

	AddRole(ctx context.Context, userID uuid.UUID, roleName string) error
	RemoveRole(ctx context.Context, userID uuid.UUID, roleName string) error
}

type SessionsStoragePort interface {
	Add(ctx context.Context, session *models.Session) error
	Get(ctx context.Context, sessionID uuid.UUID) (*models.Session, error)
	GetAll(ctx context.Context, userID uuid.UUID) ([]*models.Session, error)
	Delete(ctx context.Context, sessionID uuid.UUID) error
	DeleteAll(ctx context.Context, userID uuid.UUID) error
}

type SecretsStoragePort interface {
	AddSecret(ctx context.Context, key string, value []byte) error
	GetSecret(ctx context.Context, key string) ([]byte, error)
}

type CachePort interface {
	Add(ctx context.Context, key string, value []byte) error
	Get(ctx context.Context, key string) ([]byte, error)
}

type BlackListPort interface {
	Add(ctx context.Context, id string) error
	Check(ctx context.Context, id string) (bool, error)
}

type EventsPort interface {
	EmitEvent(ctx context.Context, event *models.Event) error
}

type Authenticator interface {
	Begin(ctx context.Context, auth *models.AuthSession) (*models.AuthStep, error)
	Verify(ctx context.Context, auth *models.AuthSession) (*models.AuthStep, error)
}

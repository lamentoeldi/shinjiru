package models

import (
	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"
	"time"
)

type BaseCredentials struct {
	Username string
	Password string
}

type Realm struct {
	ID   uuid.UUID
	Name string
}

type User struct {
	ID       uuid.UUID `json:"id"`
	RealmID  uuid.UUID `json:"realm_id"`
	Username string    `json:"username"`
	Password []byte    `json:"password"`
	Version  int       `json:"ver"`
	Roles    RoleSet   `json:"roles"`
	MFA      []*MFAConfig
}

type Role struct {
	ID   uuid.UUID
	Name string
}

// AuthContext is server authentication DTO
type AuthContext struct {
	ID                  uuid.UUID `json:"id"`
	Step                string    `json:"step"`
	User                User      `json:"user"`
	NeedMFAVerification bool      `json:"need_mfa_verification"`
}

type Session struct {
	ID           uuid.UUID
	UserID       uuid.UUID
	Platform     string
	LastActivity time.Time
	StartedAt    time.Time
}

type TokenCouple struct {
	AccessToken  string
	RefreshToken string
}

type Event struct {
	Type      string
	Timestamp time.Time
	Meta      map[string]any
}

// AuthStep is an object retrieved by client
// to handle next auth step properly
type AuthStep struct {
	ID   uuid.UUID      `json:"id"`
	Step string         `json:"step"`
	Body map[string]any `json:"body"`
}

// AuthSession is an object sent by client to pass MFA
type AuthSession struct {
	ID   uuid.UUID         `json:"id"`
	Body map[string]string `json:"body"`
}

type MFAConfig struct {
	ID         uuid.UUID      `json:"id"`
	StepName   string         `json:"step_name"`
	Enabled    bool           `json:"enabled"`
	Attributes map[string]any `json:"attributes"`
}

type JWTClaims struct {
	Version int      `json:"ver"`
	Roles   []string `json:"roles"`
	jwt.RegisteredClaims
}

type RoleSet []Role

func (rc RoleSet) ToStrings() []string {
	roles := make([]string, 0, len(rc))

	for _, role := range rc {
		roles = append(roles, role.Name)
	}

	return roles
}

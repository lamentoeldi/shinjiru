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
	ID       uuid.UUID
	RealmID  uuid.UUID
	Username string
	Password []byte
	Roles    []Role
}

type Role struct {
	ID   uuid.UUID
	Name string
}

type AuthContext struct {
	ID   uuid.UUID
	Step string
	User User
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

type AuthStep struct {
	ID   uuid.UUID
	Step string
}

type AuthSession struct {
	ID   uuid.UUID
	Meta map[string]string
}

type JWTToken struct {
	ID     uuid.UUID
	Claims jwt.MapClaims
	Token  jwt.Token
}

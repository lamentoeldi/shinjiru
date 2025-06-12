package usecases

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/google/uuid"
	"github.com/shinjiru/internal/models"
	"github.com/shinjiru/internal/ports"
	"time"
)

const (
	AuthStepAuth          = "authorize"
	AuthStepPasswordReset = "reset_password"
)

type App struct {
	core           Core
	cache          ports.CachePort
	repo           ports.ResourceStoragePort
	bl             ports.BlackListPort
	authenticators map[string]ports.Authenticator
}

func NewApp(
	core Core, cache ports.CachePort, repo ports.ResourceStoragePort,
	bl ports.BlackListPort, authenticators map[string]ports.Authenticator,
) *App {
	return &App{
		core:           core,
		repo:           repo,
		cache:          cache,
		authenticators: authenticators,
	}
}

func (a *App) CreateRealm(ctx context.Context, realmName string) (uuid.UUID, error) {
	realm, err := a.core.CreateRealm(ctx, realmName)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create realm: %w", err)
	}

	err = a.repo.AddRealm(ctx, realm)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to add realm: %w", err)
	}

	return realm.ID, nil
}

func (a *App) GetRealm(ctx context.Context, realmID uuid.UUID) (*models.Realm, error) {
	realm, err := a.repo.GetRealm(ctx, realmID)
	if err != nil {
		return nil, fmt.Errorf("failed to get realm: %w", err)
	}

	return realm, nil
}

func (a *App) GetRealms(ctx context.Context) ([]*models.Realm, error) {
	realms, err := a.repo.GetRealms(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get realms: %w", err)
	}

	return realms, nil
}

func (a *App) UpdateRealm(ctx context.Context, realm *models.Realm) error {
	err := a.repo.UpdateRealm(ctx, realm)
	if err != nil {
		return fmt.Errorf("failed to update realm: %w", err)
	}

	return nil
}

func (a *App) DeleteRealm(ctx context.Context, realmID uuid.UUID) error {
	err := a.repo.DeleteRealm(ctx, realmID)
	if err != nil {
		return fmt.Errorf("failed to delete realm: %w", err)
	}

	return nil
}

func (a *App) CreateUser(ctx context.Context, user *models.User) (uuid.UUID, error) {
	user, err := a.core.CreateUser(ctx, user.Username, string(user.Password), user.RealmID)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to create user: %w", err)
	}

	err = a.repo.AddUser(ctx, user)
	if err != nil {
		return uuid.Nil, fmt.Errorf("failed to add user: %w", err)
	}

	return user.ID, nil
}

func (a *App) GetUser(ctx context.Context, userID uuid.UUID) (*models.User, error) {
	user, err := a.repo.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	return user, nil
}

func (a *App) UpdateUser(ctx context.Context, user *models.User) error {
	err := a.repo.UpdateUser(ctx, user)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

func (a *App) DeleteUser(ctx context.Context, userID uuid.UUID) error {
	err := a.repo.DeleteUser(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to delete user: %w", err)
	}

	return nil
}

func (a *App) StartAuthentication(ctx context.Context, creds *models.BaseCredentials) (*models.AuthStep, error) {
	user, err := a.repo.GetByUsername(ctx, creds.Username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	err = a.core.VerifyPassword(ctx, user.ID, []byte(creds.Password), user.Password)
	if err != nil {
		return nil, fmt.Errorf("failed to verify password: %w", err)
	}

	authID, _ := uuid.NewV7()

	session := &models.AuthContext{
		ID:   authID,
		User: *user,
	}

	step := &models.AuthStep{
		ID: authID,
	}

	if len(user.MFA) < 1 {
		step.Step = AuthStepAuth
		session.Step = AuthStepAuth
	} else {
		stepName := user.MFA[0].StepName
		step.Step = stepName
		session.Step = stepName
	}

	authJSON, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal user: %w", err)
	}

	err = a.cache.Add(ctx, session.ID.String(), authJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to add auth: %w", err)
	}

	return step, nil
}

func (a *App) Authenticate(ctx context.Context, auth *models.AuthSession) (*models.AuthStep, error) {
	authJSON, err := a.cache.Get(ctx, auth.ID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch auth: %w", err)
	}

	authCtx := &models.AuthContext{}
	err = json.Unmarshal(authJSON, authCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth: %w", err)
	}

	if authCtx.NeedMFAVerification {
		nextStep, err := a.authenticators[authCtx.Step].Verify(ctx, auth)
		if err != nil {
			return nil, fmt.Errorf("failed to verify mfa: %w", err)
		}

		return nextStep, nil
	}

	nextStep, err := a.authenticators[authCtx.Step].Begin(ctx, auth)
	if err != nil {
		return nil, fmt.Errorf("failed to begin auth: %w", err)
	}

	return nextStep, nil
}

func (a *App) Authorize(ctx context.Context, authID uuid.UUID) (*models.TokenCouple, error) {
	authJSON, err := a.cache.Get(ctx, authID.String())
	if err != nil {
		return nil, fmt.Errorf("failed to fetch auth: %w", err)
	}

	authCtx := &models.AuthContext{}
	err = json.Unmarshal(authJSON, authCtx)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal auth: %w", err)
	}

	if authCtx.Step != AuthStepAuth {
		return nil, fmt.Errorf("invalid auth step")
	}

	access, refresh, jti, err := a.core.IssueTokens(ctx, &authCtx.User)
	if err != nil {
		return nil, fmt.Errorf("failed to issue tokens: %w", err)
	}

	sess := &models.Session{
		ID:           jti,
		UserID:       authCtx.User.ID,
		Platform:     "todo",
		LastActivity: time.Now(),
		StartedAt:    time.Now(),
	}

	err = a.repo.Add(ctx, sess)
	if err != nil {
		return nil, fmt.Errorf("failed to add session: %w", err)
	}

	accessStr, refreshStr, err := a.core.SignTokens(ctx, access, refresh)
	if err != nil {
		return nil, fmt.Errorf("failed to sign tokens: %w", err)
	}

	tokens := &models.TokenCouple{
		AccessToken:  accessStr,
		RefreshToken: refreshStr,
	}

	return tokens, nil
}

func (a *App) RequestPasswordReset(ctx context.Context, username string) (*models.AuthStep, error) {
	user, err := a.repo.GetByUsername(ctx, username)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if len(user.MFA) < 1 {
		return nil, fmt.Errorf("mfa required")
	}

	mfaStep := user.MFA[0].StepName

	authID, _ := uuid.NewV7()

	authStep := &models.AuthStep{
		ID:   authID,
		Step: mfaStep,
	}

	session := &models.AuthContext{
		ID:   authID,
		Step: mfaStep,
		User: *user,
	}

	authJSON, err := json.Marshal(session)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal user: %w", err)
	}

	err = a.cache.Add(ctx, session.ID.String(), authJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to add auth: %w", err)
	}

	return authStep, nil
}

func (a *App) ConfirmPasswordReset(ctx context.Context, auth *models.AuthSession) error {
	authJSON, err := a.cache.Get(ctx, auth.ID.String())
	if err != nil {
		return fmt.Errorf("failed to fetch auth: %w", err)
	}

	authCtx := &models.AuthContext{}
	err = json.Unmarshal(authJSON, authCtx)
	if err != nil {
		return fmt.Errorf("failed to unmarshal auth: %w", err)
	}

	if authCtx.Step != AuthStepPasswordReset {
		return fmt.Errorf("invalid auth step")
	}

	newPassword, ok := auth.Body["password"]
	if !ok {
		return fmt.Errorf("no new password provided")
	}

	newHash, err := a.core.ResetPassword(ctx, authCtx.User.ID, newPassword)
	if err != nil {
		return fmt.Errorf("failed to reset password: %w", err)
	}

	updUser := &models.User{
		ID:       authCtx.User.ID,
		Password: newHash,
	}

	err = a.repo.UpdateUser(ctx, updUser)
	if err != nil {
		return fmt.Errorf("failed to update user: %w", err)
	}

	return nil
}

func (a *App) RefreshTokens(ctx context.Context, refreshToken string) (*models.TokenCouple, error) {
	_, claims, err := a.core.VerifyAndExtract(ctx, refreshToken)
	if err != nil {
		return nil, fmt.Errorf("failed to verify refresh token: %w", err)
	}

	jti, err := uuid.Parse(claims.ID)
	if err != nil {
		return nil, fmt.Errorf("failed to parse claims: %w", err)
	}

	userID, err := uuid.Parse(claims.Subject)
	if err != nil {
		return nil, fmt.Errorf("failed to parse subject: %w", err)
	}

	ver := claims.Version

	user, err := a.repo.GetUser(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("failed to get user: %w", err)
	}

	if ver != user.Version {
		return nil, fmt.Errorf("invalid user version")
	}

	access, refresh, jti, err := a.core.IssueTokens(ctx, user)
	if err != nil {
		return nil, fmt.Errorf("failed to issue tokens: %w", err)
	}

	accessSigned, refreshSigned, err := a.core.SignTokens(ctx, access, refresh)
	if err != nil {
		return nil, fmt.Errorf("failed to sign tokens: %w", err)
	}

	session := &models.Session{
		ID:           jti,
		UserID:       userID,
		LastActivity: time.Now(),
		StartedAt:    time.Now(),
	}

	err = a.bl.Add(ctx, jti.String())
	if err != nil {
		return nil, fmt.Errorf("failed to add session: %w", err)
	}

	err = a.repo.Add(ctx, session)
	if err != nil {
		return nil, fmt.Errorf("failed to add session: %w", err)
	}

	err = a.repo.Delete(ctx, jti)
	if err != nil {
		return nil, fmt.Errorf("failed to delete session: %w", err)
	}

	tokens := &models.TokenCouple{
		AccessToken:  accessSigned,
		RefreshToken: refreshSigned,
	}

	return tokens, nil
}

func (a *App) GetPublicKey(ctx context.Context) ([]byte, error) {
	return a.core.GetPublicKey(ctx)
}

func (a *App) AddRole(ctx context.Context, userID uuid.UUID, roleName string) error {
	return a.repo.AddRole(ctx, userID, roleName)
}

func (a *App) RemoveRole(ctx context.Context, userID uuid.UUID, roleName string) error {
	return a.repo.RemoveRole(ctx, userID, roleName)
}

func (a *App) GetSessions(ctx context.Context, userID uuid.UUID) ([]*models.Session, error) {
	return a.repo.GetAll(ctx, userID)
}

func (a *App) TerminateSession(ctx context.Context, sessionID uuid.UUID) error {
	err := a.bl.Add(ctx, sessionID.String())
	if err != nil {
		return fmt.Errorf("failed to blacklist session: %w", err)
	}

	err = a.repo.Delete(ctx, sessionID)
	if err != nil {
		return fmt.Errorf("failed to delete session: %w", err)
	}

	return nil
}

func (a *App) TerminateAllSessions(ctx context.Context, userID uuid.UUID) error {
	err := a.repo.IncVersion(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to increment user version: %w", err)
	}

	err = a.repo.DeleteAll(ctx, userID)
	if err != nil {
		return fmt.Errorf("failed to delete all sessions: %w", err)
	}

	return nil
}

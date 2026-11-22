package nine

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// ManagementConfig configures a [ManagementClient].
type ManagementConfig struct {
	// Issuer is your tenant's issuer: https://acme.9in.io for production users,
	// https://acme-sandbox.9in.io for the sandbox's, or your custom domain.
	Issuer string
	// ClientID and ClientSecret are a confidential application that was given management
	// scopes (Applications → app → API Access → Management API).
	ClientID     string
	ClientSecret string
	// HTTPClient is used for every call. Default: a client with a 10-second timeout.
	HTTPClient *http.Client
	// AllowInsecureIssuer accepts a plain-http issuer other than localhost (development only).
	AllowInsecureIssuer bool
}

// ManagementConfigFromEnv returns a ManagementConfig from NINE_ISSUER, NINE_CLIENT_ID,
// NINE_CLIENT_SECRET and NINE_ALLOW_INSECURE_ISSUER.
func ManagementConfigFromEnv() ManagementConfig {
	return ManagementConfig{
		Issuer:              Env("ISSUER"),
		ClientID:            Env("CLIENT_ID"),
		ClientSecret:        Env("CLIENT_SECRET"),
		AllowInsecureIssuer: envBool("ALLOW_INSECURE_ISSUER"),
	}
}

// ManagementClient calls the Management API (/api/v1) of one tenant environment: users,
// sessions, login links and imports. It gets client-credentials tokens itself, one per
// management scope (so an application granted only some scopes works), and caches each
// until shortly before it expires. Safe for concurrent use.
//
// Wire data uses 9in's snake_case names in both directions. Errors are *Error with the
// API's error code (not_found, identifier_taken, invalid_user…), Status and Details.
type ManagementClient struct {
	issuer string
	http   *http.Client
	tokens map[string]*ClientCredentials
}

// The management scopes, one token each.
const (
	scopeUsersRead     = "management:users:read"
	scopeUsersWrite    = "management:users:write"
	scopeSessionsWrite = "management:sessions:write"
)

// NewManagementClient returns a ManagementClient.
func NewManagementClient(cfg ManagementConfig) (*ManagementClient, error) {
	if cfg.Issuer == "" {
		return nil, invalidOptions("Issuer is required (NINE_ISSUER)")
	}
	if cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil, invalidOptions("ClientID and ClientSecret are required (a confidential application with management scopes)")
	}
	issuer, err := NormalizeIssuer(cfg.Issuer, cfg.AllowInsecureIssuer)
	if err != nil {
		return nil, err
	}
	m := &ManagementClient{issuer: issuer, http: newHTTPClient(cfg.HTTPClient), tokens: make(map[string]*ClientCredentials)}
	for _, scope := range []string{scopeUsersRead, scopeUsersWrite, scopeSessionsWrite} {
		cc, err := NewClientCredentials(ClientCredentialsConfig{
			Issuer: issuer, ClientID: cfg.ClientID, ClientSecret: cfg.ClientSecret, Scopes: []string{scope},
			HTTPClient: cfg.HTTPClient, AllowInsecureIssuer: true,
		})
		if err != nil {
			return nil, err
		}
		m.tokens[scope] = cc
	}
	// The three token sources share one discovery document.
	shared := m.tokens[scopeUsersRead].o.provider
	for _, cc := range m.tokens {
		cc.o.provider = shared
	}
	return m, nil
}

// ManagedUser is a user as the Management API and webhooks send it.
type ManagedUser struct {
	ID                  string         `json:"id"`
	Email               string         `json:"email"`
	EmailVerified       bool           `json:"email_verified"`
	PhoneNumber         string         `json:"phone_number"`
	PhoneNumberVerified bool           `json:"phone_number_verified"`
	Username            string         `json:"username"`
	PreferredUsername   string         `json:"preferred_username"`
	Name                string         `json:"name"`
	GivenName           string         `json:"given_name"`
	MiddleName          string         `json:"middle_name"`
	FamilyName          string         `json:"family_name"`
	Nickname            string         `json:"nickname"`
	Gender              string         `json:"gender"`
	Website             string         `json:"website"`
	Picture             string         `json:"picture"`
	Locale              string         `json:"locale"`
	Zoneinfo            string         `json:"zoneinfo"`
	Birthdate           string         `json:"birthdate"`
	Blocked             bool           `json:"blocked"`
	Metadata            map[string]any `json:"metadata"`
	CreatedAt           time.Time      `json:"created_at"`
	UpdatedAt           time.Time      `json:"updated_at"`
	LastLoginAt         *time.Time     `json:"last_login_at"`
	LoginCount          int            `json:"login_count"`
}

// ManagedSession is an active sign-in session; SID is the sid claim of its tokens.
type ManagedSession struct {
	SID        string    `json:"sid"`
	UserID     string    `json:"user_id"`
	AuthTime   time.Time `json:"auth_time"`
	AMR        []string  `json:"amr"`
	IP         string    `json:"ip"`
	UserAgent  string    `json:"user_agent"`
	CreatedAt  time.Time `json:"created_at"`
	LastSeenAt time.Time `json:"last_seen_at"`
	ExpiresAt  time.Time `json:"expires_at"`
}

// ManagedIdentity is a linked sign-in of a user (social:google, enterprise:<id>, adapter…).
type ManagedIdentity struct {
	Connection string         `json:"connection"`
	Subject    string         `json:"subject"`
	Profile    map[string]any `json:"profile"`
	CreatedAt  time.Time      `json:"created_at"`
}

// MFAState is a user's two-factor state.
type MFAState struct {
	Enabled           bool       `json:"enabled"`
	EnabledAt         *time.Time `json:"enabled_at,omitempty"`
	RecoveryCodesLeft *int       `json:"recovery_codes_left,omitempty"`
}

// UserDetail is what GetUser returns: the user with their identities, active sessions
// and two-factor state.
type UserDetail struct {
	User        ManagedUser       `json:"user"`
	Identities  []ManagedIdentity `json:"identities"`
	Sessions    []ManagedSession  `json:"sessions"`
	HasPassword bool              `json:"has_password"`
	MFA         MFAState          `json:"mfa"`
}

// UserList is a page of users. Pass NextCursor back as the cursor for the next page;
// it is empty on the last page.
type UserList struct {
	Users      []ManagedUser `json:"users"`
	NextCursor string        `json:"next_cursor"`
	Total      int           `json:"total"`
}

// NewUser is a user to create. At least one of Email, PhoneNumber or Username is required.
type NewUser struct {
	Email               string `json:"email,omitempty"`
	EmailVerified       bool   `json:"email_verified,omitempty"`
	PhoneNumber         string `json:"phone_number,omitempty"` // E.164, e.g. +447700900123
	PhoneNumberVerified bool   `json:"phone_number_verified,omitempty"`
	Username            string `json:"username,omitempty"`
	Name                string `json:"name,omitempty"`
	GivenName           string `json:"given_name,omitempty"`
	FamilyName          string `json:"family_name,omitempty"`
	Picture             string `json:"picture,omitempty"`
	Locale              string `json:"locale,omitempty"`
	Zoneinfo            string `json:"zoneinfo,omitempty"`
	Birthdate           string `json:"birthdate,omitempty"` // YYYY-MM-DD
	Blocked             bool   `json:"blocked,omitempty"`
	// Metadata is stored on the user; custom profile fields live in metadata.fields.
	Metadata map[string]any `json:"metadata,omitempty"`
	// Password is a plain password (hashed with argon2id), or give PasswordHash.
	Password string `json:"password,omitempty"`
	// PasswordHash is an existing bcrypt, argon2, PBKDF2 or Firebase scrypt hash.
	PasswordHash string `json:"password_hash,omitempty"`
}

// UserChanges are the fields UpdateUser changes, with the API's names ("name",
// "phone_number", "email_verified", "metadata", "blocked", "password"…). A nil value
// clears a field. Metadata is replaced as a whole: read, merge, then send.
type UserChanges map[string]any

// ImportIdentity is a linked sign-in carried over by an import.
type ImportIdentity struct {
	Connection string `json:"connection"` // e.g. social:google
	Subject    string `json:"subject"`
}

// ImportUser is one record for ImportUsers: the fields of NewUser plus what an import
// may carry over.
type ImportUser struct {
	// ID keeps the id from your old system (letters, digits and | _ . : @ + -, max 128).
	ID string `json:"id,omitempty"`
	NewUser
	Identities  []ImportIdentity `json:"identities,omitempty"`
	CreatedAt   *time.Time       `json:"created_at,omitempty"`
	LastLoginAt *time.Time       `json:"last_login_at,omitempty"`
}

// ImportOptions are the options of ImportUsers.
type ImportOptions struct {
	// OnConflict is "skip" (the default) or "update" when a user already exists.
	OnConflict string
	// Source labels the import in the activity log.
	Source string
}

// ImportResult is the outcome of one import record, in the order given.
type ImportResult struct {
	Index int  `json:"index"`
	OK    bool `json:"ok"`
	// Status is "created", "updated", "skipped" or "failed".
	Status  string `json:"status"`
	ID      string `json:"id,omitempty"`
	Reason  string `json:"reason,omitempty"`
	Error   string `json:"error,omitempty"`
	Details any    `json:"details,omitempty"`
}

// ListUsersOptions page and search the user list.
type ListUsersOptions struct {
	// Query matches email, username, phone number and name (substring) or an exact id.
	Query string
	// Cursor is the NextCursor of the previous page.
	Cursor string
	// Limit is 1 to 200 (default 50).
	Limit int
}

// LoginLinkOptions are the options of CreateLoginLink.
type LoginLinkOptions struct {
	// ReturnTo must be a registered callback URL of one of your applications, or a path
	// on the login domain.
	ReturnTo string
	// TTL is how long the link works (whole seconds).
	TTL time.Duration
}

// LoginLink is a single-use URL that signs the user in.
type LoginLink struct {
	URL       string    `json:"url"`
	ExpiresAt time.Time `json:"expires_at"`
}

func (m *ManagementClient) request(ctx context.Context, method, path string, body, out any) error {
	scope := scopeUsersWrite
	switch {
	case method == http.MethodGet:
		scope = scopeUsersRead
	case strings.Contains(path, "/sessions"):
		scope = scopeSessionsWrite
	}
	var payload []byte
	if body != nil {
		var err error
		if payload, err = json.Marshal(body); err != nil {
			return invalidOptions("the request body can't be encoded as JSON: " + err.Error())
		}
	}
	for attempt := 0; ; attempt++ {
		token, err := m.tokens[scope].Token(ctx)
		if err != nil {
			return err
		}
		header := http.Header{"Authorization": {"Bearer " + token}, "Accept": {"application/json"}}
		if payload != nil {
			header.Set("Content-Type", "application/json")
		}
		res, err := send(ctx, m.http, method, m.issuer+"/api/v1"+path, header, bytesOrNil(payload), "request_failed")
		if err != nil {
			return err
		}
		// A cached token can stop working (a scope removed, the secret rotated): get a
		// new one and try once more.
		if res.status == http.StatusUnauthorized && attempt == 0 {
			m.tokens[scope].Invalidate()
			continue
		}
		if !res.ok() {
			return oauthError(res, "request_failed")
		}
		if out == nil || res.status == http.StatusNoContent || len(bytes.TrimSpace(res.body)) == 0 {
			return nil
		}
		if err := json.Unmarshal(res.body, out); err != nil {
			return &Error{Code: "request_failed", Description: "the response is not the expected JSON", Status: res.status, cause: err}
		}
		return nil
	}
}

func bytesOrNil(b []byte) []byte {
	if len(b) == 0 {
		return nil
	}
	return b
}

func usersPath(id string, rest string) string {
	return "/users/" + encodeURIComponent(id) + rest
}

// ListUsers returns a page of users, newest first.
func (m *ManagementClient) ListUsers(ctx context.Context, opts ListUsersOptions) (*UserList, error) {
	q := url.Values{}
	if opts.Query != "" {
		q.Set("q", opts.Query)
	}
	if opts.Cursor != "" {
		q.Set("cursor", opts.Cursor)
	}
	if opts.Limit > 0 {
		q.Set("limit", strconv.Itoa(opts.Limit))
	}
	path := "/users"
	if len(q) > 0 {
		path += "?" + q.Encode()
	}
	var out UserList
	if err := m.request(ctx, http.MethodGet, path, nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// GetUser returns a user with their identities, active sessions and two-factor state.
// An unknown id fails with not_found (404): test with errors.Is(err, nine.ErrNotFound).
func (m *ManagementClient) GetUser(ctx context.Context, id string) (*UserDetail, error) {
	var out UserDetail
	if err := m.request(ctx, http.MethodGet, usersPath(id, ""), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// FindUser looks a user up by field "email", "phone_number" (E.164) or "username".
// Emails and usernames match case-insensitively. No match fails with not_found (404).
func (m *ManagementClient) FindUser(ctx context.Context, field, value string) (*ManagedUser, error) {
	switch field {
	case "email", "phone_number", "username":
	default:
		return nil, invalidOptions(`FindUser field must be "email", "phone_number" or "username"`)
	}
	var out struct {
		User ManagedUser `json:"user"`
	}
	if err := m.request(ctx, http.MethodGet, "/users/lookup?"+url.Values{field: {value}}.Encode(), nil, &out); err != nil {
		return nil, err
	}
	return &out.User, nil
}

// FindUserByEmail is FindUser(ctx, "email", email).
func (m *ManagementClient) FindUserByEmail(ctx context.Context, email string) (*ManagedUser, error) {
	return m.FindUser(ctx, "email", email)
}

// CreateUser creates a user. A taken email, phone number or username fails with
// identifier_taken (409); bad fields with invalid_user (400, with Details).
func (m *ManagementClient) CreateUser(ctx context.Context, user NewUser) (*ManagedUser, error) {
	var out struct {
		User ManagedUser `json:"user"`
	}
	if err := m.request(ctx, http.MethodPost, "/users", user, &out); err != nil {
		return nil, err
	}
	return &out.User, nil
}

// UpdateUser changes only the fields given and returns the updated user.
func (m *ManagementClient) UpdateUser(ctx context.Context, id string, changes UserChanges) (*ManagedUser, error) {
	if changes == nil {
		changes = UserChanges{}
	}
	var out struct {
		User ManagedUser `json:"user"`
	}
	if err := m.request(ctx, http.MethodPatch, usersPath(id, ""), changes, &out); err != nil {
		return nil, err
	}
	return &out.User, nil
}

// DeleteUser deletes a user.
func (m *ManagementClient) DeleteUser(ctx context.Context, id string) error {
	return m.request(ctx, http.MethodDelete, usersPath(id, ""), nil, nil)
}

// BlockUser blocks a user: their sessions end and their tokens stop working.
func (m *ManagementClient) BlockUser(ctx context.Context, id string) (*ManagedUser, error) {
	return m.UpdateUser(ctx, id, UserChanges{"blocked": true})
}

// UnblockUser lets a blocked user sign in again.
func (m *ManagementClient) UnblockUser(ctx context.Context, id string) (*ManagedUser, error) {
	return m.UpdateUser(ctx, id, UserChanges{"blocked": false})
}

// ImportUsers imports up to 500 users per call (50 with plain-text passwords). Records
// may keep their old id and carry password hashes, social identities and original
// dates. Results are per record, in order; one bad record doesn't stop the others.
func (m *ManagementClient) ImportUsers(ctx context.Context, users []ImportUser, opts ImportOptions) ([]ImportResult, error) {
	body := map[string]any{"users": users}
	if opts.OnConflict != "" {
		body["on_conflict"] = opts.OnConflict
	}
	if opts.Source != "" {
		body["source"] = opts.Source
	}
	var out struct {
		Results []ImportResult `json:"results"`
	}
	if err := m.request(ctx, http.MethodPost, "/users/import", body, &out); err != nil {
		return nil, err
	}
	return out.Results, nil
}

// CreateLoginLink creates a single-use URL that signs the user in (magic links, handing
// a signed-in user over from your app). Two-factor authentication still applies.
func (m *ManagementClient) CreateLoginLink(ctx context.Context, id string, opts LoginLinkOptions) (*LoginLink, error) {
	body := map[string]any{}
	if opts.ReturnTo != "" {
		body["return_to"] = opts.ReturnTo
	}
	if opts.TTL > 0 {
		body["ttl_seconds"] = int(opts.TTL / time.Second)
	}
	var out LoginLink
	if err := m.request(ctx, http.MethodPost, usersPath(id, "/login-link"), body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// ListUserSessions returns the user's active sessions, most recently used first.
func (m *ManagementClient) ListUserSessions(ctx context.Context, id string) ([]ManagedSession, error) {
	var out struct {
		Sessions []ManagedSession `json:"sessions"`
	}
	if err := m.request(ctx, http.MethodGet, usersPath(id, "/sessions"), nil, &out); err != nil {
		return nil, err
	}
	return out.Sessions, nil
}

// RevokeUserSessions signs the user out everywhere and returns how many sessions ended.
func (m *ManagementClient) RevokeUserSessions(ctx context.Context, id string) (int, error) {
	var out struct {
		Revoked int `json:"revoked"`
	}
	if err := m.request(ctx, http.MethodDelete, usersPath(id, "/sessions"), nil, &out); err != nil {
		return 0, err
	}
	return out.Revoked, nil
}

// RevokeSession ends one session (its sid) and every token issued under it.
func (m *ManagementClient) RevokeSession(ctx context.Context, sid string) error {
	return m.request(ctx, http.MethodDelete, "/sessions/"+encodeURIComponent(sid), nil, nil)
}

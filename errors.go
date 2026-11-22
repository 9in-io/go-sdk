package nine

import (
	"errors"
	"net/http"
)

// Error is the error every failure in this package is reported with. Code is an
// OAuth-style error code ("invalid_token", "insufficient_scope", "invalid_grant",
// "insecure_issuer", …), passed through unchanged when it comes from 9in. Status is
// the HTTP status that goes with it (0 when there is none).
//
// Use [errors.As] to read it, or [errors.Is] with one of the Err values below to test
// for a code:
//
//	if errors.Is(err, nine.ErrInsufficientScope) { … }
//
//	var e *nine.Error
//	if errors.As(err, &e) && e.Code == "identifier_taken" { … }
type Error struct {
	// Code is the error code, e.g. "invalid_token".
	Code string
	// Description says what went wrong, for people (never contains a token or secret).
	Description string
	// Status is the HTTP status: the one 9in answered with, or the one to answer with
	// (401 for invalid_token, 403 for insufficient_scope). 0 when there is none.
	Status int
	// Details is the "details" member of a Management API error body, when there is one
	// (for invalid_user, a list of {path, message}).
	Details any

	cause error
}

func (e *Error) Error() string {
	if e.Description != "" && e.Description != e.Code {
		return "nine: " + e.Code + ": " + e.Description
	}
	return "nine: " + e.Code
}

// Unwrap returns the underlying cause (a network error, a context error), if any.
func (e *Error) Unwrap() error { return e.cause }

// Is reports whether target is an *Error with the same Code, so that
// errors.Is(err, nine.ErrInvalidToken) matches every invalid_token error.
func (e *Error) Is(target error) bool {
	var t *Error
	if !errors.As(target, &t) {
		return false
	}
	if t.Code == "not_found" && e.Code == "user_not_found" {
		return true // the Management API's other 404 code
	}
	return t.Code != "" && t.Code == e.Code
}

// Errors to test for with [errors.Is]. They match any *Error with the same Code.
var (
	// ErrInvalidToken: an access token failed verification (401).
	ErrInvalidToken = &Error{Code: "invalid_token", Status: http.StatusUnauthorized}
	// ErrInsufficientScope: the token is valid but lacks a required scope (403).
	ErrInsufficientScope = &Error{Code: "insufficient_scope", Status: http.StatusForbidden}
	// ErrInvalidIDToken: an ID token failed verification.
	ErrInvalidIDToken = &Error{Code: "invalid_id_token", Status: http.StatusUnauthorized}
	// ErrInvalidState: a callback doesn't match a sign-in in progress (another browser, a
	// replay, or it took longer than 15 minutes).
	ErrInvalidState = &Error{Code: "invalid_state", Status: http.StatusBadRequest}
	// ErrInvalidIssuer: the callback's iss parameter isn't your issuer, or the issuer URL
	// is malformed.
	ErrInvalidIssuer = &Error{Code: "invalid_issuer", Status: http.StatusBadRequest}
	// ErrInsecureIssuer: the issuer isn't https (and isn't localhost or loopback).
	ErrInsecureIssuer = &Error{Code: "insecure_issuer"}
	// ErrLoginRequired: there is no session, or it ended.
	ErrLoginRequired = &Error{Code: "login_required", Status: http.StatusUnauthorized}
	// ErrInvalidGrant: 9in refused a code or refresh token (used, expired or revoked).
	ErrInvalidGrant = &Error{Code: "invalid_grant", Status: http.StatusBadRequest}
	// ErrAccessDenied: the user cancelled or declined.
	ErrAccessDenied = &Error{Code: "access_denied", Status: http.StatusBadRequest}
	// ErrInvalidSignature: a webhook or adapter request failed signature verification.
	ErrInvalidSignature = &Error{Code: "invalid_signature", Status: http.StatusUnauthorized}
	// ErrNotFound: the Management API found no such user or session (404; it also
	// matches the API's user_not_found).
	ErrNotFound = &Error{Code: "not_found", Status: http.StatusNotFound}
	// ErrInvalidOptions: a required setting is missing or invalid.
	ErrInvalidOptions = &Error{Code: "invalid_options"}
	// ErrAuthorizationPending: device flow, the user hasn't approved yet.
	ErrAuthorizationPending = &Error{Code: "authorization_pending", Status: http.StatusBadRequest}
	// ErrSlowDown: device flow, polling too fast.
	ErrSlowDown = &Error{Code: "slow_down", Status: http.StatusBadRequest}
	// ErrExpiredToken: device flow, the code expired before the user approved it.
	ErrExpiredToken = &Error{Code: "expired_token", Status: http.StatusBadRequest}

	// ErrInvalidCredentials is what an [Adapter]'s Authenticate returns for an unknown
	// user or a wrong password (9in doesn't tell them apart).
	ErrInvalidCredentials = &Error{Code: "invalid_credentials", Status: http.StatusUnauthorized}
	// ErrUserBlocked is what an [Adapter]'s Authenticate returns for a blocked user.
	ErrUserBlocked = &Error{Code: "blocked", Status: http.StatusForbidden}
)

func newError(code, description string, status int) *Error {
	return &Error{Code: code, Description: description, Status: status}
}

func invalidToken(description string) *Error {
	return newError("invalid_token", description, http.StatusUnauthorized)
}

func invalidIDToken(description string) *Error {
	return newError("invalid_id_token", description, http.StatusUnauthorized)
}

func invalidOptions(description string) *Error {
	return newError("invalid_options", description, 0)
}

// errorCode is the Code of err when it is an *Error, else "".
func errorCode(err error) string {
	var e *Error
	if errors.As(err, &e) {
		return e.Code
	}
	return ""
}

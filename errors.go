package auth

import "errors"

var (
	errInvalidToken       = errors.New("invalid token")
	errTokenExpired       = errors.New("token expired")
	errUserNotExists      = errors.New("user does not exist")
	errPasswordMismatch   = errors.New("password does not match")
	errUserNotFound       = errors.New("user not found")
	errEmailExists        = errors.New("email already exists")
	errInvalidCredentials = errors.New("invalid credentials")
)

package auth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

// Service provides methods for authentication and registration
type Service struct {
	repo        Repository
	jwtSecret   []byte
	tokenExpiry time.Duration
}

// New creates a new authentication service
func New(repo Repository, jwtSecret string, tokenExpiry time.Duration) *Service {
	return &Service{
		repo:        repo,
		jwtSecret:   []byte(jwtSecret),
		tokenExpiry: tokenExpiry,
	}
}

// Register creates a new user
func (s *Service) Register(ctx context.Context, req *RegisterRequest) (*User, error) {
	hashedPassword, err := HashPassword(req.Password)
	if err != nil {
		return nil, fmt.Errorf("hash password: %w", err)
	}

	user := &User{
		Username: req.Username,
		Email:    req.Email,
		Password: hashedPassword,
	}

	if err := s.repo.CreateUser(ctx, user); err != nil {
		return nil, fmt.Errorf("create user: %w", err)
	}

	return user, nil
}

// Login performs user authentication
func (s *Service) Login(ctx context.Context, req *LoginRequest) (*Response, error) {
	user, err := s.repo.GetUserByEmail(ctx, req.Email)
	if err != nil {
		return nil, errInvalidCredentials
	}

	if err := CheckPassword(req.Password, user.Password); err != nil {
		return nil, errInvalidCredentials
	}

	token, err := s.generateToken(user)
	if err != nil {
		return nil, fmt.Errorf("generate token: %w", err)
	}

	return &Response{
		Token: token,
		User:  *user,
	}, nil
}

// generateToken creates a JWT token
func (s *Service) generateToken(user *User) (string, error) {
	claims := jwt.MapClaims{
		"sub":      user.ID.String(),
		"username": user.Username,
		"exp":      time.Now().Add(s.tokenExpiry).Unix(),
		"iat":      time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(s.jwtSecret)
}

// ValidateToken checks the JWT token
func (s *Service) ValidateToken(tokenString string) (jwt.MapClaims, error) {
	token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return s.jwtSecret, nil
	})

	if err != nil {
		return nil, fmt.Errorf("parse token: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		return claims, nil
	}

	return nil, errors.New("invalid token")
}

package auth

import (
	"context"
	"testing"
	"time"

	"github.com/golang-jwt/jwt"
	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

// MockRepository - mock repository for testing
type MockRepository struct {
	mock.Mock
}

func (m *MockRepository) CreateUser(ctx context.Context, user *User) error {
	args := m.Called(ctx, user)
	return args.Error(0)
}

func (m *MockRepository) GetUserByEmail(ctx context.Context, email string) (*User, error) {
	args := m.Called(ctx, email)
	if args.Get(0) == nil {
		return nil, args.Error(1)
	}
	return args.Get(0).(*User), args.Error(1)
}

func TestServiceRegister(t *testing.T) {
	tests := []struct {
		name        string
		req         *RegisterRequest
		mockSetup   func(*MockRepository)
		expected    *User
		expectedErr error
	}{
		{
			name: "successful registration",
			req: &RegisterRequest{
				Username: "testuser",
				Email:    "test@example.com",
				Password: "password123",
			},
			mockSetup: func(mr *MockRepository) {
				mr.On("CreateUser", mock.Anything, mock.AnythingOfType("*auth.User")).
					Return(nil).
					Run(func(args mock.Arguments) {
						user := args.Get(1).(*User)
						user.ID = uuid.MustParse("00000000-0000-0000-0000-000000000001")
					})
			},
			expected: &User{
				ID:       uuid.MustParse("00000000-0000-0000-0000-000000000001"),
				Username: "testuser",
				Email:    "test@example.com",
			},
			expectedErr: nil,
		},
		{
			name: "email already exists",
			req: &RegisterRequest{
				Username: "testuser",
				Email:    "exists@example.com",
				Password: "password123",
			},
			mockSetup: func(mr *MockRepository) {
				mr.On("CreateUser", mock.Anything, mock.AnythingOfType("*auth.User")).
					Return(errEmailExists)
			},
			expected:    nil,
			expectedErr: errEmailExists,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockRepository)
			tt.mockSetup(mockRepo)

			service := New(mockRepo, "secret", time.Hour)
			user, err := service.Register(context.Background(), tt.req)

			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, tt.expectedErr)
				assert.Nil(t, user)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected.ID, user.ID)
				assert.Equal(t, tt.expected.Username, user.Username)
				assert.Equal(t, tt.expected.Email, user.Email)
				assert.NotEmpty(t, user.Password)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestServiceLogin(t *testing.T) {
	hashedPassword, _ := HashPassword("password123")

	tests := []struct {
		name        string
		req         *LoginRequest
		mockSetup   func(*MockRepository)
		expected    *Response
		expectedErr error
	}{
		{
			name: "successful login",
			req: &LoginRequest{
				Email:    "test@example.com",
				Password: "password123",
			},
			mockSetup: func(mr *MockRepository) {
				mr.On("GetUserByEmail", mock.Anything, "test@example.com").
					Return(&User{
						ID:       uuid.MustParse("00000000-0000-0000-0000-000000000001"),
						Username: "testuser",
						Email:    "test@example.com",
						Password: hashedPassword,
					}, nil)
			},
			expected: &Response{
				User: User{
					ID:       uuid.MustParse("00000000-0000-0000-0000-000000000001"),
					Username: "testuser",
					Email:    "test@example.com",
					Password: hashedPassword,
				},
			},
			expectedErr: nil,
		},
		{
			name: "user not found",
			req: &LoginRequest{
				Email:    "notfound@example.com",
				Password: "password123",
			},
			mockSetup: func(mr *MockRepository) {
				mr.On("GetUserByEmail", mock.Anything, "notfound@example.com").
					Return(nil, errUserNotFound)
			},
			expected:    nil,
			expectedErr: errInvalidCredentials,
		},
		{
			name: "wrong password",
			req: &LoginRequest{
				Email:    "test@example.com",
				Password: "wrongpassword",
			},
			mockSetup: func(mr *MockRepository) {
				mr.On("GetUserByEmail", mock.Anything, "test@example.com").
					Return(&User{
						ID:       uuid.MustParse("00000000-0000-0000-0000-000000000001"),
						Username: "testuser",
						Email:    "test@example.com",
						Password: hashedPassword,
					}, nil)
			},
			expected:    nil,
			expectedErr: errInvalidCredentials,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mockRepo := new(MockRepository)
			tt.mockSetup(mockRepo)

			service := New(mockRepo, "secret", time.Hour)
			resp, err := service.Login(context.Background(), tt.req)

			if tt.expectedErr != nil {
				assert.ErrorIs(t, err, tt.expectedErr)
				assert.Nil(t, resp)
			} else {
				assert.NoError(t, err)
				assert.Equal(t, tt.expected.User.ID, resp.User.ID)
				assert.Equal(t, tt.expected.User.Username, resp.User.Username)
				assert.Equal(t, tt.expected.User.Email, resp.User.Email)
				assert.NotEmpty(t, resp.Token)
			}

			mockRepo.AssertExpectations(t)
		})
	}
}

func TestServiceValidateToken(t *testing.T) {
	service := New(nil, "secret", time.Hour)

	t.Run("valid token", func(t *testing.T) {
		user := &User{
			ID:       uuid.MustParse("00000000-0000-0000-0000-000000000001"),
			Username: "testuser",
		}
		token, err := service.generateToken(user)
		assert.NoError(t, err)

		claims, err := service.ValidateToken(token)
		assert.NoError(t, err)
		assert.Equal(t, user.ID.String(), claims["sub"])
		assert.Equal(t, user.Username, claims["username"])
	})

	t.Run("invalid token", func(t *testing.T) {
		claims, err := service.ValidateToken("invalid.token.string")
		assert.Error(t, err)
		assert.Nil(t, claims)
	})

	t.Run("wrong signing method", func(t *testing.T) {
		// Creating a token with an incorrect signature method
		token := jwt.NewWithClaims(jwt.SigningMethodRS256, jwt.MapClaims{
			"sub": "123",
		})
		tokenString, _ := token.SignedString([]byte("key"))

		claims, err := service.ValidateToken(tokenString)
		assert.Error(t, err)
		assert.Nil(t, claims)
	})
}

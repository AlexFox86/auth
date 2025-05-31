package auth

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/mock"
)

func TestHandlerRegister(t *testing.T) {
	mockRepo := new(MockRepository)
	service := New(mockRepo, "secret", time.Hour)
	handler := NewHandler(service)

	tests := []struct {
		name           string
		requestBody    interface{}
		mockSetup      func()
		expectedStatus int
	}{
		{
			name: "successful registration",
			requestBody: RegisterRequest{
				Username: "testuser",
				Email:    "test@example.com",
				Password: "password123",
			},
			mockSetup: func() {
				mockRepo.On("CreateUser", mock.Anything, mock.AnythingOfType("*auth.User")).
					Return(nil).Once()
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "invalid request body",
			requestBody: map[string]interface{}{
				"username": 123, // incorrect type
				"email":    "test@example.com",
				"password": "password123",
			},
			mockSetup:      func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "validation error",
			requestBody: RegisterRequest{
				Username: "te", // the name is too short
				Email:    "test@example.com",
				Password: "password123",
			},
			mockSetup:      func() {},
			expectedStatus: http.StatusBadRequest,
		},
		{
			name: "email already exists",
			requestBody: RegisterRequest{
				Username: "testuser",
				Email:    "exists@example.com",
				Password: "password123",
			},
			mockSetup: func() {
				mockRepo.On("CreateUser", mock.Anything, mock.AnythingOfType("*auth.User")).
					Return(errEmailExists).Once()
			},
			expectedStatus: http.StatusConflict,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/register", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.Register(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			mockRepo.AssertExpectations(t)
		})
	}
}

func TestHandlerLogin(t *testing.T) {
	mockRepo := new(MockRepository)
	service := New(mockRepo, "secret", time.Hour)
	handler := NewHandler(service)

	hashedPassword, _ := HashPassword("password123")

	tests := []struct {
		name           string
		requestBody    interface{}
		mockSetup      func()
		expectedStatus int
	}{
		{
			name: "successful login",
			requestBody: LoginRequest{
				Email:    "test@example.com",
				Password: "password123",
			},
			mockSetup: func() {
				mockRepo.On("GetUserByEmail", mock.Anything, "test@example.com").
					Return(&User{
						ID:       uuid.New(),
						Username: "testuser",
						Email:    "test@example.com",
						Password: hashedPassword,
					}, nil)
			},
			expectedStatus: http.StatusOK,
		},
		{
			name: "invalid credentials",
			requestBody: LoginRequest{
				Email:    "test@example.com",
				Password: "wrongpassword",
			},
			mockSetup: func() {
				mockRepo.On("GetUserByEmail", mock.Anything, "test@example.com").
					Return(&User{
						ID:       uuid.New(),
						Username: "testuser",
						Email:    "test@example.com",
						Password: hashedPassword,
					}, nil)
			},
			expectedStatus: http.StatusUnauthorized,
		},
		{
			name: "user not found",
			requestBody: LoginRequest{
				Email:    "notfound@example.com",
				Password: "password123",
			},
			mockSetup: func() {
				mockRepo.On("GetUserByEmail", mock.Anything, "notfound@example.com").
					Return(nil, errUserNotFound)
			},
			expectedStatus: http.StatusUnauthorized,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tt.mockSetup()

			body, _ := json.Marshal(tt.requestBody)
			req := httptest.NewRequest("POST", "/login", bytes.NewReader(body))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()

			handler.Login(w, req)

			assert.Equal(t, tt.expectedStatus, w.Code)
			mockRepo.AssertExpectations(t)
		})
	}
}

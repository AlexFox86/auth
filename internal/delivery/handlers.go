package delivery

import (
	"encoding/json"
	"errors"
	"net/http"

	"github.com/go-playground/validator/v10"

	"github.com/AlexFox86/auth/internal/models"
	"github.com/AlexFox86/auth/internal/service"
)

// Handler provides HTTP handlers for authentication
type Handler struct {
	service  *service.Service
	validate *validator.Validate
}

// NewHandler creates a new Handler
func NewHandler(service *service.Service) *Handler {
	return &Handler{
		service:  service,
		validate: validator.New(),
	}
}

// Register processes the registration request
func (h *Handler) Register(w http.ResponseWriter, r *http.Request) {
	var req models.RegisterRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.validate.Struct(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	user, err := h.service.Register(r.Context(), &req)
	if err != nil {
		if errors.Is(err, models.ErrEmailExists) {
			http.Error(w, "email already exists", http.StatusConflict)
			return
		}
		http.Error(w, "registration failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(user)
}

// Login processes the login request
func (h *Handler) Login(w http.ResponseWriter, r *http.Request) {
	var req models.LoginRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid request body", http.StatusBadRequest)
		return
	}

	if err := h.validate.Struct(req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	resp, err := h.service.Login(r.Context(), &req)
	if err != nil {
		if errors.Is(err, models.ErrInvalidCredentials) {
			http.Error(w, "invalid credentials", http.StatusUnauthorized)
			return
		}
		http.Error(w, "login failed", http.StatusInternalServerError)
		return
	}

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(resp)
}

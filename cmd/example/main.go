package main

import (
	"fmt"
	"log"
	"net/http"
	"os"
	"time"

	"github.com/AlexFox86/auth"
	"github.com/jmoiron/sqlx"
	_ "github.com/lib/pq"
)

func main() {
	dsn := fmt.Sprintf("host=%s port=%s user=%s password=%s dbname=%s sslmode=%s",
		os.Getenv("DB_HOST"),
		os.Getenv("DB_PORT"),
		os.Getenv("DB_USER"),
		os.Getenv("DB_PASSWORD"),
		os.Getenv("DB_NAME"),
		os.Getenv("DB_SSLMODE"),
	)

	db, err := sqlx.Connect("postgres", dsn)
	if err != nil {
		panic(err)
	}
	defer db.Close()

	repo := auth.NewPgRepository(db)
	service := auth.New(repo, "secret", time.Hour)
	handler := auth.NewHandler(service)

	http.HandleFunc("POST /register", handler.Register)
	http.HandleFunc("POST /login", handler.Login)

	protected := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("Protected content"))
	})
	http.Handle("/protected", handler.AuthMiddleware(protected))

	fmt.Println("Server is running on port 8080")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

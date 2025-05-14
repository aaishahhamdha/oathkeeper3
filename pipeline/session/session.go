package pipeline

import (
	"encoding/json"
	"log"
	"net/http"
	"os"
	"sync"
	"time"
)

type Session struct {
	Sub         string
	UserName    string
	AccessToken string
	ExpiresAt   time.Time
}

var (
	sessions   = make(map[string]Session) // map[accessToken]Session
	sessionMux = &sync.RWMutex{}
)

// SetSession creates or updates a session
func SetSession(s Session) {
	sessionMux.Lock()
	defer sessionMux.Unlock()
	sessions[s.AccessToken] = s
}

// GetSession retrieves a session if it exists and is valid
func GetSession(accessToken string) (Session, bool) {
	sessionMux.RLock()
	defer sessionMux.RUnlock()

	session, exists := sessions[accessToken]
	if !exists || time.Now().After(session.ExpiresAt) {
		return Session{}, false
	}
	return session, true
}

// DeleteSession removes a session (logout)
func DeleteSession(accessToken string) {
	sessionMux.Lock()
	defer sessionMux.Unlock()
	delete(sessions, accessToken)
}

// SessionMiddleware checks for valid session and adds it to the request context
func SessionMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, `{"error":"missing access token"}`, http.StatusUnauthorized)
			return
		}

		session, valid := GetSession(token)
		if !valid {
			http.Error(w, `{"error":"invalid or expired session"}`, http.StatusUnauthorized)
			return
		}
		if session.ExpiresAt.Before(time.Now()) {
			http.Error(w, `{"error":"session expired"}`, http.StatusUnauthorized)
			return
		}

		// You can add the session to the request context here if needed
		// ctx := context.WithValue(r.Context(), "session", session)
		// next.ServeHTTP(w, r.WithContext(ctx))

		next.ServeHTTP(w, r)
	})
}

// Example handler that requires session
func protectedHandler(w http.ResponseWriter, r *http.Request) {
	token := r.Header.Get("Authorization")
	session, _ := GetSession(token) // We already validated in middleware

	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(map[string]interface{}{
		"user":    session.UserName,
		"message": "You're accessing protected content",
	})
}

func main() {
	// Example usage:
	// 1. After login, create and set a session:
	// newSession := Session{
	//     Sub:         "user123",
	//     UserName:    "john_doe",
	//     AccessToken: "generated_token_here",
	//     ExpiresAt:   time.Now().Add(24 * time.Hour),
	// }
	// SetSession(newSession)

	// 2. Protect routes with session middleware
	protectedMux := http.NewServeMux()
	protectedMux.HandleFunc("/protected", protectedHandler)

	http.Handle("/protected", SessionMiddleware(protectedMux))

	port := os.Getenv("PORT")
	if port == "" {
		port = "3000"
	}
	log.Printf("Server running on :%s\n", port)
	log.Fatal(http.ListenAndServe(":"+port, nil))
}

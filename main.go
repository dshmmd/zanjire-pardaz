package main

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"html/template"
	"log"
	"math/big"
	mrand "math/rand"
	"net/http"
	"sync"
	"time"
)

var (
	templates = template.Must(template.ParseGlob("templates/*.html"))

	// In-memory stores (for MVP only)
	users    = map[string]string{} // username → password
	sessions = map[string]string{} // sessionID → username
	mu       = sync.Mutex{}
)

func main() {
	mrand.Seed(time.Now().UnixNano())

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("static"))))
	http.HandleFunc("/", homeHandler)
	http.HandleFunc("/signup", signupHandler)
	http.HandleFunc("/login", loginHandler)
	http.HandleFunc("/profile", authOnly(profileHandler))
	http.HandleFunc("/charts", authOnly(chartsHandler))
	http.HandleFunc("/logout", logoutHandler)

	fmt.Println("Starting server on http://localhost:8080 …")
	log.Fatal(http.ListenAndServe(":8080", nil))
}

// --- Handlers ---

func homeHandler(w http.ResponseWriter, r *http.Request) {
	templates.ExecuteTemplate(w, "landing.html", nil)
}

func signupHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		templates.ExecuteTemplate(w, "signup.html", nil)
	case http.MethodPost:
		user := r.FormValue("username")
		pass := r.FormValue("password")
		mu.Lock()
		defer mu.Unlock()
		if user == "" || pass == "" || users[user] != "" {
			http.Error(w, "Username taken or invalid", http.StatusBadRequest)
			return
		}
		users[user] = pass
		http.Redirect(w, r, "/login", http.StatusSeeOther)
	}
}

func loginHandler(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		templates.ExecuteTemplate(w, "login.html", nil)
	case http.MethodPost:
		user := r.FormValue("username")
		pass := r.FormValue("password")
		mu.Lock()
		realPass, exists := users[user]
		mu.Unlock()
		if !exists || realPass != pass {
			http.Error(w, "Invalid credentials", http.StatusUnauthorized)
			return
		}
		sid := newSessionID()
		mu.Lock()
		sessions[sid] = user
		mu.Unlock()
		http.SetCookie(w, &http.Cookie{
			Name:     "session",
			Value:    sid,
			Path:     "/",
			HttpOnly: true,
		})
		http.Redirect(w, r, "/profile", http.StatusSeeOther)
	}
}

func profileHandler(w http.ResponseWriter, r *http.Request) {
	user := r.Context().Value("user").(string)
	templates.ExecuteTemplate(w, "profile.html", map[string]string{"Username": user})
}

func chartsHandler(w http.ResponseWriter, r *http.Request) {
	// generate some random data
	labels := []string{}
	values := []int{}
	for i := 1; i <= 7; i++ {
		labels = append(labels, fmt.Sprintf("Day %d", i))
		values = append(values, mrand.Intn(100))
	}
	labelsJSON, _ := json.Marshal(labels)
	valuesJSON, _ := json.Marshal(values)

	templates.ExecuteTemplate(w, "charts.html", map[string]interface{}{
		"Labels": string(labelsJSON),
		"Values": string(valuesJSON),
	})
}

func logoutHandler(w http.ResponseWriter, r *http.Request) {
	cookie, err := r.Cookie("session")
	if err == nil {
		mu.Lock()
		delete(sessions, cookie.Value)
		mu.Unlock()
		cookie.Value = ""
		cookie.MaxAge = -1
		http.SetCookie(w, cookie)
	}
	http.Redirect(w, r, "/", http.StatusSeeOther)
}

// --- Helpers & Middleware ---

func authOnly(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("session")
		if err != nil {
			fmt.Println("can not find session")
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		mu.Lock()
		user, ok := sessions[cookie.Value]
		mu.Unlock()
		if !ok {
			http.Redirect(w, r, "/login", http.StatusSeeOther)
			return
		}
		ctx := r.Context()
		ctx = context.WithValue(ctx, "user", user)
		next(w, r.WithContext(ctx))
	}
}

func newSessionID() string {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err == nil {
		return fmt.Sprintf("%x", b)
	}
	// fallback to random number
	n, _ := rand.Int(rand.Reader, big.NewInt(1<<62))
	return fmt.Sprintf("%x", n)
}

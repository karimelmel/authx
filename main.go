package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gorilla/mux"
	"github.com/gorilla/sessions"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/microsoft"
)

type App struct {
	OAuth2Config oauth2.Config
	Store        *sessions.CookieStore
	Verifier     *oidc.IDTokenVerifier
}

type User struct {
	ID       string   `json:"sub"`
	Email    string   `json:"email"`
	UPN      string   `json:"preferred_username"` // Changed from "upn" to "preferred_username"
	Name     string   `json:"name"`
	TenantID string   `json:"tid"`
	Groups   []string `json:"groups,omitempty"`
}

func main() {
	// Load .env file for local development
	if err := loadEnv(".env"); err != nil {
		log.Printf("Warning: Could not load .env file: %v", err)
	}

	// Load configuration from environment
	clientID := os.Getenv("OIDC_CLIENT_ID")
	clientSecret := os.Getenv("OIDC_CLIENT_SECRET")
	redirectURL := os.Getenv("OIDC_REDIRECT_URL")
	tenantID := os.Getenv("ENTRA_TENANT_ID")

	if clientID == "" || clientSecret == "" || redirectURL == "" {
		log.Fatal("Missing required environment variables")
	}

	// Initialize the app
	app, err := NewApp(clientID, clientSecret, redirectURL, tenantID)
	if err != nil {
		log.Fatal("Failed to initialize app:", err)
	}

	// Set up routes
	r := mux.NewRouter()
	r.HandleFunc("/", app.HomeHandler).Methods("GET")
	r.HandleFunc("/login", app.LoginHandler).Methods("GET")
	r.HandleFunc("/callback", app.CallbackHandler).Methods("GET")
	r.HandleFunc("/logout", app.LogoutHandler).Methods("GET")
	r.HandleFunc("/protected", app.requireAuth(app.ProtectedHandler)).Methods("GET")

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func NewApp(clientID, clientSecret, redirectURL, tenantID string) (*App, error) {
	ctx := context.Background()

	// Use Microsoft's predefined endpoint for multi-tenant apps
	// This avoids the issuer discovery issues
	var endpoint oauth2.Endpoint
	if tenantID == "common" {
		endpoint = microsoft.AzureADEndpoint("common")
	} else {
		endpoint = microsoft.AzureADEndpoint(tenantID)
	}

	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Endpoint:     endpoint,
		// Fix: Remove invalid 'upn' scope - UPN is included in standard claims with these scopes
		Scopes: []string{"openid", "profile", "email"},
	}

	// Create a verifier that can handle multi-tenant tokens
	// Use the common discovery endpoint for key validation
	keySet := oidc.NewRemoteKeySet(ctx, "https://login.microsoftonline.com/common/discovery/v2.0/keys")

	// For multi-tenant apps, we skip issuer validation because tokens will have
	// tenant-specific issuers like https://login.microsoftonline.com/{tenantid}/v2.0
	verifier := oidc.NewVerifier("https://login.microsoftonline.com/common/v2.0", keySet, &oidc.Config{
		ClientID:        clientID,
		SkipIssuerCheck: tenantID == "common", // Skip for multi-tenant
	})

	// Generate a secure session key (in production, use a fixed key from env)
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	store := sessions.NewCookieStore(sessionKey)

	return &App{
		OAuth2Config: oauth2Config,
		Store:        store,
		Verifier:     verifier,
	}, nil
}

func (app *App) HomeHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := app.Store.Get(r, "session")
	user, authenticated := session.Values["user"].(User)

	if authenticated {
		fmt.Fprintf(w, `
		<h1>Welcome, %s!</h1>
		<p>Email: %s</p>
		<p>UPN: %s</p>
		<p>Tenant ID: %s</p>
		<p><a href='/protected'>Protected Area</a> | <a href='/logout'>Logout</a></p>
		`, user.Name, user.Email, user.UPN, user.TenantID)
	} else {
		fmt.Fprintf(w, `
		<h1>Karim OIDC SaaS Test</h1>
		<p><a href='/login'>Login with Entra ID</a></p>
		`)
	}
}

func (app *App) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// Generate state parameter for CSRF protection
	state, err := generateRandomString(16)
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	// Store state in session
	session, _ := app.Store.Get(r, "session")
	session.Values["state"] = state
	session.Save(r, w)

	// Redirect to Entra ID
	authURL := app.OAuth2Config.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

func (app *App) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := app.Store.Get(r, "session")

	// Verify state parameter
	savedState, ok := session.Values["state"].(string)
	if !ok || savedState != r.URL.Query().Get("state") {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Exchange code for token
	oauth2Token, err := app.OAuth2Config.Exchange(r.Context(), r.URL.Query().Get("code"))
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// DEBUG: Log the full OAuth2 token
	log.Printf("=== OAuth2 Token ===")
	log.Printf("Access Token (first 50 chars): %s...", oauth2Token.AccessToken[:min(50, len(oauth2Token.AccessToken))])
	log.Printf("Token Type: %s", oauth2Token.TokenType)
	log.Printf("Expires: %v", oauth2Token.Expiry)
	// Don't try to log all extra claims - just log that we have an ID token
	if idTokenRaw := oauth2Token.Extra("id_token"); idTokenRaw != nil {
		log.Printf("Has ID token: Yes")
	} else {
		log.Printf("Has ID token: No")
	}

	// Extract ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token in response", http.StatusInternalServerError)
		return
	}

	// DEBUG: Log the raw ID token (JWT)
	log.Printf("=== Raw ID Token (JWT) ===")
	log.Printf("Length: %d characters", len(rawIDToken))
	log.Printf("Raw JWT (first 100 chars): %s...", rawIDToken[:min(100, len(rawIDToken))])

	// Parse JWT to see header and payload (before verification)
	parts := strings.Split(rawIDToken, ".")
	if len(parts) >= 2 {
		// Decode header
		if headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0]); err == nil {
			log.Printf("=== JWT Header ===")
			log.Printf("%s", string(headerBytes))
		}

		// Decode payload (claims)
		if payloadBytes, err := base64.RawURLEncoding.DecodeString(parts[1]); err == nil {
			log.Printf("=== JWT Payload (All Claims) ===")

			// Pretty print JSON
			var claims map[string]interface{}
			if err := json.Unmarshal(payloadBytes, &claims); err == nil {
				prettyJSON, _ := json.MarshalIndent(claims, "", "  ")
				log.Printf("%s", string(prettyJSON))
			} else {
				log.Printf("Raw payload: %s", string(payloadBytes))
			}
		}
	}

	// Verify ID token
	idToken, err := app.Verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		log.Printf("=== Token Verification Error ===")
		log.Printf("Error: %v", err)
		http.Error(w, "Failed to verify ID token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// DEBUG: Log verified token info
	log.Printf("=== Verified ID Token Info ===")
	log.Printf("Issuer: %s", idToken.Issuer)
	log.Printf("Audience: %v", idToken.Audience)
	log.Printf("Subject: %s", idToken.Subject)
	log.Printf("Expiry: %v", idToken.Expiry)
	log.Printf("Issued At: %v", idToken.IssuedAt)

	// This is where the mapping happens - the ID token claims are mapped to the User struct
	var user User
	if err := idToken.Claims(&user); err != nil {
		log.Printf("=== Claims Parsing Error ===")
		log.Printf("Error: %v", err)
		http.Error(w, "Failed to parse claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// DEBUG: Log parsed user claims
	log.Printf("=== Parsed User Claims ===")
	userJSON, _ := json.MarshalIndent(user, "", "  ")
	log.Printf("%s", string(userJSON))

	// Try to extract ALL claims into a map for debugging
	var allClaims map[string]interface{}
	if err := idToken.Claims(&allClaims); err == nil {
		log.Printf("=== All Available Claims ===")
		allClaimsJSON, _ := json.MarshalIndent(allClaims, "", "  ")
		log.Printf("%s", string(allClaimsJSON))
	}

	// Save user in session
	session.Values["user"] = user
	delete(session.Values, "state")
	session.Save(r, w)

	log.Printf("=== Authentication Successful ===")
	log.Printf("User %s (UPN: %s) from tenant %s successfully authenticated", user.Email, user.UPN, user.TenantID)

	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

func (app *App) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := app.Store.Get(r, "session")
	session.Options.MaxAge = -1
	session.Save(r, w)

	// Redirect to Entra ID logout (optional)
	logoutURL := fmt.Sprintf("https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri=%s",
		"http://localhost:8080/")
	http.Redirect(w, r, logoutURL, http.StatusTemporaryRedirect)
}

func (app *App) ProtectedHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := app.Store.Get(r, "session")
	user := session.Values["user"].(User)

	userJSON, _ := json.MarshalIndent(user, "", "  ")
	fmt.Fprintf(w, `
	<h1>Protected Content</h1>
	<h2>User Information:</h2>
	<pre>%s</pre>
	<p><a href='/'>Home</a></p>
	`, userJSON)
}

// Middleware to require authentication
func (app *App) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := app.Store.Get(r, "session")
		if _, authenticated := session.Values["user"].(User); !authenticated {
			http.Redirect(w, r, "/login", http.StatusTemporaryRedirect)
			return
		}
		next(w, r)
	}
}

func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

// Helper function for minimum of two integers
func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

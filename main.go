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
	"golang.org/x/oauth2/google"
	"golang.org/x/oauth2/microsoft"
)

// Auth providers
const (
	ProviderMicrosoft = "microsoft"
	ProviderGoogle    = "google"
)

// MultiApp holds configurations for both identity providers
type MultiApp struct {
	MicrosoftApp *ProviderApp
	GoogleApp    *ProviderApp
	Store        *sessions.CookieStore
}

// ProviderApp holds configuration for a specific identity provider
type ProviderApp struct {
	Provider     string
	OAuth2Config oauth2.Config
	Verifier     *oidc.IDTokenVerifier
}

// User represents a unified user model across providers
type User struct {
	ID           string   `json:"sub"`
	Email        string   `json:"email"`
	UPN          string   `json:"preferred_username"` // MS specific
	Name         string   `json:"name"`
	TenantID     string   `json:"tid"` // MS specific
	HD           string   `json:"hd"`  // Google specific (hosted domain)
	Groups       []string `json:"groups,omitempty"`
	AuthProvider string   `json:"-"` // Which provider authenticated this user
}

func main() {
	// Load .env file for local development
	if err := loadEnv(".env"); err != nil {
		log.Printf("Warning: Could not load .env file: %v", err)
	}

	// Load Microsoft configuration
	msClientID := os.Getenv("MS_CLIENT_ID")
	msClientSecret := os.Getenv("MS_CLIENT_SECRET")
	msRedirectURL := os.Getenv("MS_REDIRECT_URL")
	msTenantID := os.Getenv("MS_TENANT_ID")

	// Load Google configuration
	googleClientID := os.Getenv("GOOGLE_CLIENT_ID")
	googleClientSecret := os.Getenv("GOOGLE_CLIENT_SECRET")
	googleRedirectURL := os.Getenv("GOOGLE_REDIRECT_URL")

	// Check for minimum configuration
	if msClientID == "" || msClientSecret == "" || msRedirectURL == "" {
		log.Fatal("Missing required Microsoft environment variables")
	}

	// Initialize the app with available providers
	app, err := NewMultiApp(
		msClientID, msClientSecret, msRedirectURL, msTenantID,
		googleClientID, googleClientSecret, googleRedirectURL,
	)
	if err != nil {
		log.Fatal("Failed to initialize app:", err)
	}

	// Set up routes
	r := mux.NewRouter()

	// Main routes
	r.HandleFunc("/", app.HomeHandler).Methods("GET")
	r.HandleFunc("/login/detect", app.DetectLoginHandler).Methods("POST")
	r.HandleFunc("/protected", app.requireAuth(app.ProtectedHandler)).Methods("GET")

	// Microsoft specific routes
	r.HandleFunc("/login/microsoft", app.HandleMicrosoftLogin).Methods("GET")
	r.HandleFunc("/callback/microsoft", app.HandleMicrosoftCallback).Methods("GET")

	// Google specific routes
	if app.GoogleApp != nil {
		r.HandleFunc("/login/google", app.HandleGoogleLogin).Methods("GET")
		r.HandleFunc("/callback/google", app.HandleGoogleCallback).Methods("GET")
	}

	// Common logout
	r.HandleFunc("/logout", app.LogoutHandler).Methods("GET")

	// For backward compatibility
	r.HandleFunc("/login", app.HandleMicrosoftLogin).Methods("GET")
	r.HandleFunc("/callback", app.HandleMicrosoftCallback).Methods("GET")

	// Start server
	port := os.Getenv("PORT")
	if port == "" {
		port = "8080"
	}

	log.Printf("Server starting on port %s", port)
	log.Fatal(http.ListenAndServe(":"+port, r))
}

func NewMultiApp(
	msClientID, msClientSecret, msRedirectURL, msTenantID,
	googleClientID, googleClientSecret, googleRedirectURL string,
) (*MultiApp, error) {
	ctx := context.Background()

	// Generate a secure session key (in production, use a fixed key from env)
	sessionKey := make([]byte, 32)
	rand.Read(sessionKey)
	store := sessions.NewCookieStore(sessionKey)

	// Initialize Microsoft provider
	msApp, err := InitializeMicrosoftProvider(ctx, msClientID, msClientSecret, msRedirectURL, msTenantID)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize Microsoft provider: %v", err)
	}

	// Initialize Google provider if credentials are provided
	var googleApp *ProviderApp
	if googleClientID != "" && googleClientSecret != "" && googleRedirectURL != "" {
		googleApp, err = InitializeGoogleProvider(ctx, googleClientID, googleClientSecret, googleRedirectURL)
		if err != nil {
			log.Printf("Warning: Failed to initialize Google provider: %v", err)
			// Continue without Google - don't fail the entire app
		}
	}

	return &MultiApp{
		MicrosoftApp: msApp,
		GoogleApp:    googleApp,
		Store:        store,
	}, nil
}

func InitializeMicrosoftProvider(ctx context.Context, clientID, clientSecret, redirectURL, tenantID string) (*ProviderApp, error) {
	// Use Microsoft's predefined endpoint for multi-tenant apps
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
		Scopes:       []string{"openid", "profile", "email"},
	}

	// Create a verifier that can handle multi-tenant tokens
	keySet := oidc.NewRemoteKeySet(ctx, "https://login.microsoftonline.com/common/discovery/v2.0/keys")
	verifier := oidc.NewVerifier("https://login.microsoftonline.com/common/v2.0", keySet, &oidc.Config{
		ClientID:        clientID,
		SkipIssuerCheck: tenantID == "common", // Skip for multi-tenant
	})

	return &ProviderApp{
		Provider:     ProviderMicrosoft,
		OAuth2Config: oauth2Config,
		Verifier:     verifier,
	}, nil
}

func InitializeGoogleProvider(ctx context.Context, clientID, clientSecret, redirectURL string) (*ProviderApp, error) {
	// Configure the Google OAuth2 provider
	oauth2Config := oauth2.Config{
		ClientID:     clientID,
		ClientSecret: clientSecret,
		RedirectURL:  redirectURL,
		Scopes:       []string{"openid", "profile", "email"},
		Endpoint:     google.Endpoint,
	}

	// Create a provider for verification
	provider, err := oidc.NewProvider(ctx, "https://accounts.google.com")
	if err != nil {
		return nil, fmt.Errorf("failed to create Google OIDC provider: %v", err)
	}

	// Create a verifier for Google tokens
	verifier := provider.Verifier(&oidc.Config{
		ClientID: clientID,
	})

	return &ProviderApp{
		Provider:     ProviderGoogle,
		OAuth2Config: oauth2Config,
		Verifier:     verifier,
	}, nil
}

// HomeHandler displays the home page with login options
func (app *MultiApp) HomeHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := app.Store.Get(r, "session")
	user, authenticated := session.Values["user"].(User)

	if authenticated {
		// Display user info
		var providerInfo string
		var extraInfo string

		if user.AuthProvider == ProviderMicrosoft {
			providerInfo = "Microsoft Entra ID"
			extraInfo = fmt.Sprintf("<p>UPN: %s</p><p>Tenant ID: %s</p>", user.UPN, user.TenantID)
		} else if user.AuthProvider == ProviderGoogle {
			providerInfo = "Google Workspace"
			if user.HD != "" {
				extraInfo = fmt.Sprintf("<p>Organization Domain: %s</p>", user.HD)
			} else {
				extraInfo = "<p>Personal Google Account</p>"
			}
		}

		fmt.Fprintf(w, `
		<h1>Welcome, %s!</h1>
		<p>Email: %s</p>
		<p>Auth Provider: %s</p>
		%s
		<p><a href='/protected'>Protected Area</a> | <a href='/logout'>Logout</a></p>
		`, user.Name, user.Email, providerInfo, extraInfo)
	} else {
		// Show login options
		googleOption := ""
		if app.GoogleApp != nil {
			googleOption = `<p><a href='/login/google'>Login with Google</a></p>`
		}

		fmt.Fprintf(w, `
		<h1>Multi-Provider SaaS Demo</h1>
		
		<h2>Sign in with your work account</h2>
		<form action="/login/detect" method="post">
			<input type="email" name="email" placeholder="Your work email" required>
			<button type="submit">Continue</button>
		</form>
		
		<h3>Or choose your provider</h3>
		<p><a href='/login/microsoft'>Login with Microsoft</a></p>
		%s
		`, googleOption)
	}
}

// DetectLoginHandler determines which identity provider to use based on email domain
func (app *MultiApp) DetectLoginHandler(w http.ResponseWriter, r *http.Request) {
	email := r.FormValue("email")
	if email == "" {
		http.Error(w, "Email is required", http.StatusBadRequest)
		return
	}

	parts := strings.Split(email, "@")
	if len(parts) != 2 {
		http.Error(w, "Invalid email format", http.StatusBadRequest)
		return
	}

	domain := parts[1]
	log.Printf("Detecting provider for domain: %s", domain)

	// Simple heuristic - in production you would have a domain-to-provider mapping
	if strings.Contains(domain, "gmail") ||
		strings.Contains(domain, "googlemail") ||
		strings.Contains(domain, "google") {
		if app.GoogleApp != nil {
			http.Redirect(w, r, "/login/google", http.StatusFound)
			return
		}
	}

	// Default to Microsoft
	http.Redirect(w, r, "/login/microsoft", http.StatusFound)
}

// HandleMicrosoftLogin initiates Microsoft login
func (app *MultiApp) HandleMicrosoftLogin(w http.ResponseWriter, r *http.Request) {
	state, err := generateRandomString(16)
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	session, _ := app.Store.Get(r, "session")
	session.Values["state"] = state
	session.Values["auth_provider"] = ProviderMicrosoft
	session.Save(r, w)

	authURL := app.MicrosoftApp.OAuth2Config.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// HandleGoogleLogin initiates Google login
func (app *MultiApp) HandleGoogleLogin(w http.ResponseWriter, r *http.Request) {
	if app.GoogleApp == nil {
		http.Error(w, "Google authentication not configured", http.StatusNotImplemented)
		return
	}

	state, err := generateRandomString(16)
	if err != nil {
		http.Error(w, "Failed to generate state", http.StatusInternalServerError)
		return
	}

	session, _ := app.Store.Get(r, "session")
	session.Values["state"] = state
	session.Values["auth_provider"] = ProviderGoogle
	session.Save(r, w)

	// For Google Workspace, you can restrict to specific domains with hd parameter
	// For example: oauth2.SetAuthURLParam("hd", "example.com")
	authURL := app.GoogleApp.OAuth2Config.AuthCodeURL(state)
	http.Redirect(w, r, authURL, http.StatusTemporaryRedirect)
}

// HandleMicrosoftCallback processes Microsoft login callback
func (app *MultiApp) HandleMicrosoftCallback(w http.ResponseWriter, r *http.Request) {
	session, _ := app.Store.Get(r, "session")

	// Verify state parameter
	savedState, ok := session.Values["state"].(string)
	if !ok || savedState != r.URL.Query().Get("state") {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Verify this is the expected provider
	authProvider, _ := session.Values["auth_provider"].(string)
	if authProvider != ProviderMicrosoft {
		http.Error(w, "Provider mismatch", http.StatusBadRequest)
		return
	}

	// Process auth code
	code := r.URL.Query().Get("code")
	oauth2Token, err := app.MicrosoftApp.OAuth2Config.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Log token info (debug)
	logTokenInfo(oauth2Token, "Microsoft")

	// Extract and verify ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token in response", http.StatusInternalServerError)
		return
	}

	// Debug log JWT details
	logJWTDetails(rawIDToken)

	// Verify ID token
	idToken, err := app.MicrosoftApp.Verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		log.Printf("Token verification error: %v", err)
		http.Error(w, "Failed to verify ID token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract claims
	var user User
	if err := idToken.Claims(&user); err != nil {
		http.Error(w, "Failed to parse claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set auth provider
	user.AuthProvider = ProviderMicrosoft

	// Debug log claims
	logUserClaims(user, idToken)

	// Save user in session
	session.Values["user"] = user
	delete(session.Values, "state")
	delete(session.Values, "auth_provider")
	session.Save(r, w)

	log.Printf("Microsoft authentication successful for user %s (Email: %s)", user.Name, user.Email)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// HandleGoogleCallback processes Google login callback
func (app *MultiApp) HandleGoogleCallback(w http.ResponseWriter, r *http.Request) {
	if app.GoogleApp == nil {
		http.Error(w, "Google authentication not configured", http.StatusNotImplemented)
		return
	}

	session, _ := app.Store.Get(r, "session")

	// Verify state parameter
	savedState, ok := session.Values["state"].(string)
	if !ok || savedState != r.URL.Query().Get("state") {
		http.Error(w, "Invalid state parameter", http.StatusBadRequest)
		return
	}

	// Verify this is the expected provider
	authProvider, _ := session.Values["auth_provider"].(string)
	if authProvider != ProviderGoogle {
		http.Error(w, "Provider mismatch", http.StatusBadRequest)
		return
	}

	// Process auth code
	code := r.URL.Query().Get("code")
	oauth2Token, err := app.GoogleApp.OAuth2Config.Exchange(r.Context(), code)
	if err != nil {
		http.Error(w, "Failed to exchange token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Log token info (debug)
	logTokenInfo(oauth2Token, "Google")

	// Extract and verify ID token
	rawIDToken, ok := oauth2Token.Extra("id_token").(string)
	if !ok {
		http.Error(w, "No id_token in response", http.StatusInternalServerError)
		return
	}

	// Debug log JWT details
	logJWTDetails(rawIDToken)

	// Verify ID token
	idToken, err := app.GoogleApp.Verifier.Verify(r.Context(), rawIDToken)
	if err != nil {
		log.Printf("Token verification error: %v", err)
		http.Error(w, "Failed to verify ID token: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Extract claims
	var user User
	if err := idToken.Claims(&user); err != nil {
		http.Error(w, "Failed to parse claims: "+err.Error(), http.StatusInternalServerError)
		return
	}

	// Set auth provider
	user.AuthProvider = ProviderGoogle

	// Debug log claims
	logUserClaims(user, idToken)

	// Google Workspace check - hd claim indicates organizational account
	var allClaims map[string]interface{}
	if err := idToken.Claims(&allClaims); err == nil {
		if hd, ok := allClaims["hd"].(string); ok {
			user.HD = hd
			log.Printf("User from Google Workspace domain: %s", hd)
		} else {
			log.Printf("User has a personal Google account (no hd claim)")
		}
	}

	// Save user in session
	session.Values["user"] = user
	delete(session.Values, "state")
	delete(session.Values, "auth_provider")
	session.Save(r, w)

	log.Printf("Google authentication successful for user %s (Email: %s)", user.Name, user.Email)
	http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
}

// LogoutHandler handles user logout for any provider
func (app *MultiApp) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	session, _ := app.Store.Get(r, "session")

	// Check which provider was used
	var authProvider string
	if user, ok := session.Values["user"].(User); ok {
		authProvider = user.AuthProvider
	}

	// Clear session
	session.Options.MaxAge = -1
	session.Save(r, w)

	// Redirect to appropriate logout endpoint
	var logoutURL string

	switch authProvider {
	case ProviderGoogle:
		// Google doesn't have a logout endpoint that accepts redirect_uri
		// Simply redirecting to home page
		logoutURL = "/"
	default:
		// Default to Microsoft logout (works even if provider is unknown)
		logoutURL = fmt.Sprintf("https://login.microsoftonline.com/common/oauth2/v2.0/logout?post_logout_redirect_uri=%s",
			"http://localhost:8080/")
	}

	http.Redirect(w, r, logoutURL, http.StatusTemporaryRedirect)
}

// ProtectedHandler shows protected content
func (app *MultiApp) ProtectedHandler(w http.ResponseWriter, r *http.Request) {
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

// requireAuth middleware ensures the user is authenticated
func (app *MultiApp) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		session, _ := app.Store.Get(r, "session")
		if _, authenticated := session.Values["user"].(User); !authenticated {
			http.Redirect(w, r, "/", http.StatusTemporaryRedirect)
			return
		}
		next(w, r)
	}
}

// Helper functions
func generateRandomString(length int) (string, error) {
	bytes := make([]byte, length)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(bytes), nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}

// Logging helper functions
func logTokenInfo(token *oauth2.Token, provider string) {
	log.Printf("=== %s OAuth2 Token ===", provider)
	log.Printf("Access Token (first 50 chars): %s...", token.AccessToken[:min(50, len(token.AccessToken))])
	log.Printf("Token Type: %s", token.TokenType)
	log.Printf("Expires: %v", token.Expiry)

	if idTokenRaw := token.Extra("id_token"); idTokenRaw != nil {
		log.Printf("Has ID token: Yes")
	} else {
		log.Printf("Has ID token: No")
	}
}

func logJWTDetails(rawIDToken string) {
	log.Printf("=== Raw ID Token (JWT) ===")
	log.Printf("Length: %d characters", len(rawIDToken))
	log.Printf("Raw JWT (first 100 chars): %s...", rawIDToken[:min(100, len(rawIDToken))])

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
}

func logUserClaims(user User, idToken *oidc.IDToken) {
	// Log basic token info
	log.Printf("=== Verified ID Token Info ===")
	log.Printf("Issuer: %s", idToken.Issuer)
	log.Printf("Audience: %v", idToken.Audience)
	log.Printf("Subject: %s", idToken.Subject)
	log.Printf("Expiry: %v", idToken.Expiry)
	log.Printf("Issued At: %v", idToken.IssuedAt)

	// Log parsed user
	log.Printf("=== Parsed User Claims ===")
	userJSON, _ := json.MarshalIndent(user, "", "  ")
	log.Printf("%s", string(userJSON))

	// Log all claims for debugging
	var allClaims map[string]interface{}
	if err := idToken.Claims(&allClaims); err == nil {
		log.Printf("=== All Available Claims ===")
		allClaimsJSON, _ := json.MarshalIndent(allClaims, "", "  ")
		log.Printf("%s", string(allClaimsJSON))
	}
}

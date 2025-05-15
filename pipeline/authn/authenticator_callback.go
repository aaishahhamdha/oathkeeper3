package authn

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aaishahhamdha/oathkeeper/driver/configuration"
	"github.com/aaishahhamdha/oathkeeper/pipeline"
	"github.com/dgraph-io/ristretto"
	"github.com/ory/x/httpx"
	"github.com/ory/x/logrusx"
	"github.com/ory/x/otelx"
	"github.com/pkg/errors"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
)

type AuthenticatorCallbackConfiguration struct {
	ClientID                string                                   `json:"client_id"`
	ClientSecret            string                                   `json:"client_secret"`
	TokenEndpoint           string                                   `json:"token_url"`
	UserInforEndpoint       string                                   `json:"userinfo_url"`
	RedirectURL             string                                   `json:"redirect_url"`
	TokenEndpointAuthMethod string                                   `json:"token_endpoint_auth_method"`
	Retry                   *AuthenticatorCallbackRetryConfiguration `json:"retry"`
	Cache                   cacheConfig
}

type AuthenticatorCallbackRetryConfiguration struct {
	Timeout string `json:"max_delay"`
	MaxWait string `json:"give_up_after"`
}

type AuthenticatorCallback struct {
	c         configuration.Provider
	clientMap map[string]*http.Client

	mu         sync.RWMutex
	tokenCache *ristretto.Cache[string, []byte]
	cacheTTL   *time.Duration
	logger     *logrusx.Logger
	provider   trace.TracerProvider
}

func NewAuthenticatorCallback(c configuration.Provider, logger *logrusx.Logger, provider trace.TracerProvider) *AuthenticatorCallback {
	// Create token cache
	tokenCache, err := ristretto.NewCache(&ristretto.Config[string, []byte]{
		NumCounters: 1e7,
		MaxCost:     1 << 30,
		BufferItems: 64,
	})
	if err != nil {
		logger.Fatal("Failed to create token cache", err)
	}

	return &AuthenticatorCallback{
		c:          c,
		logger:     logger,
		provider:   provider,
		clientMap:  make(map[string]*http.Client),
		tokenCache: tokenCache,
	}
}

func (a *AuthenticatorCallback) GetID() string {
	return "callback"
}

func (a *AuthenticatorCallback) Validate(config json.RawMessage) error {
	if !a.c.AuthenticatorIsEnabled(a.GetID()) {
		return NewErrAuthenticatorNotEnabled(a)
	}

	_, _, err := a.Config(config)
	return err
}

func (a *AuthenticatorCallback) Config(config json.RawMessage) (*AuthenticatorCallbackConfiguration, *http.Client, error) {
	var c AuthenticatorCallbackConfiguration
	if err := a.c.AuthenticatorConfig(a.GetID(), config, &c); err != nil {
		return nil, nil, NewErrAuthenticatorMisconfigured(a, err)
	}

	rawKey, err := json.Marshal(&c)
	if err != nil {
		return nil, nil, errors.WithStack(err)
	}

	clientKey := fmt.Sprintf("%x", md5.Sum(rawKey))
	a.mu.RLock()
	client, ok := a.clientMap[clientKey]
	a.mu.RUnlock()

	if !ok || client == nil {
		a.logger.Debug("Initializing http client")
		var rt http.RoundTripper

		if c.Retry == nil {
			c.Retry = &AuthenticatorCallbackRetryConfiguration{Timeout: "500ms", MaxWait: "1s"}
		} else {
			if c.Retry.Timeout == "" {
				c.Retry.Timeout = "500ms"
			}
			if c.Retry.MaxWait == "" {
				c.Retry.MaxWait = "1s"
			}
		}
		duration, err := time.ParseDuration(c.Retry.Timeout)
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}
		timeout := time.Millisecond * duration

		maxWait, err := time.ParseDuration(c.Retry.MaxWait)
		if err != nil {
			return nil, nil, errors.WithStack(err)
		}

		client = httpx.NewResilientClient(
			httpx.ResilientClientWithMaxRetryWait(maxWait),
			httpx.ResilientClientWithConnectionTimeout(timeout),
		).StandardClient()
		client.Transport = otelhttp.NewTransport(rt, otelhttp.WithTracerProvider(a.provider))
		a.mu.Lock()
		a.clientMap[clientKey] = client
		a.mu.Unlock()
	}

	if c.Cache.TTL != "" {
		cacheTTL, err := time.ParseDuration(c.Cache.TTL)
		if err != nil {
			return nil, nil, err
		}

		// clear cache if previous ttl was longer (or none)
		if a.tokenCache != nil {
			if a.cacheTTL == nil || (a.cacheTTL != nil && a.cacheTTL.Seconds() > cacheTTL.Seconds()) {
				a.tokenCache.Clear()
			}
		}

		a.cacheTTL = &cacheTTL
	}

	if a.tokenCache == nil {
		cost := int64(c.Cache.MaxCost)
		if cost == 0 {
			cost = 100000000
		}
		a.logger.Debugf("Creating cache with max cost: %d", c.Cache.MaxCost)
		cache, err := ristretto.NewCache(&ristretto.Config[string, []byte]{
			// This will hold about 1000 unique mutation responses.
			NumCounters: cost * 10,
			// Allocate a max
			MaxCost: cost,
			// This is a best-practice value.
			BufferItems: 64,
			Cost: func(value []byte) int64 {
				return 1
			},
			IgnoreInternalCost: true,
		})
		if err != nil {
			return nil, nil, err
		}

		a.tokenCache = cache
	}

	return &c, client, nil
}

func (a *AuthenticatorCallback) Authenticate(r *http.Request, session *AuthenticationSession, config json.RawMessage, rule pipeline.Rule) (err error) {
	tp := trace.SpanFromContext(r.Context()).TracerProvider()
	ctx, span := tp.Tracer("oauthkeeper/pipeline/authn").Start(r.Context(), "pipeline.authn.AuthenticatorCallback.Authenticate")
	defer otelx.End(span, &err)
	r = r.WithContext(ctx)

	cf, client, err := a.Config(config)
	if err != nil {
		return err
	}

	requestURL := r.URL
	authCode := requestURL.Query().Get("code")

	if authCode != "" {
		fmt.Println("Authorization code:", authCode)
	} else {
		fmt.Println("Authorization code not found in URL")
	}
	s := pipeline.Global()
	state := requestURL.Query().Get("state")
	if state != "" {
		fmt.Println("State:", state)
	} else {
		fmt.Println("State not found in URL")
	}
	authState := s.MustGet("state") // Assuming session stores it in headers
	if authState == "" {
		fmt.Println("State not found in session")
		return errors.New("no state found in session - possible session expiry")
	} else {
		fmt.Println("State from session:", authState)
	}

	// Compare the returned state with the stored state
	if authState != state {
		fmt.Println("Invalid state: possible CSRF attack")
		return errors.New("invalid state: possible CSRF attack")
	}

	// Clear the state from the session after validation
	s.Delete("state")

	fmt.Println("State is valid. Authorization code:", authCode)

	data := url.Values{}
	data.Set("grant_type", "authorization_code")
	data.Set("code", authCode)
	data.Set("redirect_uri", cf.RedirectURL)

	// Set client credentials for client_secret_post
	if cf.TokenEndpointAuthMethod == "client_secret_post" {
		data.Set("client_id", cf.ClientID)
		data.Set("client_secret", cf.ClientSecret)
	} else if cf.TokenEndpointAuthMethod == "client_secret_basic" {
		auth := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("%s:%s", cf.ClientID, cf.ClientSecret)))
		r.Header.Set("Authorization", fmt.Sprintf("Basic %s", auth))
	} else {
		return errors.Errorf("unsupported token endpoint auth method: %s", cf.TokenEndpointAuthMethod)
	}

	// Now create the body
	req, err := http.NewRequestWithContext(ctx, "POST", cf.TokenEndpoint, strings.NewReader(data.Encode()))
	fmt.Println("Token request URL:", cf.TokenEndpoint)
	fmt.Println("Client ID:", cf.ClientID)
	fmt.Println("Client Secret:", cf.ClientSecret)
	fmt.Println("Redirect URL:", cf.RedirectURL)
	fmt.Println("Token Endpoint Auth Method:", cf.TokenEndpointAuthMethod)
	fmt.Println("User Info Endpoint:", cf.UserInforEndpoint)

	if err != nil {
		return errors.Wrap(err, "failed to create token request")
	}

	// Set headers
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	// Make the request using the pre-configured client
	resp, err := client.Do(req)
	if err != nil {
		return errors.Wrap(err, "failed to make token request")
	}
	defer resp.Body.Close()

	// Check for non-200 status
	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return errors.Errorf("token endpoint returned %d: %s", resp.StatusCode, string(body))
	}

	// Parse the token response
	var tokenResponse struct {
		AccessToken  string `json:"access_token"`
		TokenType    string `json:"token_type"`
		ExpiresIn    int    `json:"expires_in"`
		RefreshToken string `json:"refresh_token"`
		IDToken      string `json:"id_token"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&tokenResponse); err != nil {
		return errors.Wrap(err, "failed to decode token response")
	}
	fmt.Printf("Access token: %s \n", tokenResponse.AccessToken)
	fmt.Printf("ID token: %s", tokenResponse.IDToken)

	if session.Extra == nil {
		session.Extra = make(map[string]interface{})
	}
	// Store the access token in Extra
	session.Extra["access_token"] = tokenResponse.AccessToken
	sessionAccessToken, err := s.Get("access_token")
	if sessionAccessToken == nil || err != nil {
		s.MustSet("access_token", tokenResponse.AccessToken)
	} else {
		s.Update("access_token", tokenResponse.AccessToken)
	}

	sessionIDToken, err := s.Get("id_token")
	if sessionIDToken == nil || err != nil {
		s.MustSet("id_token", tokenResponse.IDToken)
	} else {
		s.Update("id_token", tokenResponse.IDToken)
	}
	if tokenResponse.IDToken != "" {
		session.Extra["id_token"] = tokenResponse.IDToken
	}
	if tokenResponse.AccessToken != "" {
		session.SetHeader("Authorization", fmt.Sprintf("Bearer %s", tokenResponse.AccessToken))
	}

	req1, err := http.NewRequestWithContext(ctx, "GET", cf.UserInforEndpoint, strings.NewReader(data.Encode()))
	req1.Header.Set("Authorization", fmt.Sprintf("Bearer %s", tokenResponse.AccessToken))
	resp1, err := client.Do(req1)
	if err != nil {
		return errors.Wrap(err, "failed to make userinfo request")
	}
	defer resp1.Body.Close()
	if resp1.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp1.Body)
		return errors.Errorf("userinfo endpoint returned %d: %s", resp1.StatusCode, string(body))
	}

	var userInfoResponse struct {
		Sub      string  `json:"sub"`
		Username *string `json:"username,omitempty"`
		Email    *string `json:"email,omitempty"`
		Name     *string `json:"name,omitempty"`
	}
	// Decode the user info response from the API
	if err := json.NewDecoder(resp1.Body).Decode(&userInfoResponse); err != nil {
		return errors.Wrap(err, "failed to decode userInfo response")
	}

	// Log the user information for debugging
	fmt.Printf("Sub: %s\n", userInfoResponse.Sub)
	if userInfoResponse.Username != nil {
		fmt.Printf("Username: %s\n", *userInfoResponse.Username)
	} else {
		fmt.Println("Username: <nil>")
	}
	if userInfoResponse.Email != nil {
		fmt.Printf("Email: %s\n", *userInfoResponse.Email)
	} else {
		fmt.Println("Email: <nil>")
	}
	if userInfoResponse.Name != nil {
		fmt.Printf("Name: %s\n", *userInfoResponse.Name)
	} else {
		fmt.Println("Name: <nil>")
	}

	// Store the user info in the session's Extra field
	if session.Extra == nil {
		session.Extra = make(map[string]interface{})
	}

	// Store the user information in the session
	session.Extra["sub"] = userInfoResponse.Sub
	session.Extra["username"] = userInfoResponse.Username
	session.Extra["name"] = userInfoResponse.Name

	// Set the Authorization header for the session
	if tokenResponse.AccessToken != "" {
		session.SetHeader("Authorization", fmt.Sprintf("Bearer %s", tokenResponse.AccessToken))
	}
	return nil

}

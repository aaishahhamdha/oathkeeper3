package authn

import (
	"crypto/md5"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/aaishahhamdha/oathkeeper/driver/configuration"
	"github.com/aaishahhamdha/oathkeeper/pipeline"
	"github.com/ory/x/httpx"
	"github.com/ory/x/logrusx"
	"github.com/ory/x/otelx"
	"github.com/pkg/errors"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/trace"
)

type AuthenticatorOIDCAuthorizeConfiguration struct {
	AuthorizationURL string                                   `json:"auth_url"`
	ClientID         string                                   `json:"client_id"`
	RedirectURL      string                                   `json:"redirect_url"`
	Scopes           []string                                 `json:"scopes"`
	Retry            *AuthenticatorCallbackRetryConfiguration `json:"retry"`
	Cache            cacheConfig
}
type AuthenticatorOIDCAuthorize struct {
	c         configuration.Provider
	clientMap map[string]*http.Client

	mu       sync.RWMutex
	cacheTTL *time.Duration
	logger   *logrusx.Logger
	provider trace.TracerProvider
}

// Authenticate implements Authenticator.
func (a *AuthenticatorOIDCAuthorize) Authenticate(r *http.Request, session *AuthenticationSession, config json.RawMessage, rule pipeline.Rule) (err error) {
	tp := trace.SpanFromContext(r.Context()).TracerProvider()
	ctx, span := tp.Tracer("oauthkeeper/pipeline/authn").Start(r.Context(), "pipeline.authn.AuthenticatorCallback.Authenticate")
	defer otelx.End(span, &err)
	r = r.WithContext(ctx)

	cf, client, err := a.Config(config)
	if err != nil {
		return err
	}
	url, state, err := BuildAuthorizationURL(cf)
	if err != nil {
		return fmt.Errorf("failed to build authorization URL: %w", err)
	}

	// Store the state in the session for later validation
	session.SetHeader("state", state)
	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return errors.Wrap(err, "failed to create login request")
	}
	resp1, err := client.Do(req)
	a.logger.Debugf("Authorization URL: %s", url)
	a.logger.Debugf("Authorization response: %s", resp1.Status)
	if err != nil {
		return errors.Wrap(err, "failed to make login request")
	}

	return nil

}

func BuildAuthorizationURL(config *AuthenticatorOIDCAuthorizeConfiguration) (string, string, error) {
	// Generate random state for CSRF protection
	state, err := GenerateRandomString(32)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate state: %w", err)
	}

	// Create URL with query parameters
	authURL, err := url.Parse(config.AuthorizationURL)
	if err != nil {
		return "", "", fmt.Errorf("invalid authorization endpoint URL: %w", err)
	}

	params := url.Values{}
	params.Add("response_type", "code")
	params.Add("client_id", config.ClientID)
	params.Add("redirect_uri", config.RedirectURL)
	params.Add("scope", strings.Join(config.Scopes, " "))
	params.Add("state", state)

	return authURL.String(), state, nil
}

func GenerateRandomString(n int) (string, error) {
	b := make([]byte, n)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	return base64.URLEncoding.EncodeToString(b), nil
}

func (a *AuthenticatorOIDCAuthorize) Validate(config json.RawMessage) error {
	if !a.c.AuthenticatorIsEnabled(a.GetID()) {
		return NewErrAuthenticatorNotEnabled(a)
	}

	_, _, err := a.Config(config)
	return err
}

type AuthenticatorOidcAuthorizeRetryConfiguration struct {
	Timeout string `json:"max_delay"`
	MaxWait string `json:"give_up_after"`
}

func NewAuthenticatorOidcAuthorize(c configuration.Provider, l *logrusx.Logger, p trace.TracerProvider) *AuthenticatorOIDCAuthorize {
	return &AuthenticatorOIDCAuthorize{c: c, logger: l, provider: p, clientMap: make(map[string]*http.Client)}
}
func (a *AuthenticatorOIDCAuthorize) GetID() string {
	return "oidc_authorize"
}

func (a *AuthenticatorOIDCAuthorize) Config(config json.RawMessage) (*AuthenticatorOIDCAuthorizeConfiguration, *http.Client, error) {
	var c AuthenticatorOIDCAuthorizeConfiguration
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

	return &c, client, nil
}

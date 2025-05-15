// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package authn

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/golang-jwt/jwt/v5"
	"github.com/pkg/errors"
	"go.opentelemetry.io/otel/trace"

	"github.com/aaishahhamdha/oathkeeper/credentials"
	"github.com/aaishahhamdha/oathkeeper/driver/configuration"
	"github.com/aaishahhamdha/oathkeeper/helper"
	"github.com/aaishahhamdha/oathkeeper/pipeline"
	"github.com/ory/herodot"
	"github.com/ory/x/jwtx"
	"github.com/ory/x/otelx"
)

type AuthenticatorSessionJWTRegistry interface {
	credentials.VerifierRegistry
	Tracer() trace.Tracer
}

type AuthenticatorOAuth2SessionJWTConfiguration struct {
	Scope             []string `json:"required_scope"`
	Audience          []string `json:"target_audience"`
	Issuers           []string `json:"trusted_issuers"`
	AllowedAlgorithms []string `json:"allowed_algorithms"`
	JWKSURLs          []string `json:"jwks_urls"`
	ScopeStrategy     string   `json:"scope_strategy"`
}

type AuthenticatorSessionJWT struct {
	c configuration.Provider
	r AuthenticatorSessionJWTRegistry
}

func NewAuthenticatorSessionJWT(
	c configuration.Provider,
	r AuthenticatorSessionJWTRegistry,
) *AuthenticatorSessionJWT {
	return &AuthenticatorSessionJWT{
		c: c,
		r: r,
	}
}

func (a *AuthenticatorSessionJWT) GetID() string {
	return "session_jwt"
}

func (a *AuthenticatorSessionJWT) Validate(config json.RawMessage) error {
	if !a.c.AuthenticatorIsEnabled(a.GetID()) {
		return NewErrAuthenticatorNotEnabled(a)
	}

	_, err := a.Config(config)
	return err
}

func (a *AuthenticatorSessionJWT) Config(config json.RawMessage) (*AuthenticatorOAuth2SessionJWTConfiguration, error) {
	var c AuthenticatorOAuth2SessionJWTConfiguration
	if err := a.c.AuthenticatorConfig(a.GetID(), config, &c); err != nil {
		return nil, NewErrAuthenticatorMisconfigured(a, err)
	}

	return &c, nil
}

// BearerTokenFromSession safely extracts the access token from session
func (a *AuthenticatorSessionJWT) BearerTokenFromSession(s *pipeline.Session) (string, error) {
	token, err := s.Get("access_token")
	if err != nil {
		return "", errors.Wrap(err, "access_token not found in session")
	}

	strToken, ok := token.(string)
	if !ok || strToken == "" {
		return "", errors.New("invalid access_token format in session")
	}

	return strToken, nil
}

func (a *AuthenticatorSessionJWT) Authenticate(r *http.Request, session *AuthenticationSession, config json.RawMessage, _ pipeline.Rule) (err error) {
	ctx, span := a.r.Tracer().Start(r.Context(), "pipeline.authn.AuthenticatorSessionJWT.Authenticate")
	defer otelx.End(span, &err)
	r = r.WithContext(ctx)

	cf, err := a.Config(config)
	if err != nil {
		return err
	}

	token, err := a.BearerTokenFromSession(pipeline.Global())
	if err != nil {
		return errors.WithStack(ErrAuthenticatorNotResponsible)
	}
	if token == "" {
		return errors.WithStack(ErrAuthenticatorNotResponsible)
	}
	fmt.Println("token from jwt authenticator:", token)

	// If the token is not a JWT, declare ourselves not responsible. This enables using fallback authenticators (i. e.
	// bearer_token or oauth2_introspection) for different token types at the same location.
	if len(strings.Split(token, ".")) != 3 {
		return errors.WithStack(ErrAuthenticatorNotResponsible)
	}

	if len(cf.AllowedAlgorithms) == 0 {
		cf.AllowedAlgorithms = []string{"RS256"}
	}

	jwksu, err := a.c.ParseURLs(cf.JWKSURLs)
	if err != nil {
		return err
	}

	pt, err := a.r.CredentialsVerifier().Verify(r.Context(), token, &credentials.ValidationContext{
		Algorithms:    cf.AllowedAlgorithms,
		KeyURLs:       jwksu,
		Scope:         cf.Scope,
		Issuers:       cf.Issuers,
		Audiences:     cf.Audience,
		ScopeStrategy: a.c.ToScopeStrategy(cf.ScopeStrategy, "authenticators.session_jwt.Config.scope_strategy"),
	})
	if err != nil {
		de := herodot.ToDefaultError(err, "")
		r := fmt.Sprintf("%+v", de)
		return a.tryEnrichResultErr(token, helper.ErrUnauthorized.WithReason(r).WithTrace(err))
	}

	claims, ok := pt.Claims.(jwt.MapClaims)
	if !ok {
		return errors.WithStack(herodot.ErrInternalServerError.WithReasonf("Expected JSON Web Token claims to be of type jwt.MapClaims but got: %T", pt.Claims))
	}

	session.Subject = jwtx.ParseMapStringInterfaceClaims(claims).Subject
	session.Extra = claims

	return nil
}

func (a *AuthenticatorSessionJWT) tryEnrichResultErr(token string, err *herodot.DefaultError) *herodot.DefaultError {
	t, _ := jwt.ParseWithClaims(token, jwt.MapClaims{}, nil, jwt.WithIssuedAt())
	if t == nil {
		return err
	}
	claims, ok := t.Claims.(jwt.MapClaims)
	if !ok {
		return err
	}
	jsonVal, err2 := json.Marshal(claims)
	if err2 != nil {
		return err
	}
	return err.WithDetail("jwt_claims", string(jsonVal))
}

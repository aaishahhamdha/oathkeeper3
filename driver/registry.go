// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package driver

import (
	"go.opentelemetry.io/otel/trace"

	"github.com/ory/x/logrusx"

	"github.com/ory/x/healthx"

	"github.com/aaishahhamdha/oathkeeper/pipeline/errors"
	"github.com/aaishahhamdha/oathkeeper/proxy"

	"github.com/aaishahhamdha/oathkeeper/api"
	"github.com/aaishahhamdha/oathkeeper/credentials"
	"github.com/aaishahhamdha/oathkeeper/driver/configuration"
	"github.com/aaishahhamdha/oathkeeper/pipeline/authn"
	"github.com/aaishahhamdha/oathkeeper/pipeline/authz"
	"github.com/aaishahhamdha/oathkeeper/pipeline/mutate"
	"github.com/aaishahhamdha/oathkeeper/rule"
	"github.com/aaishahhamdha/oathkeeper/x"
)

type Registry interface {
	Init()

	WithConfig(c configuration.Provider) Registry
	WithLogger(l *logrusx.Logger) Registry
	WithBuildInfo(version, hash, date string) Registry
	BuildVersion() string
	BuildDate() string
	BuildHash() string

	ProxyRequestHandler() proxy.RequestHandler
	HealthxReadyCheckers() healthx.ReadyCheckers
	HealthHandler() *healthx.Handler
	RuleHandler() *api.RuleHandler
	DecisionHandler() *api.DecisionHandler
	CredentialHandler() *api.CredentialsHandler

	Proxy() *proxy.Proxy
	Tracer() trace.Tracer

	authn.Registry
	authz.Registry
	mutate.Registry
	errors.Registry

	rule.Registry
	credentials.FetcherRegistry
	credentials.SignerRegistry
	credentials.VerifierRegistry

	x.RegistryWriter
	x.RegistryLogger
}

func NewRegistry(c configuration.Provider) Registry {
	return NewRegistryMemory().WithConfig(c)
}

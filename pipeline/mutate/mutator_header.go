// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package mutate

import (
	"bytes"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"text/template"

	"github.com/aaishahhamdha/oathkeeper/driver/configuration"
	"github.com/aaishahhamdha/oathkeeper/pipeline"
	"github.com/aaishahhamdha/oathkeeper/pipeline/authn"
	"github.com/aaishahhamdha/oathkeeper/x"

	"github.com/pkg/errors"
)

type MutatorHeaderConfig struct {
	Headers map[string]interface{} `json:"headers"`
}

type MutatorHeader struct {
	c configuration.Provider
	t *template.Template
}

func NewMutatorHeader(c configuration.Provider) *MutatorHeader {
	return &MutatorHeader{c: c, t: x.NewTemplate("header")}
}

func (a *MutatorHeader) GetID() string {
	return "header"
}

func (a *MutatorHeader) WithCache(t *template.Template) {
	a.t = t
}

func (a *MutatorHeader) Mutate(_ *http.Request, session *authn.AuthenticationSession, config json.RawMessage, rl pipeline.Rule) error {
	cfg, err := a.config(config)
	if err != nil {
		return err
	}

	for hdr, templateValue := range cfg.Headers {
		var templateString string

		switch v := templateValue.(type) {
		case string:
			templateString = v
		case []interface{}:
			strParts := make([]string, len(v))
			for i, part := range v {
				strParts[i] = fmt.Sprint(part)
			}
			templateString = strings.Join(strParts, "")
		default:
			return errors.Errorf(`header template value has unexpected type %T for header "%s" in rule "%s"`, templateValue, hdr, rl.GetID())
		}

		var tmpl *template.Template
		templateId := fmt.Sprintf("%s:%s", rl.GetID(), hdr)
		tmpl = a.t.Lookup(templateId)
		if tmpl == nil {
			tmpl, err = a.t.New(templateId).Parse(templateString)
			if err != nil {
				return errors.Wrapf(err, `error parsing headers template "%s" in rule "%s"`, templateString, rl.GetID())
			}
		}

		headerValue := bytes.Buffer{}
		err = tmpl.Execute(&headerValue, session)
		if err != nil {
			return errors.Wrapf(err, `error executing headers template "%s" in rule "%s"`, templateString, rl.GetID())
		}
		session.SetHeader(hdr, headerValue.String())
	}

	return nil
}

func (a *MutatorHeader) Validate(config json.RawMessage) error {
	if !a.c.MutatorIsEnabled(a.GetID()) {
		return NewErrMutatorNotEnabled(a)
	}

	_, err := a.config(config)
	return err
}

func (a *MutatorHeader) config(config json.RawMessage) (*MutatorHeaderConfig, error) {
	var c MutatorHeaderConfig
	if err := a.c.MutatorConfig(a.GetID(), config, &c); err != nil {
		return nil, NewErrMutatorMisconfigured(a, err)
	}

	return &c, nil
}

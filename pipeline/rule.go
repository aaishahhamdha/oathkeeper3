// Copyright © 2023 Ory Corp
// SPDX-License-Identifier: Apache-2.0

package pipeline

import (
	"github.com/aaishahhamdha/oathkeeper/driver/configuration"
)

type Rule interface {
	GetID() string
	// ReplaceAllString searches the input string and replaces each match (with the rule's pattern)
	// found with the replacement text.
	ReplaceAllString(strategy configuration.MatchingStrategy, input, replacement string) (string, error)
}

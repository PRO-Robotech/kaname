// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package listfilter

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/filter"
	"github.com/stretchr/testify/require"
)

func TestParseLabel(t *testing.T) {
	ast, err := Parse(` labels.platform.example/team@blue-v2 = "50%_done" `, nil)
	require.NoError(t, err)
	require.Equal(t, &Label{Key: "platform.example/team@blue-v2", Value: "50%_done"}, ast.Label)

	ast, err = Parse(`labels.env=""`, nil)
	require.NoError(t, err)
	require.Equal(t, &Label{Key: "env"}, ast.Label)
}

func TestParseRejectsInvalidLabels(t *testing.T) {
	for _, expression := range []string{
		`labels="prod"`,
		`accessLabels.env="prod"`,
		`labels. = "prod"`,
		`labels.Env = "prod"`,
		`labels.env$ = "prod"`,
		`labels.env CONTAINS "prod"`,
		`labels.env = "prod`,
		`labels.env = "prod" AND name = "one"`,
		"labels." + strings.Repeat("a", 64) + `="prod"`,
		"labels.env = \"a\x00b\"",
	} {
		t.Run(expression, func(t *testing.T) {
			_, err := Parse(expression, []string{"name"})
			require.ErrorAs(t, err, new(*filter.ParseError))
		})
	}
}

func TestParseKeepsScalarGrammar(t *testing.T) {
	ast, err := Parse(`name CONTAINS "test"`, []string{"name"})
	require.NoError(t, err)
	require.Nil(t, ast.Label)
	require.Equal(t, &filter.FilterAST{Field: "name", Op: filter.OpContains, Value: "test"}, ast.FilterAST)

	ast, err = Parse("   ", []string{"name"})
	require.NoError(t, err)
	require.Nil(t, ast)
}

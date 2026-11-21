// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"io"
	"testing"
	"testing/fstest"

	"github.com/PRO-Robotech/corelib/migratorcli"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	"github.com/stretchr/testify/require"
)

func TestAuthorityBundleCommandRequiresExplicitActionAndDelivery(t *testing.T) {
	for _, tc := range []struct {
		args []string
		want string
	}{
		{[]string{"authority-bundle"}, migratorcli.ErrNoCommand.Error()},
		{[]string{"authority-bundle", "unexpected"}, "unexpected"},
		{[]string{"authority-bundle", "stage"}, "ровно один источник"},
		{[]string{"authority-bundle", "activate"}, "ровно один источник"},
		{[]string{"authority-bundle", "verify"}, "ровно один источник"},
		{[]string{"authority-bundle", "stage", "--image-only", "--manifest-dir", "somewhere"}, "ровно один источник"},
		{[]string{"authority-bundle", "stage", "--image-only", "extra"}, "extra"},
		{[]string{"authority-bundle", "close", "--image-only"}, "image-only"},
		// Законные формы доходят до настоящего DSN resolver; bogus гарантирует,
		// что тест не открывает соединение даже при регрессии dispatch.
		{[]string{"authority-bundle", "stage", "--image-only"}, "bogus"},
		{[]string{"authority-bundle", "activate", "--image-only"}, "bogus"},
		{[]string{"authority-bundle", "verify", "--image-only"}, "bogus"},
		{[]string{"authority-bundle", "close"}, "bogus"},
	} {
		t.Run(testNameArgs(tc.args), func(t *testing.T) {
			command := newRootCmd(fstest.MapFS{})
			command.SetOut(io.Discard)
			command.SetErr(io.Discard)
			command.SetArgs(append([]string{"--dialect", "bogus"}, tc.args...))
			require.ErrorContains(t, command.Execute(), tc.want)
		})
	}
}
func testNameArgs(args []string) string {
	out := ""
	for _, arg := range args {
		out += arg + "_"
	}
	return out
}

func TestAuthorityDeliveredBundleUsesAdmissionAndRealCatalogParity(t *testing.T) {
	ctx := context.Background()
	source, report, err := modelcompose.Compose(authzmodel.DSL, nil)
	require.NoError(t, err)
	rows := catalog.Halves{Live: seed.LiteralRows()}
	bundle, pins, err := authorityDeliveredBundle(ctx, source, report.KeyTerms, nil, rows)
	require.NoError(t, err)
	require.Empty(t, pins)
	require.NoError(t, bundle.Validate())
	require.Equal(t, granteffect.ProjectorVersion, bundle.Identity().ProjectorVersion)
	invalid, _, err := authorityDeliveredBundle(ctx, "model invalid", nil, nil, rows)
	require.Error(t, err)
	require.Nil(t, invalid)
	missing := catalog.Halves{Live: seed.LiteralRows()}
	require.NotEmpty(t, missing.Live.Verbs)
	missing.Live.Verbs = missing.Live.Verbs[1:]
	invalid, _, err = authorityDeliveredBundle(ctx, source, report.KeyTerms, nil, missing)
	require.Error(t, err)
	require.Nil(t, invalid, "потерянная actual строка не превращается в новую норму")
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	invalid, _, err = authorityDeliveredBundle(canceled, source, report.KeyTerms, nil, rows)
	require.ErrorIs(t, err, context.Canceled)
	require.Nil(t, invalid)
}

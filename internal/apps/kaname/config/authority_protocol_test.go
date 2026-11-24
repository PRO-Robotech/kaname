// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package config

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestAuthorityParticipationConfiguration(t *testing.T) {
	c, err := Load("")
	require.NoError(t, err)
	require.Equal(t, "legacy", c.AuthorityProtocol.Participation)
	for _, mode := range []string{"", "legacy", "participant"} {
		require.NoError(t, (AuthorityProtocolConfig{Participation: mode}).Validate())
	}
	require.Error(t, (AuthorityProtocolConfig{Participation: "particpant"}).Validate())
	t.Setenv("KANAME_AUTHORITY_PROTOCOL__PARTICIPATION", "participant")
	c, err = Load("")
	require.NoError(t, err)
	require.True(t, c.AuthorityProtocol.Participant())
}

// ENV-only selector обязан доходить до поля без YAML; default остаётся staged/legacy.
func TestAuthorityFullSemanticsSelectorIsSeparateAndBoundFromEnvironment(t *testing.T) {
	for _, mode := range []string{"", "legacy", "participant"} {
		require.NoError(t, (AuthorityProtocolConfig{Participation: mode, FullSemantics: false}).Validate())
	}
	require.Error(t, (AuthorityProtocolConfig{FullSemantics: true}).Validate())
	require.Error(t, (AuthorityProtocolConfig{Participation: "legacy", FullSemantics: true}).Validate())
	require.NoError(t, (AuthorityProtocolConfig{Participation: "participant", FullSemantics: true}).Validate())
	t.Setenv("KANAME_AUTHORITY_PROTOCOL__PARTICIPATION", "participant")
	t.Setenv("KANAME_AUTHORITY_PROTOCOL__FULL_SEMANTICS", "true")
	cfg, err := Load("")
	require.NoError(t, err)
	require.True(t, cfg.AuthorityProtocol.FullSemantics)
	require.NoError(t, cfg.AuthorityProtocol.Validate())
	t.Setenv("KANAME_AUTHORITY_PROTOCOL__FULL_SEMANTICS", "false")
	cfg, err = Load("")
	require.NoError(t, err)
	require.False(t, cfg.AuthorityProtocol.FullSemantics)
	require.True(t, cfg.AuthorityProtocol.Participant(), "staged participation не превращается в full")
}

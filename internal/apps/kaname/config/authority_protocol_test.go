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

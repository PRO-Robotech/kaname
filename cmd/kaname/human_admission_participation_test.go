// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

func TestHumanAdmissionStoresDefaultAndConfiguredNilAreDistinct(t *testing.T) {
	pool := &pgxpool.Pool{}
	legacy, recovery, err := humanAdmissionStores(pool, config.AuthorityProtocolConfig{}, nil)
	require.NoError(t, err)
	require.NotNil(t, legacy)
	require.NotNil(t, recovery)
	_, _, err = humanAdmissionStores(pool, config.AuthorityProtocolConfig{Participation: "participant"}, nil)
	require.ErrorContains(t, err, "participant is absent")
	// Ненулевой, но не сконструированный participant тоже не открывает raw TX.
	selected, completion, err := humanAdmissionStores(pool, config.AuthorityProtocolConfig{Participation: "participant"}, &kanamepg.HumanAdmissionParticipant{})
	require.NoError(t, err)
	_, err = selected.Writer(context.Background())
	require.Error(t, err)
	_, err = completion.RecoveryCompletionWriter(context.Background(), "usr_fixture")
	require.Error(t, err)
	_, _, err = humanAdmissionStores(pool, config.AuthorityProtocolConfig{Participation: "invalid"}, nil)
	require.Error(t, err)
}

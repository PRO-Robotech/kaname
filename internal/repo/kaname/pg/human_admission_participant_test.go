// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

func TestHumanAdmissionExplicitNilNeverUsesLegacyPool(t *testing.T) {
	// Пустой объект пула нельзя использовать для SQL. Любой legacy fallback
	// обнаруживается этой пробой до того, как потребовалась бы настоящая БД.
	pool := &pgxpool.Pool{}
	legacy := NewRegistrationStore(pool)
	require.False(t, legacy.participantConfigured)
	for _, participant := range []*HumanAdmissionParticipant{nil, {}} {
		configured := legacy.WithHumanAdmissionParticipant(participant)
		require.False(t, legacy.participantConfigured, "configuration не меняет исходный store")
		_, err := configured.Writer(context.Background())
		require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
		_, err = configured.VerificationWriter(context.Background(), "usr_fixture")
		require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
		_, err = configured.EmailChangeWriter(context.Background(), "usr_fixture")
		require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
		recovery, err := NewRecoveryCompletionStore(pool, func(context.Context, kaname.Writer, domain.User) (humansession.InviteActivation, error) {
			t.Fatal("callback не должен исполниться")
			return humansession.InviteActivation{}, nil
		})
		require.NoError(t, err)
		selected := recovery.WithHumanAdmissionParticipant(participant)
		require.False(t, recovery.registration.participantConfigured)
		require.True(t, selected.registration.participantConfigured)
		_, err = selected.RecoveryCompletionWriter(context.Background(), "usr_fixture")
		require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
	}
}
func TestHumanAdmissionRejectsForeignPoolAndNonCeremonyOptions(t *testing.T) {
	p := &HumanAdmissionParticipant{repo: &Repository{master: &pgxpool.Pool{}}}
	_, err := p.begin(context.Background(), &pgxpool.Pool{})
	require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
	_, err = p.beginCeremonyTx(context.Background(), pgx.TxOptions{IsoLevel: pgx.RepeatableRead})
	require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
	_, err = NewHumanAdmissionParticipant(context.Background(), nil, nil)
	require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
	for _, bundle := range []*granteffect.Bundle{nil, {}} {
		_, err = NewHumanAdmissionParticipant(context.Background(), p.repo, bundle)
		require.ErrorIs(t, err, granteffect.ErrInvalidBundle)
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/authzsnapshot"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

func TestPublishedHumanAdmissionSelection(t *testing.T) {
	pool := &pgxpool.Pool{}
	mode := config.AuthorityProtocolConfig{Participation: "participant"}
	writers := newPublishedWriterGenerations(pool, &kanamepg.Repository{}, &authzsnapshot.Store{})
	registration, recovery, err := loginHumanAdmissionStores(pool, mode, nil, writers)
	require.NoError(t, err)
	require.IsType(t, &publishedHumanAdmissionStore{}, registration)
	require.Same(t, registration, recovery)

	for name, sources := range map[string][]*publishedWriterGenerations{
		"empty source": {{}},
		"wrong pool":   {newPublishedWriterGenerations(&pgxpool.Pool{}, writers.repo, writers.store)},
		"two sources":  {writers, writers},
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := loginHumanAdmissionStores(pool, mode, nil, sources...)
			require.Error(t, err)
		})
	}
	_, _, err = loginHumanAdmissionStores(pool, config.AuthorityProtocolConfig{}, nil, writers)
	require.Error(t, err)
	// Отсутствующий источник сохраняет прежнюю явную проверку participant.
	_, _, err = loginHumanAdmissionStores(pool, mode, nil, nil)
	require.ErrorContains(t, err, "participant is absent")
	legacy, _, err := loginHumanAdmissionStores(pool, config.AuthorityProtocolConfig{}, nil, nil)
	require.NoError(t, err)
	require.IsType(t, &kanamepg.RegistrationStore{}, legacy)
}

func TestPublishedHumanAdmissionUnconfirmedFailsBeforeOpeningWriter(t *testing.T) {
	writers := newPublishedWriterGenerations(&pgxpool.Pool{}, &kanamepg.Repository{}, &authzsnapshot.Store{})
	store := &publishedHumanAdmissionStore{writers: writers}
	called := false
	body := func(context.Context, *kanamepg.RegistrationWriter) error { called = true; return nil }
	recoveryBody := func(context.Context, humansession.RecoveryCompletionWriter) error { called = true; return nil }
	for name, run := range map[string]func(context.Context) error{
		"registration writer": func(ctx context.Context) error { _, err := store.Writer(ctx); return err },
		"verification writer": func(ctx context.Context) error { _, err := store.VerificationWriter(ctx, "usr_fixture"); return err },
		"email change writer": func(ctx context.Context) error { _, err := store.EmailChangeWriter(ctx, "usr_fixture"); return err },
		"recovery writer": func(ctx context.Context) error {
			_, err := store.RecoveryCompletionWriter(ctx, "usr_fixture")
			return err
		},
		"identity writer": func(ctx context.Context) error {
			_, err := writers.IdentityLifecycleWriter(ctx, kaname.IdentityUpdate, "usr_fixture")
			return err
		},
		"registration attempt": func(ctx context.Context) error { return store.RunRegistrationWrite(ctx, body) },
		"verification attempt": func(ctx context.Context) error { return store.RunVerificationWrite(ctx, "usr_fixture", body) },
		"email change attempt": func(ctx context.Context) error { return store.RunEmailChangeWrite(ctx, "usr_fixture", body) },
		"recovery attempt": func(ctx context.Context) error {
			return store.RunRecoveryCompletionWrite(ctx, "usr_fixture", recoveryBody)
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := run(context.Background())
			require.ErrorIs(t, err, authzsnapshot.ErrUnconfirmed)
			require.ErrorIs(t, err, iamerr.ErrUnavailable)
			ctx, cancel := context.WithCancel(context.Background())
			cancel()
			require.ErrorIs(t, run(ctx), context.Canceled)
		})
	}
	require.False(t, called)
}

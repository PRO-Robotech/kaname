// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package registration_test

import (
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/stretchr/testify/require"
)

func TestFullRegistrationRequiresPreparedCapability(t *testing.T) {
	_, err := registration.NewRegisterUseCase(registration.Deps{RequirePreparedWrite: true, Store: &unitStore{}})
	require.ErrorContains(t, err, "prepared write capability required")
}

// Это контроль границы UC, а не доказательство PG retry: последнее отдельно
// исполняется через настоящий deferred COMMIT trigger в pg integration test.
type replayRegistrationStore struct {
	*unitStore
	inputs []registration.MirrorInput
}
type replayRegistrationWriter struct {
	registration.Writer
	store *replayRegistrationStore
}

func (w replayRegistrationWriter) Mirror(ctx context.Context, in registration.MirrorInput) (registration.MirrorResult, error) {
	w.store.inputs = append(w.store.inputs, in)
	out, err := w.Writer.Mirror(ctx, in)
	out.OwnerBindingID = "binding-once"
	return out, err
}
func (s *replayRegistrationStore) RunRegistrationWrite(ctx context.Context, body func(context.Context, registration.Writer) error) error {
	for attempt := 0; attempt < 2; attempt++ {
		w, err := s.Writer(ctx)
		if err != nil {
			return err
		}
		if err := body(ctx, replayRegistrationWriter{Writer: w, store: s}); err != nil {
			_ = w.Rollback(ctx)
			return err
		}
		if attempt == 0 {
			if err := w.Rollback(ctx); err != nil {
				return err
			}
			continue
		}
		return w.Commit(ctx)
	}
	return nil
}

type registrationOnceEffects struct{ charges, reconciles int }

func (e *registrationOnceEffects) ChargeSource(context.Context, humansession.SourceLane, string, time.Time, humansession.SourcePace) (bool, error) {
	e.charges++
	return true, nil
}
func (e *registrationOnceEffects) ReconcileBinding(context.Context, domain.AccessBindingID) error {
	e.reconciles++
	return nil
}

func TestPreparedRegistrationKeepsMaterialsAndPublishesOnce(t *testing.T) {
	rec := &recorder{}
	store := &replayRegistrationStore{unitStore: &unitStore{rec: rec}}
	inner, err := passwordverify.NewHasher(floorHasher())
	require.NoError(t, err)
	rule, err := humansession.NewPasswordRule(12, nil, humansession.NopObserver{}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	lane, ok := registration.LaneByName(registration.LanePassword)
	require.True(t, ok)
	obs := &unitObserver{}
	effects := &registrationOnceEffects{}
	clockReads := 0
	uc, err := registration.NewRegisterUseCase(registration.Deps{
		RequirePreparedWrite: true, Store: store, Rule: rule,
		Hasher: &recordingHasher{rec: rec, inner: inner}, Lane: lane,
		TTL: 24 * time.Hour, Observer: obs, Reconciler: effects,
		Now: func() time.Time { return unitBase }, Logger: slog.New(slog.DiscardHandler),
		CutoffClock: momentclock.Func(func() time.Time { clockReads++; return unitBase }),
		Letter:      unitLetterPace, Sources: effects, SourcePace: unitSourcePace,
	})
	require.NoError(t, err)
	out, err := uc.Execute(context.Background(), registration.Input{Email: "once@example.invalid", Password: goodPassword, Source: "203.0.113.7"})
	require.NoError(t, err)
	require.Len(t, store.writers, 2)
	require.Len(t, store.inputs, 2)
	require.Equal(t, store.inputs[0], store.inputs[1], "candidate identity принадлежит операции")
	first, second := store.writers[0], store.writers[1]
	require.Equal(t, first.sessions, second.sessions)
	require.Equal(t, first.codes, second.codes)
	require.Equal(t, first.letters, second.letters)
	require.Equal(t, second.sessions[0].ID, out.View.Session.ID)
	require.Equal(t, 1, obs.seen[registration.OutcomeIssued])
	require.Len(t, obs.seen, 1, "откаченная попытка не публикует наблюдение")
	require.Equal(t, 1, effects.charges)
	require.Equal(t, 1, effects.reconciles)
	require.Equal(t, 1, clockReads)
	hashes := 0
	for _, step := range rec.steps {
		if step == "hash" {
			hashes++
		}
	}
	require.Equal(t, 1, hashes)
}

func TestRegistrationPreservesTerminalWriteOutcome(t *testing.T) {
	exhausted := errors.Join(iamerr.ErrAborted, errors.New("private-schema-secret"))
	for name, failure := range map[string]error{
		"exhausted": exhausted,
		"cancel": errors.Join(exhausted, context.Canceled),
		"unknown-commit": errors.New("private-connection-secret"),
	} {
		t.Run(name, func(t *testing.T) {
			u := newUnit(t, func(store *unitStore) { store.commitErr = failure })
			_, err := u.register(t, "outcome@example.invalid")
			if name == "exhausted" {
				require.ErrorIs(t, err, iamerr.ErrAborted)
				require.EqualError(t, err, "aborted: " + iamerr.SerializationConflictSyncText)
				require.NotErrorIs(t, err, humansession.ErrStoreUnavailable)
			} else {
				require.ErrorIs(t, err, humansession.ErrStoreUnavailable)
				require.NotErrorIs(t, err, iamerr.ErrAborted)
			}
			require.NotContains(t, err.Error(), "private-")
			require.Len(t, u.store.writers, 1, "UC не исполняет собственный retry")
			require.Zero(t, u.obs.seen[registration.OutcomeIssued])
			require.Equal(t, 1, u.obs.seen[registration.OutcomeStoreFailed])
		})
	}
}

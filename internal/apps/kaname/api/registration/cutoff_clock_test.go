// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package registration_test

// cutoff_clock_test.go — регистрация ставит момент выдаваемой сессии ОБЩИМ
// источником, а не часами процесса своей реплики (задача kaname#589); отказ
// источника — закрытый отказ без следа.

import (
	"bytes"
	"context"
	"errors"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registration"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
)

// clockUnit — регистрация с раздельными часами процесса реплики (unitBase) и
// источником моментов clock.
func clockUnit(t *testing.T, clock revocationpolicy.Clock, logger *slog.Logger) *unit {
	t.Helper()
	rec := &recorder{}
	store := &unitStore{rec: rec}
	inner, err := passwordverify.NewHasher(floorHasher())
	require.NoError(t, err)
	rule, err := humansession.NewPasswordRule(12, nil, humansession.NopObserver{}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	lane, ok := registration.LaneByName(registration.LanePassword)
	require.True(t, ok)
	obs := &unitObserver{}
	uc, err := registration.NewRegisterUseCase(registration.Deps{
		Store: store, Rule: rule, Hasher: &recordingHasher{rec: rec, inner: inner}, Lane: lane,
		TTL: 24 * time.Hour, Observer: obs, Now: func() time.Time { return unitBase }, Logger: logger,
		Letter: unitLetterPace, Sources: admitEverySource{}, SourcePace: unitSourcePace,
		CutoffClock: clock,
	})
	require.NoError(t, err)
	return &unit{rec: rec, store: store, obs: obs, uc: uc}
}

// TestRegister_SessionMomentComesFromTheSharedSource — пара: общий источник
// (впереди часов реплики на 37 минут) — момент источника; инъекция «часы
// реплики» — момент реплики. Разные исходы пары и есть способность пробы
// различить источник.
func TestRegister_SessionMomentComesFromTheSharedSource(t *testing.T) {
	shared := unitBase.Add(37 * time.Minute)
	for name, c := range map[string]struct {
		clock revocationpolicy.Clock
		want  time.Time
	}{
		"проводка корня: общий источник": {momentclock.At(shared), shared},
		"инъекция: часы реплики":         {momentclock.At(unitBase), unitBase},
	} {
		t.Run(name, func(t *testing.T) {
			u := clockUnit(t, c.clock, slog.New(slog.DiscardHandler))
			_, err := u.register(t, "clock@example.invalid")
			require.NoError(t, err)
			require.Len(t, u.store.writers, 1)
			require.Len(t, u.store.writers[0].sessions, 1)
			got := u.store.writers[0].sessions[0].AuthenticatedAt
			require.Truef(t, got.Equal(c.want), "момент сессии %s, ожидался %s", got, c.want)
		})
	}
}

// TestRegister_UnansweredSourceRefusesBeforeAnyWrite — источник не ответил:
// фиксированный отказ «не выполнено», транзакция не открыта; журнал называет
// шаг и класс, не адрес и не текст причины.
func TestRegister_UnansweredSourceRefusesBeforeAnyWrite(t *testing.T) {
	var logBuf bytes.Buffer
	u := clockUnit(t, momentclock.Failing{Err: errors.New("dial tcp 10.0.0.9:5432 (user=kaname)")},
		slog.New(slog.NewTextHandler(&logBuf, nil)))
	_, err := u.uc.Execute(context.Background(), registration.Input{Email: "nobody@example.invalid", Password: goodPassword, Source: "203.0.113.7"})
	require.ErrorIs(t, err, humansession.ErrStoreUnavailable)
	require.Empty(t, u.store.writers, "транзакция регистрации не открыта")
	logged := logBuf.String()
	require.Contains(t, logged, "step=shared-moment")
	require.Contains(t, logged, "class=store")
	require.NotContains(t, logged, "nobody@example.invalid")
	require.NotContains(t, logged, "10.0.0.9")
}

// TestRegister_RefusesToBuildWithoutTheSource — без источника полоса не
// собирается.
func TestRegister_RefusesToBuildWithoutTheSource(t *testing.T) {
	inner, err := passwordverify.NewHasher(floorHasher())
	require.NoError(t, err)
	rule, err := humansession.NewPasswordRule(12, nil, humansession.NopObserver{}, slog.New(slog.DiscardHandler))
	require.NoError(t, err)
	lane, ok := registration.LaneByName(registration.LanePassword)
	require.True(t, ok)
	_, err = registration.NewRegisterUseCase(registration.Deps{
		Store: &unitStore{rec: &recorder{}}, Rule: rule, Hasher: inner, Lane: lane, TTL: time.Hour,
		Letter: unitLetterPace, Sources: admitEverySource{}, SourcePace: unitSourcePace,
	})
	require.ErrorContains(t, err, "shared clock required")
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// keystore_lifecycle_test.go — жизненный цикл ключа, достижимый оператором
// (#314): вывод из обращения, реакция на утечку, ротация до объявленного срока
// и наблюдаемость сметателя.
//
// # Что здесь судится, а что — в соседях
//
// Здесь — РЕШЕНИЯ ключницы на дублёре хранилища: когда подпись переходит к
// новому ключу, что остаётся в наборе, что считается уже сделанным. Условность
// передачи подписи под конкуренцией судит проба на настоящей базе
// (`internal/repo/kaname/pg/signing_key_lifecycle_integration_test.go`), а путь
// с поверхности оператора — проба команды (`cmd/kaname`).
package signingkeys_test

import (
	"bytes"
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/signingkeys"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
)

const (
	lifecycleLifetime = 48 * time.Hour
	lifecycleLead     = time.Hour
)

// lifecycleKeystore — ключница над дублёром с УПРАВЛЯЕМЫМИ часами: момент
// ротации есть функция времени, и без управляемых часов проба не различает
// «рано» и «пора».
func lifecycleKeystore(t *testing.T, store *memStore, clock *time.Time) *signingkeys.Keystore {
	t.Helper()
	wrapper, err := keywrap.New(bytes.Repeat([]byte{7}, keywrap.KeySize))
	require.NoError(t, err)
	ks, err := signingkeys.New(signingkeys.Config{
		Algorithm:    domain.SigningAlgES256,
		KeyLifetime:  lifecycleLifetime,
		RemovalGrace: tokenpolicy.KeyRemovalGrace,
		RotationLead: lifecycleLead,
		Clock:        func() time.Time { return *clock },
	}, store, store, wrapper)
	require.NoError(t, err)
	return ks
}

func activeKID(t *testing.T, store *memStore) domain.KeyID {
	t.Helper()
	rec, err := store.Active(context.Background())
	require.NoError(t, err, "подписывающий обязан существовать")
	return rec.KID
}

// ── Вывод из обращения ──────────────────────────────────────────────────────

// TestRetire_OfTheSignerHandsSigningOverAndKeepsTheKeyInTheSet — вывод
// подписывающего не оставляет службу без подписи: подпись переходит к новому
// ключу, выведенный остаётся в наборе на отсрочку.
func TestRetire_OfTheSignerHandsSigningOverAndKeepsTheKeyInTheSet(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(ctx))
	old := activeKID(t, store)

	out, err := ks.Retire(ctx, old, "oncall")
	require.NoError(t, err)
	require.Equal(t, old, out.KID)
	require.NotEmpty(t, out.Replacement, "подпись обязана перейти к новому ключу")
	require.NotEqual(t, old, out.Replacement)
	require.Equal(t, out.Replacement, activeKID(t, store))
	require.Equal(t, domain.SigningKeyRetired, store.rows[old].State)

	set, err := ks.PublishedSet(ctx)
	require.NoError(t, err)
	require.True(t, publishedContains(set, old), "выведенный остаётся в наборе всю отсрочку")
	require.True(t, publishedContains(set, out.Replacement))
}

// TestRetire_OfAPublishedKeyLeavesTheSignerAlone — законный близнец: ключ,
// который не подписывает, выводится без передачи подписи.
func TestRetire_OfAPublishedKeyLeavesTheSignerAlone(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(ctx))
	signer := activeKID(t, store)
	spare, err := ks.Generate(ctx)
	require.NoError(t, err)

	out, err := ks.Retire(ctx, spare.KID, "oncall")
	require.NoError(t, err)
	require.Empty(t, out.Replacement, "подпись не переходит, когда выводится не подписывающий")
	require.Equal(t, signer, activeKID(t, store))
	require.Equal(t, domain.SigningKeyRetired, store.rows[spare.KID].State)
}

// TestRetire_OfARetiredKeyIsAlreadyDone — повтор команды не отказ и не вторая
// ротация.
func TestRetire_OfARetiredKeyIsAlreadyDone(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(ctx))
	old := activeKID(t, store)
	_, err := ks.Retire(ctx, old, "oncall")
	require.NoError(t, err)
	generated := ks.Stats().Generated

	out, err := ks.Retire(ctx, old, "oncall")
	require.NoError(t, err)
	require.True(t, out.AlreadyDone)
	require.Equal(t, generated, ks.Stats().Generated, "повтор не порождает ключей")
}

// TestRetire_RequiresNamingWhoDecided — действие оператора не бывает анонимным.
func TestRetire_RequiresNamingWhoDecided(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(ctx))
	old := activeKID(t, store)

	_, err := ks.Retire(ctx, old, "  ")
	require.Error(t, err)
	require.Equal(t, old, activeKID(t, store), "отказ обязан наступить ДО перехода")
}

// ── Реакция на утечку ───────────────────────────────────────────────────────

// TestCompromise_OfTheSignerLeavesTheSetAndHandsSigningOver — утёкший
// подписывающий покидает набор, и подпись переходит к новому ключу.
func TestCompromise_OfTheSignerLeavesTheSetAndHandsSigningOver(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(ctx))
	leaked := activeKID(t, store)

	out, err := ks.Compromise(ctx, leaked, "oncall")
	require.NoError(t, err)
	require.NotEmpty(t, out.Replacement)
	require.NotEqual(t, leaked, out.Replacement)
	require.Equal(t, out.Replacement, activeKID(t, store))

	set, err := ks.PublishedSet(ctx)
	require.NoError(t, err)
	require.False(t, publishedContains(set, leaked), "утёкший покидает набор немедленно")
	require.True(t, publishedContains(set, out.Replacement))
	require.Equal(t, uint64(1), ks.Stats().Compromised)
}

// TestCompromise_OfANonSignerDoesNotRotate — законный близнец: утечка не
// подписывающего ключа подпись не трогает.
func TestCompromise_OfANonSignerDoesNotRotate(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(ctx))
	signer := activeKID(t, store)
	spare, err := ks.Generate(ctx)
	require.NoError(t, err)

	out, err := ks.Compromise(ctx, spare.KID, "oncall")
	require.NoError(t, err)
	require.Empty(t, out.Replacement)
	require.Equal(t, signer, activeKID(t, store))
}

// TestCompromise_WithoutAReplacementIsNamedAndTheRepeatRestoresTheSigner —
// частичный исход назван: ключ снят, замены нет. Повтор той же команды не
// отказывает на уже снятом ключе, а довершает замену.
func TestCompromise_WithoutAReplacementIsNamedAndTheRepeatRestoresTheSigner(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(ctx))
	leaked := activeKID(t, store)

	store.insertErr = errors.New("memstore: insert refused")
	out, err := ks.Compromise(ctx, leaked, "oncall")
	require.ErrorIs(t, err, signingkeys.ErrNoSignerAfterCompromise)
	require.Equal(t, domain.SigningKeyCompromised, store.rows[leaked].State,
		"снятие утёкшего не откатывается из-за того, что замена не удалась")
	require.Empty(t, out.Replacement)

	store.insertErr = nil
	out, err = ks.Compromise(ctx, leaked, "oncall")
	require.NoError(t, err)
	require.True(t, out.AlreadyDone)
	require.NotEmpty(t, out.Replacement, "повтор обязан довершить замену")
	require.Equal(t, out.Replacement, activeKID(t, store))
}

// ── Ротация до объявленного срока ───────────────────────────────────────────

// TestRotateIfDue_WaitsForTheLeadAndThenHandsSigningOver — объявленный срок
// ключа управляет подписью: до запаса ротации подпись не трогается, в нём —
// переходит к новому ключу раньше, чем срок наступит.
func TestRotateIfDue_WaitsForTheLeadAndThenHandsSigningOver(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	now := t0
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(ctx))
	first := activeKID(t, store)
	due := store.rows[first].NotAfter.Add(-lifecycleLead)

	now = due.Add(-time.Second)
	rotated, err := ks.RotateIfDue(ctx)
	require.NoError(t, err)
	require.False(t, rotated, "до запаса ротации подпись не трогается")
	require.Equal(t, first, activeKID(t, store))

	now = due
	rotated, err = ks.RotateIfDue(ctx)
	require.NoError(t, err)
	require.True(t, rotated, "в запасе ротации подпись обязана перейти к новому ключу")
	next := activeKID(t, store)
	require.NotEqual(t, first, next)
	require.True(t, now.Before(store.rows[first].NotAfter), "переход обязан случиться ДО объявленного срока")
	require.Equal(t, domain.SigningKeyRetired, store.rows[first].State, "прежний остаётся в наборе на отсрочку")
}

// TestRotateIfDue_LostRaceRetiresItsOwnKey — другая реплика успела сменить
// подписывающего: это не отказ, а порождённый проигравшим ключ не остаётся в
// наборе опубликованным навсегда.
func TestRotateIfDue_LostRaceRetiresItsOwnKey(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	now := t0
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(ctx))
	first := activeKID(t, store)
	now = store.rows[first].NotAfter.Add(-lifecycleLead)

	// Соседняя реплика сменяет подписывающего между чтением и передачей.
	winner := lifecycleKeystore(t, store, &now)
	store.beforeReplace = func() {
		store.beforeReplace = nil
		_, err := winner.Rotate(ctx)
		require.NoError(t, err)
	}

	rotated, err := ks.RotateIfDue(ctx)
	require.NoError(t, err, "проигранная гонка — не отказ")
	require.False(t, rotated)
	published := 0
	for _, r := range store.rows {
		if r.State == domain.SigningKeyPublished {
			published++
		}
	}
	require.Zero(t, published, "ключ проигравшего не остаётся опубликованным без будущего")
}

// TestNew_RefusesALifetimeWithinTheRotationLead — срок, не превышающий запас
// ротации, ротировал бы ключ на каждом проходе.
func TestNew_RefusesALifetimeWithinTheRotationLead(t *testing.T) {
	wrapper, err := keywrap.New(bytes.Repeat([]byte{7}, keywrap.KeySize))
	require.NoError(t, err)
	build := func(lifetime, lead time.Duration) error {
		store := newMemStore()
		_, err := signingkeys.New(signingkeys.Config{
			Algorithm:    domain.SigningAlgES256,
			KeyLifetime:  lifetime,
			RemovalGrace: tokenpolicy.KeyRemovalGrace,
			RotationLead: lead,
			Clock:        time.Now,
		}, store, store, wrapper)
		return err
	}
	require.Error(t, build(time.Hour, time.Hour), "срок, равный запасу, отвергается")
	require.Error(t, build(time.Hour, 0), "незаданный запас отвергается")
	require.NoError(t, build(2*time.Hour, time.Hour), "срок длиннее запаса принимается")
}

// ── Наблюдаемость сметателя ─────────────────────────────────────────────────

// TestSweepRemovable_CountsEveryCompletedPass — «сметатель прошёл и снимать
// было нечего» отличимо от «сметатель не ходит»: проход считается и с нулём
// снятых, а сорванный — нет.
func TestSweepRemovable_CountsEveryCompletedPass(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.Zero(t, ks.Stats().Sweeps, "до первого прохода — ноль")

	n, err := ks.SweepRemovable(ctx)
	require.NoError(t, err)
	require.Zero(t, n)
	require.Equal(t, uint64(1), ks.Stats().Sweeps, "проход с нулём снятых — всё равно проход")

	store.err = errors.New("memstore: unavailable")
	_, err = ks.SweepRemovable(ctx)
	require.Error(t, err)
	require.Equal(t, uint64(1), ks.Stats().Sweeps, "сорванный проход проходом не считается")
	require.NotZero(t, ks.Stats().Failures)
}

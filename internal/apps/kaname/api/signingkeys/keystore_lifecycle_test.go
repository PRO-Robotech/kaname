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
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/tokenpolicy"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/signingkeys"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
)

const (
	lifecycleLifetime = 48 * time.Hour
	lifecycleLead     = time.Hour
	// lifecycleHandoverLimit — предел пути «порождение → передача подписи»,
	// который ключница ставит сама.
	lifecycleHandoverLimit = 5 * time.Minute
	// lifecycleStrandedAfter — возраст опубликованного ключа, после которого
	// сметатель выводит его как застрявший.
	lifecycleStrandedAfter = 2 * lifecycleHandoverLimit
)

// lifecycleKeystore — ключница над дублёром с УПРАВЛЯЕМЫМИ часами: момент
// ротации есть функция времени, и без управляемых часов проба не различает
// «рано» и «пора».
func lifecycleKeystore(t *testing.T, store *memStore, clock *time.Time) *signingkeys.Keystore {
	t.Helper()
	wrapper, err := keywrap.New(bytes.Repeat([]byte{7}, keywrap.KeySize))
	require.NoError(t, err)
	ks, err := signingkeys.New(signingkeys.Config{
		Algorithm:     domain.SigningAlgES256,
		KeyLifetime:   lifecycleLifetime,
		RemovalGrace:  tokenpolicy.KeyRemovalGrace,
		RotationLead:  lifecycleLead,
		HandoverLimit: lifecycleHandoverLimit,
		StrandedAfter: lifecycleStrandedAfter,
		Clock:         func() time.Time { return *clock },
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

// TestCompromise_AnUnreadSignerIsNotReportedAsNoSigner — снятие состоялось,
// а чтение подписывающего отказало сбоем хранилища. «Подписывающего нет» при
// этом НЕ установлено — он есть, — и исход обязан это сказать, а не объявить
// службу неподписывающей. Близнец — TestCompromise_OfANonSignerDoesNotRotate:
// тот же ключ, то же снятие, чтение отвечает.
func TestCompromise_AnUnreadSignerIsNotReportedAsNoSigner(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(ctx))
	signer := activeKID(t, store)
	spare, err := ks.Generate(ctx)
	require.NoError(t, err)

	store.activeErr = errors.New("memstore: connection reset")
	out, err := ks.Compromise(ctx, spare.KID, "oncall")
	require.NotErrorIs(t, err, signingkeys.ErrNoSignerAfterCompromise,
		"сбой чтения — не «подписывающего нет»: подписывающий %s существует", signer)
	require.ErrorIs(t, err, signingkeys.ErrSignerUnknownAfterCompromise)
	require.Equal(t, domain.SigningKeyCompromised, store.rows[spare.KID].State, "снятие состоялось и не откатывается")
	require.Empty(t, out.Replacement)
	store.activeErr = nil
	require.Equal(t, signer, activeKID(t, store), "подпись не тронута")
}

// TestCompromise_ACallEndingDuringTheReplacementIsNotReportedAsNoSigner —
// снятие состоялось, а срок вызова кончился, пока заводилась замена. Исход
// замены при этом не установлен, и объявлять службу неподписывающей нечем.
// Близнец — TestCompromise_WithoutAReplacementIsNamedAndTheRepeatRestoresTheSigner:
// та же запись замены не удаётся, но вызов жив, — там частичный исход законен.
func TestCompromise_ACallEndingDuringTheReplacementIsNotReportedAsNoSigner(t *testing.T) {
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(context.Background()))
	leaked := activeKID(t, store)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store.beforeInsert = cancel
	out, err := ks.Compromise(ctx, leaked, "oncall")
	require.NotErrorIs(t, err, signingkeys.ErrNoSignerAfterCompromise,
		"срок вызова кончился посреди замены — «замены нет» не установлено")
	require.ErrorIs(t, err, signingkeys.ErrSignerUnknownAfterCompromise)
	require.Equal(t, domain.SigningKeyCompromised, store.rows[leaked].State, "снятие состоялось и не откатывается")
	require.Empty(t, out.Replacement)
}

// failActivationAfter — повышение замены отказывает так, как отказывает
// настоящее хранилище, когда подписывающим успел стать ЧУЖОЙ ключ: соседняя
// транзакция зафиксировала своё повышение, пока наше ждало её замка. Перед
// отказом исполняется `meanwhile` — то, что успело случиться у соседа.
func failActivationAfter(store *memStore, meanwhile func()) {
	store.beforeActivate = func() error {
		store.beforeActivate = nil
		meanwhile()
		return fmt.Errorf("%w: SigningKey already exists", iamerr.ErrAlreadyExists)
	}
}

// promoteElsewhere — соседняя реплика (старт с обеспечением подписывающего) либо
// второй оператор с тем же повтором поставили подписывающим свой ключ.
func promoteElsewhere(t *testing.T, store *memStore, kid domain.KeyID, at time.Time) {
	t.Helper()
	require.NoError(t, store.set(kid, domain.SigningKeyActive, &at, func(r *domain.SigningKeyRecord) { r.ActivatedAt = &at }))
}

// TestCompromise_AFailedReplacementUnderASignerPlacedElsewhereNamesThatSigner —
// утёкший ключ снят, замена этим вызовом не легла, потому что подписывающим
// успел стать ключ соседа. Служба при этом ПОДПИСЫВАЕТ, и исход обязан это
// сказать — назвать подписывающего, прочитанного после отказа, — а не объявить
// её неподписывающей по чтению, сделанному до неудавшейся записи. Законный
// близнец — TestCompromise_AFailedActivationUnderNoSignerIsPartial: тот же отказ
// повышения, но подписывающего никто не поставил.
func TestCompromise_AFailedReplacementUnderASignerPlacedElsewhereNamesThatSigner(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(ctx))
	leaked := activeKID(t, store)
	neighbour, err := ks.Generate(ctx)
	require.NoError(t, err)
	failActivationAfter(store, func() { promoteElsewhere(t, store, neighbour.KID, now) })

	out, err := ks.Compromise(ctx, leaked, "oncall")
	require.NotErrorIs(t, err, signingkeys.ErrNoSignerAfterCompromise,
		"подписывающий %s существует — «подписывающего нет» ложно", neighbour.KID)
	require.NoError(t, err, "служба подписывает: снятие состоялось, отказа по существу нет")
	require.Equal(t, neighbour.KID, out.Signer, "исход называет подписывающего, прочитанного ПОСЛЕ отказа замены")
	require.Empty(t, out.Replacement, "замена, заводимая этим вызовом, не легла")
	require.Equal(t, neighbour.KID, activeKID(t, store))
	require.Equal(t, domain.SigningKeyCompromised, store.rows[leaked].State, "снятие состоялось и не откатывается")
	for kid, r := range store.rows {
		require.NotEqualf(t, domain.SigningKeyPublished, r.State,
			"ключ %s, порождённый для не легшей замены, не остаётся опубликованным без будущего", kid)
	}
}

// TestCompromise_AFailedActivationUnderNoSignerIsPartial — законный близнец
// пробы выше, отличие в одном факте: повышение отказывает тем же отказом, а
// подписывающего не поставил никто. Отсутствие ПРОЧИТАНО после отказа — и
// частичный исход законен.
func TestCompromise_AFailedActivationUnderNoSignerIsPartial(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(ctx))
	leaked := activeKID(t, store)
	_, err := ks.Generate(ctx)
	require.NoError(t, err)
	failActivationAfter(store, func() {})

	out, err := ks.Compromise(ctx, leaked, "oncall")
	require.ErrorIs(t, err, signingkeys.ErrNoSignerAfterCompromise)
	require.Empty(t, out.Signer, "подписывающего нет — называть некого")
	require.Empty(t, out.Replacement)
	_, aerr := store.Active(ctx)
	require.ErrorIs(t, aerr, iamerr.ErrFailedPrecondition, "частичный исход: подписывающего действительно нет")
}

// TestCompromise_AFailedReplacementWhoseSignerCannotBeReadIsSignerUnknown —
// повышение замены отказало, а перечитать подписывающего не удалось: сбой
// хранилища на чтении. Подписывает ли служба, не установлено, и «подписывающего
// нет» было бы утверждением без основания. Близнец —
// TestCompromise_AFailedActivationUnderNoSignerIsPartial: то же, но чтение отвечает.
func TestCompromise_AFailedReplacementWhoseSignerCannotBeReadIsSignerUnknown(t *testing.T) {
	ctx := context.Background()
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(ctx))
	leaked := activeKID(t, store)
	_, err := ks.Generate(ctx)
	require.NoError(t, err)
	failActivationAfter(store, func() { store.activeErr = errors.New("memstore: connection reset") })

	out, err := ks.Compromise(ctx, leaked, "oncall")
	require.NotErrorIs(t, err, signingkeys.ErrNoSignerAfterCompromise,
		"подписывающий не прочитан — «подписывающего нет» не установлено")
	require.ErrorIs(t, err, signingkeys.ErrSignerUnknownAfterCompromise)
	require.ErrorContains(t, err, "connection reset", "причина чтения доезжает до вызывающего")
	require.Empty(t, out.Signer)
	require.Equal(t, domain.SigningKeyCompromised, store.rows[leaked].State, "снятие состоялось и не откатывается")
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
			Algorithm:     domain.SigningAlgES256,
			KeyLifetime:   lifetime,
			RemovalGrace:  tokenpolicy.KeyRemovalGrace,
			RotationLead:  lead,
			HandoverLimit: time.Minute,
			StrandedAfter: 2 * time.Minute,
			Clock:         time.Now,
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

// ── Передача, оборванная концом вызова, и застрявший ключ ───────────────────

func countPublished(store *memStore) int {
	n := 0
	for _, r := range store.rows {
		if r.State == domain.SigningKeyPublished {
			n++
		}
	}
	return n
}

// writeContext — каким был контекст записи В МОМЕНТ вызова.
type writeContext struct {
	seen        bool
	err         error
	deadline    time.Time
	hasDeadline bool
}

func recordWrites(store *memStore) map[string]*writeContext {
	seen := map[string]*writeContext{}
	store.onWrite = func(op string, ctx context.Context) {
		w := &writeContext{seen: true, err: ctx.Err()}
		w.deadline, w.hasDeadline = ctx.Deadline()
		seen[op] = w
	}
	return seen
}

// TestRotateIfDue_AHandOverEndedByTheCallStillRetiresTheKeyItGenerated — проход
// кончился (предел прохода, сигнал остановки), пока передача подписи ждала
// замка. Ключ, порождённый для неё, выводится ВСЁ РАВНО: под своим живым и
// ограниченным контекстом, а не под тем, чей конец и вызвал отказ, — иначе он
// навсегда оставался бы опубликованным и доверенным. Законный близнец —
// TestRotateIfDue_WaitsForTheLeadAndThenHandsSigningOver: тот же проход без
// оборванного вызова передаёт подпись.
func TestRotateIfDue_AHandOverEndedByTheCallStillRetiresTheKeyItGenerated(t *testing.T) {
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(context.Background()))
	first := activeKID(t, store)
	now = store.rows[first].NotAfter.Add(-lifecycleLead)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	store.beforeReplace = func() { store.beforeReplace = nil; cancel() }
	writes := recordWrites(store)

	rotated, err := ks.RotateIfDue(ctx)
	require.Error(t, err, "предпосылка: передача оборвана концом вызова")
	require.False(t, rotated)
	require.Len(t, store.rows, 2, "предпосылка: ключ для передачи порождён")
	require.Equal(t, first, activeKID(t, store), "оборванная передача не трогает подписывающего")
	require.Zero(t, countPublished(store),
		"ключ, порождённый для оборванной передачи, не остаётся опубликованным без будущего")

	retire := writes["Retire"]
	require.NotNil(t, retire, "порождённый ключ обязан выводиться")
	require.NoError(t, retire.err, "вывод идёт под живым контекстом, а не под оконченным вызовом")
	require.True(t, retire.hasDeadline, "и под своим сроком: вывод, ждущий вечно, держал бы остановку процесса")
}

// TestRotate_TheHandOverRunsUnderTheKeystoresOwnLimit — путь «порождение →
// передача» ограничен пределом САМОЙ ключницы, и тогда, когда у вызывающего
// предела нет (обеспечение подписывающего при старте). Это и делает
// застрявший ключ определимым: опубликованный ключ старше предела передачу
// уже не получит. Порождение идёт под тем же пределом, что передача: время
// порождения — отсчёт, от которого сметатель судит возраст.
func TestRotate_TheHandOverRunsUnderTheKeystoresOwnLimit(t *testing.T) {
	for _, tc := range []struct {
		name     string
		handOver string
		run      func(ks *signingkeys.Keystore, store *memStore, now *time.Time) error
	}{
		{"обеспечение подписывающего при старте", "Activate", func(ks *signingkeys.Keystore, _ *memStore, _ *time.Time) error {
			return ks.EnsureSigningKey(context.Background())
		}},
		{"ротация по сроку", "ReplaceActive", func(ks *signingkeys.Keystore, store *memStore, now *time.Time) error {
			*now = store.rows[activeKID(t, store)].NotAfter.Add(-lifecycleLead)
			_, err := ks.RotateIfDue(context.Background())
			return err
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
			store := newMemStore()
			ks := lifecycleKeystore(t, store, &now)
			if tc.handOver == "ReplaceActive" {
				require.NoError(t, ks.EnsureSigningKey(context.Background()))
			}
			writes := recordWrites(store)

			before := time.Now()
			require.NoError(t, tc.run(ks, store, &now))
			after := time.Now()

			insert, handOver := writes["Insert"], writes[tc.handOver]
			require.NotNil(t, insert, "предпосылка: ключ порождён")
			require.NotNil(t, handOver, "предпосылка: подпись передана")
			require.True(t, handOver.hasDeadline, "передача ограничена пределом ключницы и без предела вызывающего")
			require.False(t, handOver.deadline.Before(before.Add(lifecycleHandoverLimit)), "срок передачи — предел ключницы, а не короче")
			require.False(t, handOver.deadline.After(after.Add(lifecycleHandoverLimit)), "срок передачи — предел ключницы, а не длиннее")
			require.True(t, insert.hasDeadline)
			require.Equal(t, handOver.deadline, insert.deadline, "порождение и передача — под одним пределом")
		})
	}
}

// TestSweepRemovable_RetiresAPublishedKeyOnlyOnceItIsOlderThanAnyHandOver —
// передача, которую никто не довёл (процесс убит между порождением и передачей,
// вывод порождённого ключа отказал), доделывается сметателем: опубликованный
// ключ старше возраста застревания выводится. Младше — нет: его передача,
// возможно, ещё идёт, и вывод отнял бы у неё ключ.
func TestSweepRemovable_RetiresAPublishedKeyOnlyOnceItIsOlderThanAnyHandOver(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	now := t0
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(ctx))
	signer := activeKID(t, store)
	stranded, err := ks.Generate(ctx)
	require.NoError(t, err)
	retiredBefore := ks.Stats().Retired

	now = t0.Add(lifecycleStrandedAfter - time.Second)
	_, err = ks.SweepRemovable(ctx)
	require.NoError(t, err)
	require.Equal(t, domain.SigningKeyPublished, store.rows[stranded.KID].State,
		"ключ младше возраста застревания не трогается: его передача, возможно, ещё идёт")

	now = t0.Add(lifecycleStrandedAfter)
	n, err := ks.SweepRemovable(ctx)
	require.NoError(t, err)
	require.Zero(t, n, "застрявший ключ выводится, а не снимается: снятие — через отсрочку")
	got := store.rows[stranded.KID]
	require.Equal(t, domain.SigningKeyRetired, got.State, "застрявший ключ выводится сметателем")
	require.NotNil(t, got.RetiredAt)
	require.Equal(t, now, *got.RetiredAt, "отсрочка снятия отсчитывается от вывода")
	require.Equal(t, signer, activeKID(t, store), "вывод застрявшего не трогает подписывающего")
	require.Equal(t, retiredBefore+1, ks.Stats().Retired, "вывод застрявшего считается выводом")
	require.Zero(t, ks.Stats().Failures)
	require.Equal(t, uint64(2), ks.Stats().Sweeps)
}

// TestSweepRemovable_AStrandedKeyWhoseHandOverLandsMeanwhileKeepsSigning —
// вывод застрявшего условен так же, как всякий переход: если передача этому
// ключу легла между чтением набора и выводом, вывод получает невыполненное
// предусловие, ключ подписывает дальше, а проход не срывается и отказом не
// считается. Близнец — проба выше: без легшей передачи ключ выводится.
func TestSweepRemovable_AStrandedKeyWhoseHandOverLandsMeanwhileKeepsSigning(t *testing.T) {
	ctx := context.Background()
	t0 := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	now := t0
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(ctx))
	first := activeKID(t, store)
	late, err := ks.Generate(ctx)
	require.NoError(t, err)

	attempted := false
	store.beforeRetire = func(kid domain.KeyID) {
		if kid != late.KID {
			return
		}
		attempted = true
		require.NoError(t, store.ReplaceActive(ctx, late.KID, first, now))
	}
	now = t0.Add(lifecycleStrandedAfter)
	_, err = ks.SweepRemovable(ctx)
	require.True(t, attempted, "ключ старше возраста застревания сметатель обязан пытаться вывести")
	require.NoError(t, err, "проигранный вывод — не отказ прохода")
	require.Equal(t, late.KID, activeKID(t, store), "легшая передача не отменяется выводом")
	require.Zero(t, ks.Stats().Failures)
	require.Equal(t, uint64(1), ks.Stats().Sweeps)
}

// TestEnsureSigningKey_AHandOverOutlivingTheKeystoreLimitEndsNamedAndRetiresItsKey —
// у обеспечения подписывающего при старте своего предела нет, а передача
// зависла (хранилище не отвечает на повышение). Её кончает предел ключницы:
// отказ НАЗЫВАЕТ, что кончился именно он, — код состояния сервера об этом не
// говорит, — а порождённый ключ выведен, а не оставлен опубликованным.
// Законный близнец — TestRotate_TheHandOverRunsUnderTheKeystoresOwnLimit: та же
// передача без зависания ложится под тем же пределом.
func TestEnsureSigningKey_AHandOverOutlivingTheKeystoreLimitEndsNamedAndRetiresItsKey(t *testing.T) {
	const limit = 50 * time.Millisecond
	wrapper, err := keywrap.New(bytes.Repeat([]byte{7}, keywrap.KeySize))
	require.NoError(t, err)
	store := newMemStore()
	ks, err := signingkeys.New(signingkeys.Config{
		Algorithm:     domain.SigningAlgES256,
		KeyLifetime:   lifecycleLifetime,
		RemovalGrace:  tokenpolicy.KeyRemovalGrace,
		RotationLead:  lifecycleLead,
		HandoverLimit: limit,
		StrandedAfter: 2 * limit,
		Clock:         fixedClock(time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)),
	}, store, store, wrapper)
	require.NoError(t, err)
	// Повышение ждёт, пока его вызов не кончится: так выглядит зависшее хранилище.
	store.onWrite = func(op string, ctx context.Context) {
		if op == "Activate" {
			<-ctx.Done()
		}
	}

	err = ks.EnsureSigningKey(context.Background())
	require.Error(t, err)
	require.ErrorContains(t, err, "the hand-over limit "+limit.String()+" expired",
		"отказ называет, что кончился предел передачи ключницы")
	require.Len(t, store.rows, 1, "предпосылка: ключ для передачи порождён")
	require.Zero(t, countPublished(store), "ключ зависшей передачи выведен, а не оставлен опубликованным")
}

// TestRotateIfDue_AHandOverThatLandedDespiteItsRefusalIsNotACleanupFailure —
// передача ЛЕГЛА, а вызов получил отказ: фиксация дошла до сервера, ответ —
// нет. Вывод порождённого ключа после этого получает невыполненное
// предусловие — ключ подписывает, — и это не отказ ключницы: отказов ровно
// один, сам отказ передачи. Близнец —
// TestRotateIfDue_AHandOverEndedByTheCallStillRetiresTheKeyItGenerated: там
// передача не легла, и ключ выводится.
func TestRotateIfDue_AHandOverThatLandedDespiteItsRefusalIsNotACleanupFailure(t *testing.T) {
	now := time.Date(2026, 9, 22, 10, 0, 0, 0, time.UTC)
	store := newMemStore()
	ks := lifecycleKeystore(t, store, &now)
	require.NoError(t, ks.EnsureSigningKey(context.Background()))
	first := activeKID(t, store)
	now = store.rows[first].NotAfter.Add(-lifecycleLead)
	failuresBefore := ks.Stats().Failures

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	var landed domain.KeyID
	store.beforeReplace = func() {
		store.beforeReplace = nil
		for kid, r := range store.rows {
			if r.State == domain.SigningKeyPublished {
				landed = kid
			}
		}
		require.NoError(t, store.ReplaceActive(context.Background(), landed, first, now))
		cancel()
	}

	_, err := ks.RotateIfDue(ctx)
	require.Error(t, err, "предпосылка: вызов получил отказ")
	require.NotEmpty(t, landed, "предпосылка: передача легла")
	require.Equal(t, landed, activeKID(t, store), "легшая передача не отменяется выводом")
	require.Zero(t, countPublished(store))
	require.Equal(t, failuresBefore+1, ks.Stats().Failures, "отказ один — сама передача; вывод легшего ключа отказом не считается")
}

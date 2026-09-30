// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// rewrap_test.go — проход переобёртки секретов второго фактора (kaname#259
// п.3) над портами.
//
// Хранилище здесь — дублёр в памяти, но его замена исполняет ТОТ ЖЕ контракт,
// что оператор адаптера: материал сменяется, только пока он побайтово равен
// прочитанному. Проверяющий — настоящий (`totpverify`): исход переобёртки
// судится его сверкой, а не формой значения. Семантику базы — замок строки,
// повторную оценку условия под READ COMMITTED, откат — судят интеграционные
// пробы адаптера и команды.
package secondfactorwrap_test

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 в параметрах по умолчанию: оракул кода пробы
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/secondfactorwrap"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// ── проверяющие на перечнях ключей ─────────────────────────────────────────

func ring(t *testing.T, keys ...byte) *totpverify.Verifier {
	t.Helper()
	var list [][]byte
	for _, k := range keys {
		key := make([]byte, keywrap.KeySize)
		for i := range key {
			key[i] = k
		}
		list = append(list, key)
	}
	w, err := keywrap.New(list...)
	require.NoError(t, err)
	v, err := totpverify.New(w)
	require.NoError(t, err)
	return v
}

// Ключи пробы: прежний, новый и посторонний.
const (
	keyPrevious byte = 1
	keyCurrent  byte = 2
	keyStranger byte = 3
)

var probeAt = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

// codeOf — код RFC 6238 секрета на момент пробы: оракул пробы, не продукт.
func codeOf(t *testing.T, s totpverify.Secret) string {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s.Base32())
	require.NoError(t, err)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(totpverify.StepAt(probeAt))) // #nosec G115 -- шаг неотрицателен
	mac := hmac.New(sha1.New, raw)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

// opens — принимает ли проверяющий код секрета по хранимому материалу.
func opens(t *testing.T, v *totpverify.Verifier, stored domain.LoginVerifier, s totpverify.Secret) totpverify.Outcome {
	t.Helper()
	return v.Verify(stored, totpverify.NoAcceptedStep(), codeOf(t, s), probeAt).Outcome
}

// ── дублёр хранилища ────────────────────────────────────────────────────────

// memStore — строки `totp` по человеку. Замена — CAS по материалу, как у
// оператора адаптера; крючки ставят конкурента ПЕРЕД заменой.
type memStore struct {
	mu   sync.Mutex
	rows map[domain.UserID]domain.LoginMethod

	// beforeSwap — конкурент: зовётся перед каждой заменой с именем человека.
	beforeSwap func(user domain.UserID)
	// failSwapAfter — замена отказывает, когда успешных уже столько; <0 — никогда.
	failSwapAfter int
	failPage      error
	swaps, okSwap int
	// deadlines — сроки контекстов каждого вызова хранилища.
	deadlines  []time.Duration
	noDeadline int
}

func newMemStore() *memStore {
	return &memStore{rows: map[domain.UserID]domain.LoginMethod{}, failSwapAfter: -1}
}

func (s *memStore) note(ctx context.Context) {
	dl, ok := ctx.Deadline()
	if !ok {
		s.noDeadline++
		return
	}
	s.deadlines = append(s.deadlines, time.Until(dl))
}

func (s *memStore) put(m domain.LoginMethod) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.rows[m.UserID] = m
}

func (s *memStore) get(user domain.UserID) (domain.LoginMethod, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, ok := s.rows[user]
	return m, ok
}

func (s *memStore) TOTPSecretsAfter(ctx context.Context, after domain.UserID, limit int) ([]domain.LoginMethod, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note(ctx)
	if s.failPage != nil {
		return nil, s.failPage
	}
	ids := make([]string, 0, len(s.rows))
	for id := range s.rows {
		if string(id) > string(after) {
			ids = append(ids, string(id))
		}
	}
	sort.Strings(ids)
	if len(ids) > limit {
		ids = ids[:limit]
	}
	out := make([]domain.LoginMethod, 0, len(ids))
	for _, id := range ids {
		out = append(out, s.rows[domain.UserID(id)])
	}
	return out, nil
}

func (s *memStore) SwapTOTPSecret(ctx context.Context, user domain.UserID, prev, next domain.LoginVerifier) (bool, error) {
	if hook := s.beforeSwap; hook != nil {
		hook(user)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note(ctx)
	s.swaps++
	if s.failSwapAfter >= 0 && s.okSwap >= s.failSwapAfter {
		return false, iamerr.Wrapf(iamerr.ErrUnavailable, "LoginMethod.SwapTOTPSecret: connection reset")
	}
	m, ok := s.rows[user]
	if !ok || m.Verifier.Reveal() != prev.Reveal() {
		return false, nil
	}
	m.Verifier = next
	s.rows[user] = m
	s.okSwap++
	return true, nil
}

func (s *memStore) Get(ctx context.Context, user domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.note(ctx)
	m, ok := s.rows[user]
	if !ok || kind != domain.LoginMethodTOTP {
		return domain.LoginMethod{}, iamerr.Wrapf(iamerr.ErrNotFound, "Login method %s of user %s not found", kind, user)
	}
	return m, nil
}

// ── посев ───────────────────────────────────────────────────────────────────

type seeded struct {
	user   domain.UserID
	secret totpverify.Secret
}

// seed кладёт n строк `totp` под проверяющим by; чётные — подтверждённые,
// нечётные — заведения (`pending`): переобёртка не различает состояний.
func seed(t *testing.T, s *memStore, by *totpverify.Verifier, n int) []seeded {
	t.Helper()
	out := make([]seeded, 0, n)
	for i := 0; i < n; i++ {
		secret, err := totpverify.NewSecret()
		require.NoError(t, err)
		stored, err := by.Wrap(secret)
		require.NoError(t, err)
		state := domain.LoginMethodStateActive
		if i%2 == 1 {
			state = domain.LoginMethodStatePending
		}
		user := domain.UserID(fmt.Sprintf("usr%017d", i))
		s.put(domain.LoginMethod{UserID: user, Kind: domain.LoginMethodTOTP, Verifier: stored, State: state, CreatedAt: probeAt})
		out = append(out, seeded{user: user, secret: secret})
	}
	return out
}

func newUseCase(t *testing.T, s secondfactorwrap.Store, v secondfactorwrap.Rewrapper, batch int) *secondfactorwrap.UseCase {
	t.Helper()
	uc, err := secondfactorwrap.New(s, v, batch, 5*time.Second)
	require.NoError(t, err)
	return uc
}

// ── пробы ───────────────────────────────────────────────────────────────────

// TestRewrap_EverySecretMovesUnderTheFirstKeyAcrossPages — проход через три
// страницы переобёртывает каждый секрет прежнего ключа: после него один НОВЫЙ
// ключ открывает каждый, один ПРЕЖНИЙ — ни одного.
func TestRewrap_EverySecretMovesUnderTheFirstKeyAcrossPages(t *testing.T) {
	store := newMemStore()
	people := seed(t, store, ring(t, keyPrevious), 5)

	rep, err := newUseCase(t, store, ring(t, keyCurrent, keyPrevious), 2).Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, secondfactorwrap.Report{Rows: 5, Rewrapped: 5}, rep)
	require.True(t, rep.Settled())

	onlyCurrent, onlyPrevious := ring(t, keyCurrent), ring(t, keyPrevious)
	for _, p := range people {
		m, ok := store.get(p.user)
		require.True(t, ok)
		require.Equal(t, totpverify.OutcomeMatched, opens(t, onlyCurrent, m.Verifier, p.secret), "новый ключ открывает секрет %s", p.user)
		require.Equal(t, totpverify.OutcomeMaterialUnreadable, opens(t, onlyPrevious, m.Verifier, p.secret), "прежний ключ не читает секрет %s", p.user)
	}
}

// TestRewrap_RepeatWritesNothing — повтор прохода идемпотентен: всё уже под
// первым ключом, замен ноль, материал побайтово прежний.
func TestRewrap_RepeatWritesNothing(t *testing.T) {
	store := newMemStore()
	seed(t, store, ring(t, keyPrevious), 3)
	uc := newUseCase(t, store, ring(t, keyCurrent, keyPrevious), 2)
	_, err := uc.Run(context.Background())
	require.NoError(t, err)
	before := map[domain.UserID]string{}
	for id, m := range store.rows {
		before[id] = m.Verifier.Reveal()
	}
	swapsBefore := store.swaps

	rep, err := uc.Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, secondfactorwrap.Report{Rows: 3, Current: 3}, rep)
	require.Equal(t, swapsBefore, store.swaps, "повтор не пишет ничего")
	for id, m := range store.rows {
		require.Equal(t, before[id], m.Verifier.Reveal(), "материал %s тронут повтором", id)
	}
}

// TestRewrap_EmptyStoreIsNothingToDoNotAFailure — пустое хранилище — исход
// «строк 0» без отказа; отказ чтения — отказ, а не «строк 0».
func TestRewrap_EmptyStoreIsNothingToDoNotAFailure(t *testing.T) {
	store := newMemStore()
	rep, err := newUseCase(t, store, ring(t, keyCurrent), 2).Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, secondfactorwrap.Report{}, rep)
	require.True(t, rep.Settled())

	store.failPage = iamerr.Wrapf(iamerr.ErrUnavailable, "LoginMethod.TOTPSecretsAfter: connection refused")
	_, err = newUseCase(t, store, ring(t, keyCurrent), 2).Run(context.Background())
	require.ErrorIs(t, err, iamerr.ErrUnavailable, "не смог спросить — отказ, а не пустой проход")
	require.Contains(t, err.Error(), "connection refused")
}

// TestRewrap_ASecretReplacedDuringThePassIsNotOverwritten — служба заводит
// фактор заново, пока проход держит прежнее значение: замена не ложится
// (материал уже не тот), проход перечитывает строку и находит её под первым
// ключом. Секрет строки — НОВЫЙ: прежний не возвращается поверх.
func TestRewrap_ASecretReplacedDuringThePassIsNotOverwritten(t *testing.T) {
	store := newMemStore()
	people := seed(t, store, ring(t, keyPrevious), 3)
	service := ring(t, keyCurrent, keyPrevious)
	target := people[1]
	fresh, err := totpverify.NewSecret()
	require.NoError(t, err)
	var once sync.Once
	store.beforeSwap = func(user domain.UserID) {
		if user != target.user {
			return
		}
		once.Do(func() {
			stored, werr := service.Wrap(fresh)
			require.NoError(t, werr)
			m, _ := store.get(user)
			m.Verifier = stored
			store.put(m)
		})
	}

	rep, err := newUseCase(t, store, service, 2).Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, secondfactorwrap.Report{Rows: 3, Rewrapped: 2, Current: 1}, rep)

	m, _ := store.get(target.user)
	onlyCurrent := ring(t, keyCurrent)
	require.Equal(t, totpverify.OutcomeMatched, opens(t, onlyCurrent, m.Verifier, fresh), "секрет нового заведения цел")
	require.Equal(t, totpverify.OutcomeMismatched, opens(t, onlyCurrent, m.Verifier, target.secret), "прежний секрет не вернулся поверх нового")
}

// TestRewrap_AReplacementUnderThePreviousKeyIsRewrappedToo — близнец: новое
// значение положила реплика, у которой первым ещё стоит ПРЕЖНИЙ ключ. Проход
// перечитывает и переобёртывает уже его — секрет нового заведения, не прежний.
func TestRewrap_AReplacementUnderThePreviousKeyIsRewrappedToo(t *testing.T) {
	store := newMemStore()
	people := seed(t, store, ring(t, keyPrevious), 2)
	straggler := ring(t, keyPrevious)
	target := people[0]
	fresh, err := totpverify.NewSecret()
	require.NoError(t, err)
	var once sync.Once
	store.beforeSwap = func(user domain.UserID) {
		if user != target.user {
			return
		}
		once.Do(func() {
			stored, werr := straggler.Wrap(fresh)
			require.NoError(t, werr)
			m, _ := store.get(user)
			m.Verifier = stored
			store.put(m)
		})
	}

	rep, err := newUseCase(t, store, ring(t, keyCurrent, keyPrevious), 2).Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, secondfactorwrap.Report{Rows: 2, Rewrapped: 2}, rep)

	m, _ := store.get(target.user)
	require.Equal(t, totpverify.OutcomeMatched, opens(t, ring(t, keyCurrent), m.Verifier, fresh))
	require.Equal(t, totpverify.OutcomeMaterialUnreadable, opens(t, ring(t, keyPrevious), m.Verifier, fresh))
}

// TestRewrap_ARowRemovedDuringThePassIsNotResurrected — человек снял фактор,
// пока проход держал его строку: замена не ложится, строки нет — счёт
// «снято во время прохода», и строка не появляется снова.
func TestRewrap_ARowRemovedDuringThePassIsNotResurrected(t *testing.T) {
	store := newMemStore()
	people := seed(t, store, ring(t, keyPrevious), 3)
	target := people[2]
	store.beforeSwap = func(user domain.UserID) {
		if user == target.user {
			store.mu.Lock()
			delete(store.rows, user)
			store.mu.Unlock()
		}
	}

	rep, err := newUseCase(t, store, ring(t, keyCurrent, keyPrevious), 10).Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, secondfactorwrap.Report{Rows: 3, Rewrapped: 2, Vanished: 1}, rep)
	require.True(t, rep.Settled(), "снятая строка — исход, а не остаток")
	_, ok := store.get(target.user)
	require.False(t, ok, "снятая строка воскресла")
}

// TestRewrap_AnUnreadableSecretIsCountedAndLeftAlone — секрет, которого не
// открывает ни один ключ перечня, не трогается и считается отдельно: проход
// не «завершён» — прежние ключи снимать нельзя.
func TestRewrap_AnUnreadableSecretIsCountedAndLeftAlone(t *testing.T) {
	store := newMemStore()
	seed(t, store, ring(t, keyPrevious), 2)
	secret, err := totpverify.NewSecret()
	require.NoError(t, err)
	stored, err := ring(t, keyStranger).Wrap(secret)
	require.NoError(t, err)
	stranger := domain.UserID("usr99999999999999999")
	store.put(domain.LoginMethod{UserID: stranger, Kind: domain.LoginMethodTOTP, Verifier: stored, State: domain.LoginMethodStateActive, CreatedAt: probeAt})

	rep, err := newUseCase(t, store, ring(t, keyCurrent, keyPrevious), 2).Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, secondfactorwrap.Report{Rows: 3, Rewrapped: 2, Unreadable: 1}, rep)
	require.False(t, rep.Settled())
	m, _ := store.get(stranger)
	require.Equal(t, stored.Reveal(), m.Verifier.Reveal(), "нечитаемый материал не тронут")
}

// TestRewrap_AWriterThatKeepsReplacingIsUnsettledAfterTheBudget — строку,
// которую конкурент меняет перед КАЖДОЙ заменой, проход не держит вечно:
// после бюджета попыток она — остаток «не устоялось», и проход не завершён.
func TestRewrap_AWriterThatKeepsReplacingIsUnsettledAfterTheBudget(t *testing.T) {
	store := newMemStore()
	people := seed(t, store, ring(t, keyPrevious), 1)
	straggler := ring(t, keyPrevious)
	store.beforeSwap = func(user domain.UserID) {
		s, err := totpverify.NewSecret()
		require.NoError(t, err)
		stored, err := straggler.Wrap(s)
		require.NoError(t, err)
		m, _ := store.get(people[0].user)
		m.Verifier = stored
		store.put(m)
	}

	rep, err := newUseCase(t, store, ring(t, keyCurrent, keyPrevious), 2).Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, secondfactorwrap.Report{Rows: 1, Unsettled: 1}, rep)
	require.False(t, rep.Settled())
	require.Equal(t, secondfactorwrap.SwapAttempts, store.swaps, "попыток ровно бюджет")
}

// TestRewrap_AFailureMidwayLeavesEveryRowReadable — отказ хранилища посреди
// прохода: проход останавливается и называет сделанное; ни одна строка не
// остаётся без обёртки, которую открывает перечень, — переобёрнутые открывает
// новый ключ один, прочие прежний. Повтор довершает.
func TestRewrap_AFailureMidwayLeavesEveryRowReadable(t *testing.T) {
	store := newMemStore()
	people := seed(t, store, ring(t, keyPrevious), 5)
	store.failSwapAfter = 2
	uc := newUseCase(t, store, ring(t, keyCurrent, keyPrevious), 2)

	rep, err := uc.Run(context.Background())
	require.ErrorIs(t, err, iamerr.ErrUnavailable)
	require.Contains(t, err.Error(), "connection reset")
	require.Equal(t, 2, rep.Rewrapped, "сделанное до отказа названо")

	full, onlyCurrent, onlyPrevious := ring(t, keyCurrent, keyPrevious), ring(t, keyCurrent), ring(t, keyPrevious)
	var underCurrent, underPrevious int
	for _, p := range people {
		m, _ := store.get(p.user)
		require.Equal(t, totpverify.OutcomeMatched, opens(t, full, m.Verifier, p.secret), "строка %s без читаемой обёртки", p.user)
		if opens(t, onlyCurrent, m.Verifier, p.secret) == totpverify.OutcomeMatched {
			underCurrent++
		}
		if opens(t, onlyPrevious, m.Verifier, p.secret) == totpverify.OutcomeMatched {
			underPrevious++
		}
	}
	require.Equal(t, 2, underCurrent)
	require.Equal(t, 3, underPrevious)

	store.failSwapAfter = -1
	rep, err = uc.Run(context.Background())
	require.NoError(t, err)
	require.Equal(t, secondfactorwrap.Report{Rows: 5, Rewrapped: 3, Current: 2}, rep, "повтор довершает")
}

// TestRewrap_EveryStoreCallCarriesItsOwnDeadline — каждый вызов хранилища идёт
// под своим пределом, не длиннее объявленного, даже когда у вызывающего срока
// нет вовсе.
func TestRewrap_EveryStoreCallCarriesItsOwnDeadline(t *testing.T) {
	store := newMemStore()
	people := seed(t, store, ring(t, keyPrevious), 3)
	var once sync.Once
	store.beforeSwap = func(user domain.UserID) {
		if user != people[0].user {
			return
		}
		once.Do(func() { // один промах — ради перечитывания
			m, _ := store.get(user)
			stored, err := ring(t, keyCurrent).Wrap(people[0].secret)
			require.NoError(t, err)
			m.Verifier = stored
			store.put(m)
		})
	}
	const limit = 3 * time.Second
	uc, err := secondfactorwrap.New(store, ring(t, keyCurrent, keyPrevious), 2, limit)
	require.NoError(t, err)
	_, err = uc.Run(context.Background())
	require.NoError(t, err)

	require.Zero(t, store.noDeadline, "вызов хранилища без предела")
	// страницы: 2 (+1 пустая не нужна — вторая неполная) · замены: 3 · перечитывание: 1
	require.Len(t, store.deadlines, 6)
	for _, d := range store.deadlines {
		require.LessOrEqual(t, d, limit)
		require.Greater(t, d, time.Duration(0))
	}
}

// TestNew_RefusesAnIncompleteUseCase — без хранилища, проверяющего,
// положительного размера страницы и предела вызова проход не собирается.
func TestNew_RefusesAnIncompleteUseCase(t *testing.T) {
	store, v := newMemStore(), ring(t, keyCurrent)
	for name, build := range map[string]func() error{
		"нет хранилища":    func() error { _, err := secondfactorwrap.New(nil, v, 2, time.Second); return err },
		"нет проверяющего": func() error { _, err := secondfactorwrap.New(store, nil, 2, time.Second); return err },
		"страница 0":       func() error { _, err := secondfactorwrap.New(store, v, 0, time.Second); return err },
		"предел 0":         func() error { _, err := secondfactorwrap.New(store, v, 2, 0); return err },
	} {
		require.Error(t, build(), name)
	}
	_, err := secondfactorwrap.New(store, v, 2, time.Second)
	require.NoError(t, err, "положительный контроль")
}

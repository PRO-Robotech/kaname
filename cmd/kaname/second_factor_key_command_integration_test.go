// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// second_factor_key_command_integration_test.go — переобёртка секретов второго
// фактора, достижимая ОПЕРАТОРОМ (kaname#259 п.3): проба идёт СКВОЗЬ
// поверхность.
//
// Переобёртка подаётся командой процесса (`kaname second-factor-key rewrap`),
// тем же входом, что у оператора, над настоящей базой с цепочкой миграций. Исход
// судится не счётом команды, а СВЕРКОЙ: проверяющий кода по времени, собранный
// на перечне из ОДНОГО нового ключа, принимает код каждого секрета — «прежний
// ключ снят, и все секреты открываются», — а собранный на одном прежнем не
// открывает ни одного.
//
// Конкурент — служба: она заводит фактор заново тем же оператором базы, пока
// команда держит прежнее значение, и её значение обязано уцелеть.

import (
	"context"
	"crypto/hmac"
	"crypto/sha1" // #nosec G505 -- RFC 6238 в параметрах по умолчанию: оракул кода пробы
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"regexp"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/secondfactorwrap"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/keywrap"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/totpverify"
)

// Ключи пробы: прежний, новый.
const (
	sfPrevious byte = 0x11
	sfCurrent  byte = 0x22
)

var sfProbeAt = time.Date(2026, 9, 29, 12, 0, 0, 0, time.UTC)

// sfWorld — база с цепочкой миграций, посеянные люди и их секреты.
type sfWorld struct {
	dsn     string
	pool    *pgxpool.Pool
	repo    *kanamepg.LoginMethodRepo
	people  []domain.UserID
	secrets map[domain.UserID]totpverify.Secret
}

func sfVerifier(t *testing.T, ring ...byte) *totpverify.Verifier {
	t.Helper()
	keys := make([][]byte, 0, len(ring))
	for _, b := range ring {
		key := make([]byte, keywrap.KeySize)
		for i := range key {
			key[i] = b
		}
		keys = append(keys, key)
	}
	w, err := keywrap.New(keys...)
	require.NoError(t, err)
	v, err := totpverify.New(w)
	require.NoError(t, err)
	return v
}

// sfCode — код RFC 6238 секрета на момент пробы: оракул пробы, не продукт.
func sfCode(t *testing.T, s totpverify.Secret) string {
	t.Helper()
	raw, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(s.Base32())
	require.NoError(t, err)
	var msg [8]byte
	binary.BigEndian.PutUint64(msg[:], uint64(totpverify.StepAt(sfProbeAt))) // #nosec G115 -- шаг неотрицателен
	mac := hmac.New(sha1.New, raw)
	mac.Write(msg[:])
	sum := mac.Sum(nil)
	off := sum[len(sum)-1] & 0x0f
	bin := (uint32(sum[off])&0x7f)<<24 | uint32(sum[off+1])<<16 | uint32(sum[off+2])<<8 | uint32(sum[off+3])
	return fmt.Sprintf("%06d", bin%1000000)
}

// newSFWorld — n людей со строкой `totp` под прежним ключом: чётные —
// подтверждённые, нечётные — заведения.
func newSFWorld(t *testing.T, n int) *sfWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: нужен Postgres в контейнере")
	}
	ctx := context.Background()
	dsn := pgtest.WithSearchPath(pgtest.NewDB(t), "kaname,public")
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	w := &sfWorld{dsn: dsn, pool: pool, repo: kanamepg.NewLoginMethodRepo(pool), secrets: map[domain.UserID]totpverify.Secret{}}

	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `SET CONSTRAINTS ALL DEFERRED`)
	require.NoError(t, err)
	const account = "acc00000000000sfkey"
	for i := 0; i < n; i++ {
		id := domain.UserID(fmt.Sprintf("usr%017d", i))
		_, err = tx.Exec(ctx, `
			INSERT INTO users (id, external_id, email, display_name, account_id, invite_status)
			VALUES ($1, $2, $3, $4, $5, 'ACTIVE')`,
			string(id), fmt.Sprintf("ext-sfkey-%02d", i), fmt.Sprintf("sfkey-%02d@example.invalid", i), fmt.Sprintf("person %02d", i), account)
		require.NoError(t, err, "посев человека %d", i)
		w.people = append(w.people, id)
	}
	_, err = tx.Exec(ctx, `INSERT INTO accounts (id, name, owner_user_id) VALUES ($1, 'acc-sfkey', $2)`, account, string(w.people[0]))
	require.NoError(t, err)
	require.NoError(t, tx.Commit(ctx))

	previous := sfVerifier(t, sfPrevious)
	for i, id := range w.people {
		secret, err := totpverify.NewSecret()
		require.NoError(t, err)
		stored, err := previous.Wrap(secret)
		require.NoError(t, err)
		state := domain.LoginMethodStateActive
		if i%2 == 1 {
			state = domain.LoginMethodStatePending
		}
		_, err = w.repo.Create(ctx, domain.LoginMethod{UserID: id, Kind: domain.LoginMethodTOTP, Verifier: stored, State: state})
		require.NoError(t, err, "посев фактора %d", i)
		w.secrets[id] = secret
	}
	return w
}

// outcomeOf — исход сверки секрета человека проверяющим на перечне ring.
func (w *sfWorld) outcomeOf(t *testing.T, id domain.UserID, secret totpverify.Secret, ring ...byte) totpverify.Outcome {
	t.Helper()
	m, err := w.repo.Get(context.Background(), id, domain.LoginMethodTOTP)
	require.NoError(t, err)
	return sfVerifier(t, ring...).Verify(m.Verifier, totpverify.NoAcceptedStep(), sfCode(t, secret), sfProbeAt).Outcome
}

// sfCount — число из строки исхода команды по имени поля.
func sfCount(t *testing.T, out, field string) int {
	t.Helper()
	m := regexp.MustCompile(`(?:^|\s)` + field + `=(\d+)(?:\s|$)`).FindStringSubmatch(out)
	require.NotNil(t, m, "в выводе нет поля %s: %s", field, out)
	n, err := strconv.Atoi(m[1])
	require.NoError(t, err)
	return n
}

// TestSecondFactorKeyCommand_AfterTheRewrapThePreviousKeyLeavesTheListAndEverySecretOpens —
// предикат снятия kaname#259 п.3: после прохода перечень из одного нового
// ключа открывает КАЖДЫЙ секрет, прежний ключ один — ни одного; повтор с тем же
// перечнем не пишет ничего; прогон без прежнего ключа — «сделано», все секреты
// под первым.
func TestSecondFactorKeyCommand_AfterTheRewrapThePreviousKeyLeavesTheListAndEverySecretOpens(t *testing.T) {
	w := newSFWorld(t, 5)

	code, out := runSFKey(t, sfCommandCfgAt(w.dsn, sfCurrent, sfPrevious), "rewrap")
	require.Equal(t, secondFactorKeyExitDone, code, "вывод: %s", out)
	require.Contains(t, out, "outcome=done")
	require.Equal(t, 5, sfCount(t, out, "rows"))
	require.Equal(t, 5, sfCount(t, out, "rewrapped"))
	require.Equal(t, 2, sfCount(t, out, "keys"))

	for _, id := range w.people {
		require.Equal(t, totpverify.OutcomeMatched, w.outcomeOf(t, id, w.secrets[id], sfCurrent), "новый ключ один открывает секрет %s", id)
		require.Equal(t, totpverify.OutcomeMaterialUnreadable, w.outcomeOf(t, id, w.secrets[id], sfPrevious), "прежний ключ один читает секрет %s", id)
	}

	code, out = runSFKey(t, sfCommandCfgAt(w.dsn, sfCurrent, sfPrevious), "rewrap")
	require.Equal(t, secondFactorKeyExitDone, code, "повтор: %s", out)
	require.Equal(t, 0, sfCount(t, out, "rewrapped"), "повтор не пишет")
	require.Equal(t, 5, sfCount(t, out, "current"))

	code, out = runSFKey(t, sfCommandCfgAt(w.dsn, sfCurrent), "rewrap")
	require.Equal(t, secondFactorKeyExitDone, code, "прежний ключ снят из перечня: %s", out)
	require.Equal(t, 1, sfCount(t, out, "keys"))
	require.Equal(t, 5, sfCount(t, out, "current"))
	require.Equal(t, 0, sfCount(t, out, "unreadable"))
}

// TestSecondFactorKeyCommand_AKeyRemovedBeforeTheRewrapIsNamedAndNothingIsTouched —
// близнец с обратной стороны: прежний ключ снят из перечня ДО прохода. Команда
// не «переобёртывает» то, чего не открывает, — исход «не всё переехало», код 1,
// материал цел, и возвращённый в перечень ключ открывает каждый секрет.
func TestSecondFactorKeyCommand_AKeyRemovedBeforeTheRewrapIsNamedAndNothingIsTouched(t *testing.T) {
	w := newSFWorld(t, 3)

	code, out := runSFKey(t, sfCommandCfgAt(w.dsn, sfCurrent), "rewrap")
	require.Equal(t, secondFactorKeyExitPartial, code, "вывод: %s", out)
	require.Contains(t, out, "outcome=partial")
	require.Equal(t, 3, sfCount(t, out, "unreadable"))
	require.Equal(t, 0, sfCount(t, out, "rewrapped"))

	for _, id := range w.people {
		require.Equal(t, totpverify.OutcomeMatched, w.outcomeOf(t, id, w.secrets[id], sfPrevious), "секрет %s тронут", id)
	}
}

// TestSecondFactorKeyCommand_AnEnrollmentDuringThePassIsNotOverwritten — служба
// заводит фактор заново тем же оператором, пока команда держит прежнее
// значение: писатель держит строку, замена команды ждёт его замка, писатель
// фиксирует. Команда не кладёт переобёрнутый ПРЕЖНИЙ секрет поверх нового — она
// перечитывает строку и находит её под первым ключом.
func TestSecondFactorKeyCommand_AnEnrollmentDuringThePassIsNotOverwritten(t *testing.T) {
	w := newSFWorld(t, 4)
	ctx := context.Background()
	target := w.people[1] // заведение (`pending`) — его служба и заменяет
	fresh, err := totpverify.NewSecret()
	require.NoError(t, err)
	stored, err := sfVerifier(t, sfCurrent, sfPrevious).Wrap(fresh)
	require.NoError(t, err)

	writer, err := w.pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = writer.Rollback(ctx) }()
	_, err = writer.Exec(ctx, `UPDATE user_login_methods SET verifier = $2, created_at = now() WHERE user_id = $1 AND kind = 'totp'`,
		string(target), stored.Reveal())
	require.NoError(t, err)

	type result struct {
		code int
		out  string
	}
	done := make(chan result, 1)
	go func() {
		code, out := runSFKey(t, sfCommandCfgAt(w.dsn, sfCurrent, sfPrevious), "rewrap")
		done <- result{code, out}
	}()
	awaitLockWaiter(t, w.pool)
	require.NoError(t, writer.Commit(ctx))

	var got result
	select {
	case got = <-done:
	case <-time.After(30 * time.Second):
		t.Fatal("команда не вернулась после фиксации писателя")
	}
	require.Equal(t, secondFactorKeyExitDone, got.code, "вывод: %s", got.out)
	require.Equal(t, 3, sfCount(t, got.out, "rewrapped"))
	require.Equal(t, 1, sfCount(t, got.out, "current"), "строка писателя — под первым ключом")

	require.Equal(t, totpverify.OutcomeMatched, w.outcomeOf(t, target, fresh, sfCurrent), "секрет нового заведения цел")
	require.Equal(t, totpverify.OutcomeMismatched, w.outcomeOf(t, target, w.secrets[target], sfCurrent), "прежний секрет вернулся поверх нового")
}

// TestSecondFactorKeyCommand_TwoConcurrentPassesRewrapEachSecretOnce — два
// оператора гонят команду одновременно: каждая замена — CAS по прочитанному,
// поэтому каждый секрет переобёрнут ровно одной из них, а вторая находит его
// уже под первым ключом. Обе — «сделано».
func TestSecondFactorKeyCommand_TwoConcurrentPassesRewrapEachSecretOnce(t *testing.T) {
	const n = 8
	w := newSFWorld(t, n)
	var (
		wg    sync.WaitGroup
		codes [2]int
		outs  [2]string
	)
	for i := range codes {
		wg.Add(1)
		go func() {
			defer wg.Done()
			codes[i], outs[i] = runSFKey(t, sfCommandCfgAt(w.dsn, sfCurrent, sfPrevious), "rewrap")
		}()
	}
	wg.Wait()
	for i := range codes {
		require.Equal(t, secondFactorKeyExitDone, codes[i], "вывод: %s", outs[i])
	}
	rewrapped := sfCount(t, outs[0], "rewrapped") + sfCount(t, outs[1], "rewrapped")
	require.Equal(t, n, rewrapped, "каждый секрет переобёрнут ровно одним проходом: %v", outs)
	require.Equal(t, 2*n, rewrapped+sfCount(t, outs[0], "current")+sfCount(t, outs[1], "current"), "каждый проход видел каждую строку")
	for _, id := range w.people {
		require.Equal(t, totpverify.OutcomeMatched, w.outcomeOf(t, id, w.secrets[id], sfCurrent))
	}
}

// failingSwaps — адаптер хранилища, отказывающий в замене после after успешных:
// так выглядит обрыв связи посреди прохода. Прочие операторы — настоящие.
type failingSwaps struct {
	*kanamepg.LoginMethodRepo
	after int
	ok    int
}

func (f *failingSwaps) SwapTOTPSecret(ctx context.Context, user domain.UserID, prev, next domain.LoginVerifier) (bool, error) {
	if f.ok >= f.after {
		return false, iamerr.Wrapf(iamerr.ErrUnavailable, "LoginMethod.SwapTOTPSecret: connection reset")
	}
	swapped, err := f.LoginMethodRepo.SwapTOTPSecret(ctx, user, prev, next)
	if swapped {
		f.ok++
	}
	return swapped, err
}

// TestSecondFactorRewrap_AFailureMidwayLeavesEveryRowReadable — отказ связи
// посреди прохода над настоящей базой: каждая замена — свой оператор, поэтому
// ни одна строка не остаётся без обёртки, которую открывает перечень, —
// переобёрнутые до отказа открывает новый ключ один, прочие прежний. Команда
// после этого довершает.
func TestSecondFactorRewrap_AFailureMidwayLeavesEveryRowReadable(t *testing.T) {
	w := newSFWorld(t, 5)
	uc, err := secondfactorwrap.New(&failingSwaps{LoginMethodRepo: w.repo, after: 2},
		sfVerifier(t, sfCurrent, sfPrevious), secondFactorRewrapPage, secondFactorRewrapCallTimeout)
	require.NoError(t, err)
	rep, err := uc.Run(context.Background())
	require.ErrorIs(t, err, iamerr.ErrUnavailable)
	require.Equal(t, 2, rep.Rewrapped)

	var underCurrent, underPrevious int
	for _, id := range w.people {
		require.Equal(t, totpverify.OutcomeMatched, w.outcomeOf(t, id, w.secrets[id], sfCurrent, sfPrevious), "строка %s без читаемой обёртки", id)
		if w.outcomeOf(t, id, w.secrets[id], sfCurrent) == totpverify.OutcomeMatched {
			underCurrent++
		}
		if w.outcomeOf(t, id, w.secrets[id], sfPrevious) == totpverify.OutcomeMatched {
			underPrevious++
		}
	}
	require.Equal(t, 2, underCurrent)
	require.Equal(t, 3, underPrevious)

	code, out := runSFKey(t, sfCommandCfgAt(w.dsn, sfCurrent, sfPrevious), "rewrap")
	require.Equal(t, secondFactorKeyExitDone, code, "вывод: %s", out)
	require.Equal(t, 3, sfCount(t, out, "rewrapped"))
	require.Equal(t, 2, sfCount(t, out, "current"))
}

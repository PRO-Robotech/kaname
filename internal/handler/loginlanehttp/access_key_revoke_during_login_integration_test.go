// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// access_key_revoke_during_login_integration_test.go — снятие ключа доступа,
// зафиксированное ВНУТРИ входа этим ключом (Ф13-21, задача
// PRO-Robotech/kaname#669; приёмка
// `docs/engineering/acceptance/passwordless-login-with-access-key.md`,
// отпечаток 5fe6cca1…, Р8, Р15).
//
// # Что наблюдается
//
// Вход ключом читает строку ключа и сдвигает его счётчик СВОЕЙ транзакцией, а
// сессию выдаёт другой. Снятие, зафиксированное между ними, гасит все записи
// сессии человека и ставит отсечку ниже первой аутентификации; запись,
// выданная ПОСЛЕ него, ни тем, ни другим не задета. Свойство Р8 держится,
// только если транзакция выдачи сама судит, есть ли ещё ключ, после замка
// личности — механизмом базы, а не прочитанным раньше.
//
// Чередование ставится швом порта входа (`AccessKeyLoginStore`): сдвиг счётчика
// отвечает настоящим адаптером, и, пока ответ не вернулся во вход, НАСТОЯЩИЙ
// глагол снятия исполняется до терминальной операции. Встречное действие идёт
// в горутине обработчика входа, поэтому оно не зовёт `t`: исход кладётся в
// переменную и судится после ответа.
//
// # Близнецы
//
// Каждый отличается ОДНИМ фактом от красной пробы: (а) тот же шов без снятия —
// вход выдаёт годную сессию; (б) снятие ДРУГОГО человека в том же окне — вход
// выдаёт годную сессию (снятие гасит сессии своего человека, а не всякий вход).
package loginlanehttp_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/handler/loginlanehttp"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/webauthnverify/webauthntest"
)

// afterAdvanceKeys — порт входа ключом, у которого после ЗАФИКСИРОВАННОГО
// сдвига счётчика один раз исполняется встречное действие.
type afterAdvanceKeys struct {
	humansession.AccessKeyLoginStore
	after atomic.Pointer[func()]
	calls atomic.Int64
}

func (k *afterAdvanceKeys) AdvanceSignCount(ctx context.Context, id domain.AccessKeyID, expected, reported uint32, usedAt time.Time) (bool, error) {
	advanced, err := k.AccessKeyLoginStore.AdvanceSignCount(ctx, id, expected, reported, usedAt)
	k.calls.Add(1)
	if f := k.after.Swap(nil); f != nil && advanced && err == nil {
		(*f)()
	}
	return advanced, err
}

// laneWithAdvanceSeam — стенд, у которого вход ключом идёт через шов.
func laneWithAdvanceSeam(t *testing.T) (*sessionLane, *afterAdvanceKeys) {
	t.Helper()
	seam := &afterAdvanceKeys{}
	h := newSessionLaneWith(t, sessionLaneOptions{akKeys: func(inner humansession.AccessKeyLoginStore) humansession.AccessKeyLoginStore {
		seam.AccessKeyLoginStore = inner
		return seam
	}})
	return h, seam
}

// revokeVerb — НАСТОЯЩИЙ глагол снятия над адаптерами базы, исполняемый без
// `t`: синхронный отказ и отказ операции возвращаются ошибкой.
func revokeVerb(t *testing.T, h *sessionLane) func(user domain.UserID, keyID domain.AccessKeyID) error {
	t.Helper()
	ops := operations.NewRepo(h.pool, "kaname")
	uc, err := access_keys.NewRevokeUseCase(access_keys.Deps{
		Store:           kanamepg.NewAccessKeyRepo(h.pool),
		Freshness:       kanamepg.NewHumanSessionFreshness(h.pool),
		Methods:         kanamepg.NewLoginMethodRepo(h.pool),
		Binding:         laneKeyBinding(),
		FreshnessWindow: laneFreshness,
		Now:             time.Now,
	}, ops)
	require.NoError(t, err)
	return func(user domain.UserID, keyID domain.AccessKeyID) error {
		op, err := uc.Execute(h.ctx, access_keys.RevokeInput{UserID: user, Actor: user, AccessKeyID: string(keyID)})
		if err != nil {
			return fmt.Errorf("снятие отвергнуто синхронно: %w", err)
		}
		waitCtx, cancel := context.WithTimeout(h.ctx, 20*time.Second)
		defer cancel()
		if err := operations.Wait(waitCtx); err != nil {
			return fmt.Errorf("исполнитель операций не завершил очередь: %w", err)
		}
		got, err := ops.Get(h.ctx, op.ID)
		switch {
		case err != nil:
			return fmt.Errorf("операция %s не прочитана: %w", op.ID, err)
		case !got.Done:
			return fmt.Errorf("операция %s не терминальна", op.ID)
		case got.Error != nil:
			return fmt.Errorf("операция %s отказала: %v", op.ID, got.Error)
		}
		return nil
	}
}

// firedResult — исход встречного действия шва; шов не сработал — «условие не
// создано», а не исход пробы.
func firedResult(t *testing.T, res <-chan error, seam *afterAdvanceKeys) error {
	t.Helper()
	select {
	case err := <-res:
		return err
	default:
		require.FailNowf(t, "условие не создано", "встречное действие не исполнилось (сдвиг счётчика вызван %d раз)", seam.calls.Load())
		return nil
	}
}

// liveSessions — число живых записей сессии человека.
func (h *sessionLane) liveSessions(t *testing.T, user domain.UserID) int {
	t.Helper()
	var n int
	require.NoError(t, h.pool.QueryRow(h.ctx,
		`SELECT count(*) FROM human_sessions WHERE user_id = $1 AND ended_at IS NULL AND expires_at > now()`,
		string(user)).Scan(&n))
	return n
}

// keyExists — лежит ли строка ключа.
func (h *sessionLane) keyExists(t *testing.T, id domain.AccessKeyID) bool {
	t.Helper()
	var n int
	require.NoError(t, h.pool.QueryRow(h.ctx, `SELECT count(*) FROM user_access_keys WHERE id = $1`, string(id)).Scan(&n))
	return n == 1
}

// TestF13_21_RevokeCommittedInsideTheLoginLeavesNoSession — красная до фикса:
// снятие ключа зафиксировано между сдвигом счётчика и выдачей входа этим
// ключом; вход обязан отказать единым отказом (Р15 «снятый ключ и удостоверения
// не было — одно состояние»), и живых записей у человека не остаётся.
func TestF13_21_RevokeCommittedInsideTheLoginLeavesNoSession(t *testing.T) {
	h, seam := laneWithAdvanceSeam(t)
	revoke := revokeVerb(t, h)
	kA := givenAcceptedKey(t, h, h.user.ID)
	h.login(t, integrationPassword)
	require.Positive(t, h.liveSessions(t, h.user.ID), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: у человека есть живые сессии до снятия")

	res := make(chan error, 1)
	f := func() { res <- revoke(h.user.ID, kA.id) }
	seam.after.Store(&f)

	form := givenAKForm(t, h)
	ch := givenChallenge(t, h, form)
	r := akLoginWith(t, h, form, kA, ch, webauthntest.AssertionOptions{})

	require.NoError(t, firedResult(t, res, seam), "условие не создано: снятие ключа не исполнено")
	require.False(t, h.keyExists(t, kA.id), "условие не создано: строка ключа после снятия лежит")

	require.Equalf(t, http.StatusUnauthorized, r.status,
		"Ф13-21/Р8: вход ключом, снятым до выдачи, выдал сессию: %s", r.body)
	require.Zero(t, h.liveSessions(t, h.user.ID),
		"Ф13-21/Р8: после снятия ключа у человека осталась живая сессия, выданная снятым ключом")
	if ck := cookieNamed(r.cookies, loginlanehttp.CookieSession); ck != nil {
		require.False(t, h.resolve(t, ck.Value).GetFound(), "Ф13-21: носитель, выданный снятым ключом, отвергается")
	}
}

// TestF13_21_TwinSameSeamWithoutRevokeIssuesALiveSession — близнец (а): тот
// же шов и то же чередование без снятия — вход выдаёт годную сессию.
func TestF13_21_TwinSameSeamWithoutRevokeIssuesALiveSession(t *testing.T) {
	h, seam := laneWithAdvanceSeam(t)
	kA := givenAcceptedKey(t, h, h.user.ID)
	res := make(chan error, 1)
	f := func() { res <- nil }
	seam.after.Store(&f)

	bearer := keySession(t, h, kA)

	require.NoError(t, firedResult(t, res, seam), "ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: шов сработал")
	require.True(t, h.resolve(t, bearer).GetFound(), "близнец (а): сессия, выданная ключом без снятия, годна")
	require.True(t, h.keyExists(t, kA.id))
}

// TestF13_21_TwinRevokeOfAnotherPersonInsideTheLoginKeepsTheSession —
// близнец (б): в то же окно снят ключ ДРУГОГО человека — вход выдаёт годную
// сессию: проверка ключа в выдаче судит свой ключ, а не всякое снятие.
func TestF13_21_TwinRevokeOfAnotherPersonInsideTheLoginKeepsTheSession(t *testing.T) {
	h, seam := laneWithAdvanceSeam(t)
	revoke := revokeVerb(t, h)
	kA := givenAcceptedKey(t, h, h.user.ID)
	other := registerPerson(t, h, "ak-during-other")
	kOther := givenAcceptedKey(t, h, other)

	res := make(chan error, 1)
	f := func() { res <- revoke(other, kOther.id) }
	seam.after.Store(&f)

	bearer := keySession(t, h, kA)

	require.NoError(t, firedResult(t, res, seam), "условие не создано: снятие ключа другого не исполнено")
	require.False(t, h.keyExists(t, kOther.id))
	require.True(t, h.resolve(t, bearer).GetFound(), "близнец (б): снятие чужого ключа вход этим ключом не гасит")
}

// akRequest — запрос формы входа без `t`: для горутин конкурентной пробы.
func akRequest(h *sessionLane, f akForm, k akKey, as webauthntest.Assertion) (int, error) {
	b, err := json.Marshal(map[string]any{"csrfToken": f.login, "credential": credentialBody(as, k.handle)})
	if err != nil {
		return 0, err
	}
	req, err := http.NewRequestWithContext(h.ctx, http.MethodPost, h.lane.srv.URL+akPathLogin, bytes.NewReader(b))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range fwd() {
		req.Header.Set(k, v)
	}
	req.AddCookie(f.cookie)
	resp, err := h.c.Do(req)
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()
	_, _ = io.Copy(io.Discard, resp.Body)
	return resp.StatusCode, nil
}

// TestF13_21_ConcurrentLoginsAndRevokeLeaveNoLiveSession — конкурентная проба
// спорного пути: N входов ключом K параллельно со снятием K. После того как
// снятие зафиксировано и все входы ответили, живых записей у человека ноль:
// каждый вход либо выдан до замка снятия (и снят им), либо отказан.
func TestF13_21_ConcurrentLoginsAndRevokeLeaveNoLiveSession(t *testing.T) {
	const logins = 8
	h := newSessionLane(t)
	revoke := revokeVerb(t, h)
	k := givenAcceptedKey(t, h, h.user.ID)
	zero := uint32(0)

	type prepared struct {
		form akForm
		as   webauthntest.Assertion
	}
	ready := make([]prepared, logins)
	for i := range ready {
		f := givenAKForm(t, h)
		ch := givenChallenge(t, h, f)
		// Счётчик ноль — сдвиг «0 → 0» не судится (Ф7-19): входы не
		// проигрывают друг другу условие на прежнее значение, и спор идёт
		// только со снятием.
		ready[i] = prepared{form: f, as: assertOver(t, k, ch, webauthntest.AssertionOptions{SignCount: &zero})}
	}

	var (
		wg       sync.WaitGroup
		start    = make(chan struct{})
		statuses = make([]int, logins)
		errs     = make([]error, logins+1)
	)
	for i := range ready {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			<-start
			statuses[i], errs[i] = akRequest(h, ready[i].form, k, ready[i].as)
		}(i)
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		<-start
		errs[logins] = revoke(h.user.ID, k.id)
	}()
	close(start)
	wg.Wait()

	require.NoError(t, errors.Join(errs...), "условие не создано: запрос входа или снятие не исполнены")
	issued := 0
	for _, s := range statuses {
		require.Containsf(t, []int{http.StatusOK, http.StatusUnauthorized}, s, "исход входа вне двух законных: %d", s)
		if s == http.StatusOK {
			issued++
		}
	}
	t.Logf("входов %d · выдано %d · отказано %d", logins, issued, logins-issued)
	require.False(t, h.keyExists(t, k.id), "условие не создано: строка ключа после снятия лежит")
	require.Zero(t, h.liveSessions(t, h.user.ID),
		"Ф13-21/Р8: после снятия ключа и ответа всех входов у человека осталась живая сессия")
}

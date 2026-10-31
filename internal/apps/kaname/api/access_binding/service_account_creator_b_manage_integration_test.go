// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// service_account_creator_b_manage_integration_test.go — группа B приёмки
// `service-account-creation-is-its-own-right.md` (PRO-Robotech/kaname#1003):
// создатель заводит и ведёт СВОИ учётки (SAC-10…SAC-16). Мир — `newSACWorld`;
// глаголы учётки и ключа — только через дверь мира.

import (
	"fmt"
	"sort"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// sac10 — «Дано» SAC-10: G выполнена, sva-iss создал sva-cr1 (тело U). Отдаёт
// id выдачи и id учётки.
func (w *sacWorld) sac10(sc string) (bc, cr1 string) {
	w.t.Helper()
	bc = w.grantC(sc+" Дано: G", w.svaIss)
	cr1 = w.createSADone(asSA(w.ctx, w.svaIss), string(w.accA), "cr-1", sc+" Дано: sva-iss создаёт sva-cr1 (тело U)")
	return bc, cr1
}

// untilDoorPasses — первый шаг ведения идёт в окне материализации: повтор, пока
// дверь не пропустит, не дольше окна опроса (30 с, SAC-12 «Тогда»).
func untilDoorPasses(t *testing.T, what string, try func() error) {
	t.Helper()
	deadline := time.Now().Add(30 * time.Second)
	var last error
	for {
		if last = try(); last == nil {
			return
		}
		if time.Now().After(deadline) {
			break
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatalf("%s: дверь за 30 с не пропустила (последний отказ: %v)", what, last)
}

// SAC-10 — создатель заводит учётку в аккаунте выдачи.
func TestServiceAccountCreator_SAC10_CreatorCreatesAnAccountWhereHeHoldsTheRole(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-10")
	w.grantC("SAC-10 Дано: G", w.svaIss)

	o := w.saCreate(asSA(w.ctx, w.svaIss), string(w.accA), "cr-1")
	requireSACDone(t, o, "SAC-10: sva-iss создаёт учётку (тело U)")
	cr1 := w.createdSAID(o)
	got, err := w.saGet(asUser(w.ctx, w.usrA), cr1)
	require.NoError(t, err, "SAC-10: Get sva-cr1 от usr-A")
	require.Equal(t, string(w.accA), got.GetAccountId(), "SAC-10: accountId")
	require.Equal(t, "cr-1", got.GetName(), "SAC-10: name")
	require.True(t, got.GetEnabled(), "SAC-10: enabled")
	require.Equal(t, 1, w.auditCountFor("iam.service_account.created", cr1, w.svaIss),
		"SAC-10: строка аудита iam.service_account.created с actor = sva-iss")
}

// auditCountFor — строк аудита данного типа по объекту с данным `actor`.
func (w *sacWorld) auditCountFor(eventType, resourceID, actor string) int {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `
		SELECT count(*) FROM kaname.audit_outbox
		 WHERE event_type = $1 AND event_payload->>'resource_id' = $2 AND event_payload->>'actor' = $3`,
		eventType, resourceID, actor).Scan(&n))
	return n
}

// SAC-11 — создаёт только там, где держит роль создателя.
func TestServiceAccountCreator_SAC11_CreatesOnlyWhereHeHoldsTheRole(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-11")
	w.grantC("SAC-11 Дано: G", w.svaIss)
	saaReq := w.gC(w.svaAdm)
	saaReq.RoleId = string(w.rolSAA)
	w.createDoneX(asUser(w.ctx, w.usrA), saaReq, "SAC-11 Дано: выдача SAA учётке sva-adm")
	w.pollRelation("service_account:"+w.svaAdm, "v_update", sacSAModelType+":"+w.svaA, true,
		"SAC-11 контроль: sva-adm ведёт учётки acc-A по SAA")

	beforeA, beforeB := w.saCensus(w.accA), w.saCensus(w.accB)
	requireSACDenied(t, w.saCreate(asSA(w.ctx, w.svaIss), string(w.accB), "cr-1"), "SAC-11 a: sva-iss в acc-B")
	requireSACDenied(t, w.saCreate(asSA(w.ctx, w.svaIss2), string(w.accA), "cr-1"), "SAC-11 b: sva-iss2 без выдачи")
	requireSACDenied(t, w.saCreate(asSA(w.ctx, w.svaAdm), string(w.accA), "cr-1"), "SAC-11 c: sva-adm с SAA")
	require.Equal(t, beforeA, w.saCensus(w.accA), "SAC-11: учёток acc-A до = после")
	require.Equal(t, beforeB, w.saCensus(w.accB), "SAC-11: учёток acc-B до = после")
	// Близнец — SAC-10: тот же вызов от sva-iss в acc-A.
	w.createSADone(asSA(w.ctx, w.svaIss), string(w.accA), "cr-1", "SAC-11 (близнец): sva-iss в acc-A")
}

// SAC-12 — создатель ведёт созданную учётку весь цикл.
func TestServiceAccountCreator_SAC12_CreatorManagesHisAccountTheWholeCycle(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-12")
	_, cr1 := w.sac10("SAC-12")
	iss := asSA(w.ctx, w.svaIss)

	// 1) Get — в окне материализации.
	untilDoorPasses(t, "SAC-12 шаг 1: Get sva-cr1 от sva-iss", func() error {
		_, err := w.saGet(iss, cr1)
		return err
	})
	got, err := w.saGet(iss, cr1)
	require.NoError(t, err, "SAC-12 шаг 1")
	require.Equal(t, cr1, got.GetId(), "SAC-12 шаг 1: тело sva-cr1")
	// Ведение — глаголами, без яруса (Р2 п.3: «ярус на учётках не
	// материализуется»): сверх таблицы сценария, чтобы проба различала «глаголы
	// на своей учётке» и «ярус на ней».
	for _, r := range []string{"viewer", "editor", "admin"} {
		w.requireRelation("service_account:"+w.svaIss, r, sacSAModelType+":"+cr1, false,
			"SAC-12: у создателя на своей учётке нет яруса "+r)
	}
	// 2) два ключа.
	o := w.keyIssue(iss, cr1)
	requireSACDone(t, o, "SAC-12 шаг 2: K1")
	k1 := w.issuedKeyID(o)
	o = w.keyIssue(iss, cr1)
	requireSACDone(t, o, "SAC-12 шаг 2: K2")
	k2 := w.issuedKeyID(o)
	require.NotEqual(t, k1, k2, "SAC-12 шаг 2: keyId различны")
	// 3) список ключей.
	keys, err := w.keyList(iss, cr1)
	require.NoError(t, err, "SAC-12 шаг 3")
	sort.Strings(keys)
	want := []string{k1, k2}
	sort.Strings(want)
	require.Equal(t, want, keys, "SAC-12 шаг 3: ключи K1 и K2")
	// 4) отзыв K1.
	requireSACDone(t, w.keyRevoke(iss, cr1, k1), "SAC-12 шаг 4: отзыв K1")
	keys, err = w.keyList(iss, cr1)
	require.NoError(t, err, "SAC-12 шаг 4: список")
	require.Equal(t, []string{k2}, keys, "SAC-12 шаг 4: остался K2")
	// 5) метки.
	requireSACDone(t, w.saUpdateLabels(iss, cr1, map[string]string{"k": "v"}), "SAC-12 шаг 5")
	got, err = w.saGet(iss, cr1)
	require.NoError(t, err)
	require.Equal(t, map[string]string{"k": "v"}, got.GetLabels(), "SAC-12 шаг 5: метки")
	// 6) выключение и включение.
	requireSACDone(t, w.saDisable(iss, cr1), "SAC-12 шаг 6: Disable")
	got, err = w.saGet(iss, cr1)
	require.NoError(t, err)
	require.False(t, got.GetEnabled(), "SAC-12 шаг 6: enabled после Disable")
	requireSACDone(t, w.saEnable(iss, cr1), "SAC-12 шаг 6: Enable")
	got, err = w.saGet(iss, cr1)
	require.NoError(t, err)
	require.True(t, got.GetEnabled(), "SAC-12 шаг 6: enabled после Enable")
	// 7) отзыв K2 и удаление.
	requireSACDone(t, w.keyRevoke(iss, cr1, k2), "SAC-12 шаг 7: отзыв K2")
	requireSACDone(t, w.saDelete(iss, cr1), "SAC-12 шаг 7: Delete")
	require.NotContains(t, w.saList(asUser(w.ctx, w.usrA), string(w.accA)), cr1, "SAC-12 шаг 7: List от usr-A")
}

// SAC-13 — чужие учётки аккаунта создателю недоступны.
func TestServiceAccountCreator_SAC13_ForeignAccountsAreOutOfReach(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-13")
	_, cr1 := w.sac10("SAC-13")
	iss := asSA(w.ctx, w.svaIss)
	// Контроль окна материализации: своя учётка уже ведётся.
	w.pollRelation("service_account:"+w.svaIss, "v_update", sacSAModelType+":"+cr1, true,
		"SAC-13 контроль: sva-iss ведёт sva-cr1")

	keysA, keysA2 := w.keyCensus(w.svaA), w.keyCensus(w.sacA2)
	requireSACDenied(t, w.keyIssue(iss, w.svaA), "SAC-13 a: Issue sva-A")
	requireSACDenied(t, w.saDelete(iss, w.svaA), "SAC-13 b: Delete sva-A")
	_, err := w.saGet(iss, w.sacA2)
	// Строка c — ЧТЕНИЕ: дверь отвечает на отказ в чтении объекта, о котором
	// вызывающий знать не вправе, не PERMISSION_DENIED, а NOT_FOUND текстом
	// настоящего промаха владельца (corelib `authz/hide_existence.go`, скрытие
	// существования — не флаг записи каталога, а свойство отказа в чтении). Таблица
	// приёмки (§0.6, SAC-13) этого не учла; проба утверждает поведение двери
	// дословно — строже, а не мягче: «не твоё» неотличимо от «нет такого».
	requireSyncRefusal(t, err, codes.NotFound, fmt.Sprintf("ServiceAccount %s not found", w.sacA2),
		"SAC-13 c: Get sva-A2")
	requireSACDenied(t, w.keyIssue(iss, w.sacA2), "SAC-13 d: Issue sva-A2")
	requireSACDenied(t, w.saUpdateLabels(iss, w.sacA2, map[string]string{"k": "v"}), "SAC-13 e: Update sva-A2")
	for _, id := range []string{w.svaA, w.sacA2} {
		_, gerr := w.saGet(asUser(w.ctx, w.usrA), id)
		require.NoErrorf(t, gerr, "SAC-13: учётка %s на месте", id)
	}
	require.Equal(t, keysA, w.keyCensus(w.svaA), "SAC-13: ключей sva-A до = после")
	require.Equal(t, keysA2, w.keyCensus(w.sacA2), "SAC-13: ключей sva-A2 до = после")
}

// requireSyncRefusalPD — отказ `PERMISSION_DENIED` `permission denied`.
func requireSyncRefusalPD(t *testing.T, err error, why string) {
	t.Helper()
	requireSyncRefusal(t, err, codes.PermissionDenied, "permission denied", why)
}

// SAC-14 — два создателя одного аккаунта не ведут учёток друг друга.
func TestServiceAccountCreator_SAC14_TwoCreatorsDoNotManageEachOthersAccounts(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-14")
	w.grantC("SAC-14 Дано: G", w.svaIss)
	w.grantC("SAC-14 Дано: G2", w.svaIss2)
	cr1 := w.createSADone(asSA(w.ctx, w.svaIss), string(w.accA), "cr-1", "SAC-14 Дано: sva-cr1")
	cr2 := w.createSADone(asSA(w.ctx, w.svaIss2), string(w.accA), "cr-2", "SAC-14 Дано: sva-cr2")
	w.pollRelation("service_account:"+w.svaIss2, "v_update", sacSAModelType+":"+cr2, true,
		"SAC-14 контроль: sva-iss2 ведёт sva-cr2")
	iss2 := asSA(w.ctx, w.svaIss2)

	requireSACDenied(t, w.keyIssue(iss2, cr1), "SAC-14 a: sva-iss2 Issue sva-cr1")
	requireSACDenied(t, w.saDelete(iss2, cr1), "SAC-14 b: sva-iss2 Delete sva-cr1")
	_, err := w.saGet(asUser(w.ctx, w.usrA), cr1)
	require.NoError(t, err, "SAC-14: sva-cr1 на месте")
	require.Zero(t, w.keyCensus(cr1), "SAC-14: ключей у sva-cr1")
	requireSACDone(t, w.keyIssue(iss2, cr2), "SAC-14 c (близнец): sva-iss2 Issue sva-cr2")
}

// SAC-14 d — сверх таблицы сценария: ОДНА выдача роли C двум учёткам. Ведение
// своей учётки каждый получает по своей строке субъекта выдачи, а не по выдаче
// целиком (`reconcile.creatorGrantees`): иначе сосед по выдаче вёл бы учётки
// другого. Пара — «своя учётка» против «учётка соседа по той же выдаче».
func TestServiceAccountCreator_SAC14d_OneGrantTwoSubjectsEachManagesOnlyHisOwn(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-14 d")
	gm := w.grantC("SAC-14 d Дано: G на двоих", w.svaIss, w.svaOther)
	cr1 := w.createSADone(asSA(w.ctx, w.svaIss), string(w.accA), "cr-1", "SAC-14 d Дано: sva-cr1 от sva-iss")
	crO := w.createSADone(asSA(w.ctx, w.svaOther), string(w.accA), "cr-o", "SAC-14 d Дано: sva-crO от sva-other")
	w.pollRelation("service_account:"+w.svaIss, "v_update", sacSAModelType+":"+cr1, true,
		"SAC-14 d контроль: sva-iss ведёт sva-cr1")
	w.pollRelation("service_account:"+w.svaOther, "v_update", sacSAModelType+":"+crO, true,
		"SAC-14 d близнец: sva-other ведёт sva-crO")

	w.requireRelation("service_account:"+w.svaOther, "v_update", sacSAModelType+":"+cr1, false,
		"SAC-14 d: sva-other не ведёт sva-cr1 соседа по выдаче")
	w.requireRelation("service_account:"+w.svaIss, "v_update", sacSAModelType+":"+crO, false,
		"SAC-14 d: sva-iss не ведёт sva-crO соседа по выдаче")
	// Выпущенное выдачей — реестр материализации: на sva-cr1 кортежи только у
	// создателя. Решение двери выше судит строку селектора с осью создателя и
	// материализации не видит; читатели кортежей видят ровно реестр.
	emitted := func(user, object string) int {
		var n int
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples
			 WHERE binding_id = $1 AND fga_user = $2 AND object = $3`, gm, user, object).Scan(&n), "SAC-14 d: реестр выпущенного")
		return n
	}
	deadline := time.Now().Add(30 * time.Second)
	for emitted("service_account:"+w.svaIss, sacSAModelType+":"+cr1) == 0 && time.Now().Before(deadline) {
		time.Sleep(200 * time.Millisecond)
	}
	require.NotZero(t, emitted("service_account:"+w.svaIss, sacSAModelType+":"+cr1),
		"SAC-14 d контроль: выдача выпустила кортежи sva-iss на sva-cr1")
	require.NotZero(t, emitted("service_account:"+w.svaOther, sacSAModelType+":"+crO),
		"SAC-14 d близнец: выдача выпустила кортежи sva-other на sva-crO")
	require.Zero(t, emitted("service_account:"+w.svaOther, sacSAModelType+":"+cr1),
		"SAC-14 d: выдача выпустила кортежи sva-other на sva-cr1 соседа")
	require.Zero(t, emitted("service_account:"+w.svaIss, sacSAModelType+":"+crO),
		"SAC-14 d: выдача выпустила кортежи sva-iss на sva-crO соседа")
	requireSACDenied(t, w.keyIssue(asSA(w.ctx, w.svaOther), cr1), "SAC-14 d: sva-other Issue sva-cr1")
	requireSACDone(t, w.keyIssue(asSA(w.ctx, w.svaOther), crO), "SAC-14 d (близнец): sva-other Issue sva-crO")
}

// SAC-15 — список создателя — только его учётки.
func TestServiceAccountCreator_SAC15_CreatorsListShowsOnlyHisAccounts(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-15")
	w.grantC("SAC-15 Дано: G", w.svaIss)
	w.grantC("SAC-15 Дано: G2", w.svaIss2)
	cr1 := w.createSADone(asSA(w.ctx, w.svaIss), string(w.accA), "cr-1", "SAC-15 Дано: sva-cr1")
	cr2 := w.createSADone(asSA(w.ctx, w.svaIss2), string(w.accA), "cr-2", "SAC-15 Дано: sva-cr2")
	w.pollRelation("service_account:"+w.svaIss, "v_list", sacSAModelType+":"+cr1, true,
		"SAC-15 контроль: sva-iss видит sva-cr1")

	require.Equal(t, []string{cr1}, w.saList(asSA(w.ctx, w.svaIss), string(w.accA)), "SAC-15 a: List от sva-iss")
	all := w.saList(asUser(w.ctx, w.usrA), string(w.accA))
	for _, id := range []string{w.svaA, w.sacA2, cr1, cr2} {
		require.Containsf(t, all, id, "SAC-15 b: List от usr-A содержит %s", id)
	}
}

// SAC-16 — администратор аккаунта распоряжается учётками создателя.
func TestServiceAccountCreator_SAC16_AccountAdministratorDisposesOfCreatorsAccounts(t *testing.T) {
	w := newSACWorld(t)
	w.requireCreatorRole("SAC-16")
	_, cr1 := w.sac10("SAC-16")
	owner := asUser(w.ctx, w.usrA)
	untilDoorPasses(t, "SAC-16 a: usr-A Disable sva-cr1", func() error {
		o := w.saDisable(owner, cr1)
		if o.syncErr != nil {
			return o.syncErr
		}
		requireSACDone(t, o, "SAC-16 a")
		return nil
	})
	requireSACDone(t, w.saDelete(owner, cr1), "SAC-16 b: usr-A Delete sva-cr1")
	require.NotContains(t, w.saList(owner, string(w.accA)), cr1, "SAC-16 b: List от usr-A")
}

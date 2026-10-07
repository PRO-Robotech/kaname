// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// audience_fence_fixture_selfcheck_integration_test.go — фикстура проб K3
// судится ОТДЕЛЬНО от предмета: мир GW ложится, дверь отвечает на вопросы, на
// которые опираются пробы, оракул ограды различает «в снимке» и «шла в момент
// снимка», классификатор паритета называет дефект, а не молчит. Красное здесь —
// сломанный вопрос, а не отсутствующая возможность.
package main

import (
	"context"
	"testing"
)

func TestNTF3K3_FixtureSelfCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	w := newAFWorld(t)

	// Перепись мира: привязки GW, их субъекты, член группы.
	if n := afCount(t, w.db, `SELECT count(*) FROM kaname.access_binding_subjects WHERE binding_id LIKE 'acb-k3-%'`); n != len(afGWBindings) {
		afBroken(t, "субъектов привязок мира %d, ожидалось %d", n, len(afGWBindings))
	}
	if n := afCount(t, w.db, `SELECT count(*) FROM kaname.users WHERE account_id = 'acc-1' AND email_verified_at IS NOT NULL`); n != len(afPeople) {
		afBroken(t, "людей с подтверждённым адресом %d, ожидалось %d", n, len(afPeople))
	}
	if n := afCount(t, w.db, `SELECT count(*) FROM kaname.role_rule_selectors WHERE role_id LIKE 'rol-k3-%'`); n != 5 {
		afBroken(t, "селекторов ролей мира %d, ожидалось 5", n)
	}
	// Владелец аккаунта читает его выдачей владельца, проекция глаголов которой
	// знает тома (Р30: владелец в аудитории тем же отношением модели).
	if afCount(t, w.db, `SELECT count(*) FROM kaname.access_bindings b JOIN kaname.role_verb rv ON rv.role_id = b.role_id
		WHERE b.subject_id = 'usr-own' AND b.resource_type = 'account' AND rv.object_type = 'storage.volumes' AND rv.verb = 'get'`) != 1 {
		afBroken(t, "у выдачи владельца usr-own нет проекции (storage.volumes, get)")
	}

	// Оракул ограды: транзакция, шедшая в момент снимка, в нём НЕ видна, хотя
	// её xid меньше верхней границы снимка; закоммиченная до снимка при
	// удерживаемом нижнем пределе — видна, хотя её xid не меньше нижнего.
	long := w.afBegin(t)
	early := w.afBegin(t)
	early.afCommit(t)
	inflight := w.afBegin(t)
	r := w.afToken(t)
	inflight.afCommit(t)
	if !w.afVisible(t, early.xid, r) {
		afBroken(t, "оракул: транзакция %s закоммичена до снимка %s, а в нём не видна", early.xid, r)
	}
	if w.afVisible(t, inflight.xid, r) {
		afBroken(t, "оракул: транзакция %s шла в момент снимка %s, а в нём видна", inflight.xid, r)
	}
	var xmin, earlyXid string
	if err := w.db.fixture.QueryRow(context.Background(),
		`SELECT pg_snapshot_xmin($1::pg_snapshot)::text, $2::xid8::text`, r, early.xid).Scan(&xmin, &earlyXid); err != nil {
		afBroken(t, "нижний предел снимка: %v", err)
	}
	var below bool
	if err := w.db.fixture.QueryRow(context.Background(),
		`SELECT $1::xid8 < pg_snapshot_xmin($2::pg_snapshot)`, early.xid, r).Scan(&below); err != nil {
		afBroken(t, "сравнение с нижним пределом: %v", err)
	}
	if below {
		afBroken(t, "оракул: xid %s ниже нижнего предела %s — близнец «видна, хотя не ниже xmin» не построен", early.xid, xmin)
	}
	long.afCommit(t)

	// Классификатор паритета (NTF3-181) на синтетике: ответ без раскрытия
	// группы называет usr-D, классы исключения названы, полный ответ молчит.
	live := []string{"user:usr-A", "user:usr-D", "group:grp-1", "service_account:sva-1", "user:usr-ca", "user:*"}
	leaked, unexplained, classes := afParity(t, w.db, live, []string{"usr-A"})
	if len(leaked) != 0 || len(unexplained) != 1 || unexplained[0] != "user:usr-D" {
		afBroken(t, "классификатор паритета: ответ без usr-D дал утечку %v, без класса %v (ждали ровно user:usr-D)", leaked, unexplained)
	}
	for s, want := range map[string]string{
		"user:usr-ca": "только уровень кластера", "service_account:sva-1": "сервисный аккаунт",
		"group:grp-1": "группа как адресат (раскрыта в членов)", "user:*": "подстановочное право",
	} {
		if classes[s] != want {
			afBroken(t, "классификатор паритета: класс %s — %q, ждали %q", s, classes[s], want)
		}
	}
	if leaked, unexplained, _ := afParity(t, w.db, live, []string{"usr-A", "usr-D"}); len(leaked)+len(unexplained) != 0 {
		afBroken(t, "классификатор паритета: полный ответ дал утечку %v, без класса %v", leaked, unexplained)
	}
	if leaked, _, _ := afParity(t, w.db, live, []string{"usr-A", "usr-D", "usr-X"}); len(leaked) != 1 || leaked[0] != "user:usr-X" {
		afBroken(t, "классификатор паритета: лишний usr-X не назван утечкой (%v)", leaked)
	}
	t.Logf("мир GW: людей %d, привязок %d; оракул: снимок %s, xmin %s", len(afPeople), len(afGWBindings), r, xmin)
}

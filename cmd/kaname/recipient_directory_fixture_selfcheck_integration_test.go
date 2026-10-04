// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// recipient_directory_fixture_selfcheck_integration_test.go — фикстура проб
// справочника судится ОТДЕЛЬНО от предмета: мир G0 ложится, дверь отвечает на
// вопросы, на которые опираются пробы, журнал операторов видит вопрос о
// `v_get`. Красное здесь — сломанный вопрос, а не отсутствующая возможность.
package main

import (
	"testing"
)

func TestNTF3X4D_FixtureSelfCheck(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	db := newNTFDB(t)
	door, _ := ntfDoor(db)
	requireWireSeesDoorQuestions(t, db, door)
	rdSeedG0(t, db, door, true)
	rdRequireWireSeesVGet(t, db, door)
	// Отрицательный контроль мира: адрес usr-blk подтверждён, состояние BLOCKED.
	if n := rdCount(t, db, `SELECT count(*) FROM kaname.users WHERE id = 'usr-blk' AND invite_status = 'BLOCKED'
		AND email_verified_at IS NOT NULL`); n != 1 {
		t.Fatalf("фикстура: usr-blk не в состоянии BLOCKED с подтверждённым адресом (строк %d)", n)
	}
	// Положительный контроль ленты привязок: прямые действующие привязки
	// пользователей на prj-1 — ровно четыре (A, B, E, blk), прочие строки G0
	// отличаются от них ровно одним фактом (субъект-группа, сервисный аккаунт,
	// область аккаунта, срок, отзыв).
	if n := rdCount(t, db, `SELECT count(DISTINCT s.subject_id) FROM kaname.access_bindings b
		JOIN kaname.access_binding_subjects s ON s.binding_id = b.id
		WHERE b.resource_type = 'project' AND b.resource_id = 'prj-1' AND s.subject_type = 'user'
		  AND b.status = 'ACTIVE' AND (b.expires_at IS NULL OR b.expires_at > now())`); n != 4 {
		t.Fatalf("фикстура: прямых действующих привязок пользователей на prj-1 %d, ожидалось 4", n)
	}
}

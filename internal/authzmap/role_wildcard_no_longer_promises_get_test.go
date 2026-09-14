// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap_test

// role_wildcard_no_longer_promises_get_test.go — подстановочное правило на
// ресурсе `role` больше не обещает глагол `get` (kacho#1922, GWT-4 приёмки
// `docs/engineering/acceptance/role-read-relation-retired-not-half-declared.md`).
//
// # Предмет
//
// Правило `classes: ["*"]` роли `iam.role.admin` разворачивается в набор ТИПА, и
// ровно этот набор читает превью роли (`domain.Role.EffectiveVerbs` ←
// `TypeVerbs` ← набор живого каталога, который сеется из этого же литерала).
// Пока тип объявлял `v_get`, подстановка называла арендатору глагол, которого не
// исполняет ни один путь запроса: отношения `v_get` на `iam_role` не спрашивала
// ни одна запись каталога прав, а единичное чтение роли энфорсится тем же
// предикатом, что страница.
//
// #1916 снял класс `get` там, где он назван ПОИМЁННО (у ролей `iam.role.edit` и
// `iam.role.view`), а подстановка сохраняла его BY CONSTRUCTION — она не
// перечисляет классы, а берёт набор типа. Закрыть это можно было только на
// уровне ТИПА, что и сделано.
//
// # Почему пара, а не одно отрицание
//
// «Набор роли не содержит get» истинно и на типе, у которого отняли всё, и на
// сломанном резолве. Поэтому рядом стоят два положительных контроля: набор роли
// непуст и равен ТРЁМ оставшимся глаголам, а у соседнего типа `get` остаётся —
// иначе «у роли его нет» читалось бы как «его нет нигде», то есть как поломка
// словаря, а не как сужение набора одного типа.

import (
	"sort"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
)

func TestRoleWildcardExpandsWithoutGet(t *testing.T) {
	roleType, ok := authzmap.ObjectType("iam", "role")
	if !ok {
		t.Fatal("предпосылка сломана: пара (iam, role) не резолвится в тип — " +
			"утверждение о её наборе не значило бы ничего")
	}

	got := authzmap.VerbsOfType(roleType)
	sort.Strings(got)
	t.Logf("осмотрено: тип %q объявляет глаголы %v", roleType, got)

	want := []string{"delete", "list", "update"}
	if len(got) != len(want) {
		t.Fatalf("набор типа %q = %v, ждали %v: подстановка `classes: [\"*\"]` разворачивается "+
			"в набор ТИПА, и всякое расхождение здесь есть расхождение того, что превью роли "+
			"обещает арендатору", roleType, got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("набор типа %q на позиции %d = %q, ждали %q", roleType, i, got[i], want[i])
		}
	}

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: глагол жив у СОСЕДНЕГО типа.
	//
	// Без него отрицание выше зеленело бы на дереве, где `get` снят у всех, —
	// то есть на изменении, отнимающем живое право у двадцати шести соседей.
	groupType, ok := authzmap.ObjectType("iam", "group")
	if !ok {
		t.Fatal("предпосылка контроля сломана: пара (iam, group) не резолвится в тип")
	}
	var neighbourHasGet bool
	for _, v := range authzmap.VerbsOfType(groupType) {
		if v == "get" {
			neighbourHasGet = true
			break
		}
	}
	if !neighbourHasGet {
		t.Errorf("соседний тип %q перестал объявлять `get` — сужение вышло за ресурс `role`, "+
			"и утверждение выше говорит о поломке словаря, а не о снятии одного отношения",
			groupType)
	}
}

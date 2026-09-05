// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package permission_catalog

// resource_verbs_iam_user_test.go — редактор ролей НЕ ПРЕДЛАГАЕТ арендатору
// глагол, которого никто не спрашивает (#1189).
//
// # Предмет
//
// Выпадающий список редактора ролей строится из `CatalogResource.verbs` — набора
// глаголов САМОГО ресурса (#1128). Пока тип `iam_user` объявлял `v_delete`, набор
// нёс `delete`, и арендатор видел его в списке наравне с `get` и `list`.
//
// Читателя у пары (`iam_user`, `v_delete`) нет ни одного: снятие строки личности
// спрашивает `identity_remover` (#1131), правку записи — `record_writer`, запрет и
// его снятие — `identity_suspender` (#1102). То есть список предлагал выбор,
// который не даёт ничего: роль авторуется, выдаётся, материализуется — и не
// энфорсится нигде. Узнать это можно было только по последствиям.
//
// # Почему отдельная проба, а не строка в перечне суженных
//
// Соседний гейт (`TestCatalogResourceVerbs_DescribeTheTypesOwnSets`) сверяет
// предложенное с ОБЪЯВЛЕННЫМ и требует, чтобы всякое сужение было записано с
// причиной. Он ответит «да» и на наборе `[get list delete]`, и на `[get list]` —
// оба согласованы с типом. Здесь утверждается ДРУГОЕ: какой именно глагол
// перестал предлагаться. Без этого сужение держалось бы записью перечня, а
// запись — прозой.
//
// # Обе стороны
//
// Отрицание («delete не предлагается») зеленело бы на ресурсе, который не
// предлагает НИЧЕГО, и на каталоге, отдавшем пустой список. Поэтому рядом стоят
// два положительных контроля: `iam.user` продолжает предлагать читающие глаголы —
// у них читатель есть, — а обычный ресурс продолжает предлагать `delete`.

import (
	"testing"
)

// identityResource / neighbourOfIdentity — подопытный и его контраст. Литералы
// законны: проба РЕДАКТИРУЕТ утверждение о конкретном ресурсе, а утверждать
// можно только названное.
const (
	identityResource    = "iam.user"
	neighbourOfIdentity = "vpc.network"
)

// TestCatalogVerbs_IdentityDoesNotOfferTheVerbNobodyAsks — гейт на дереве.
func TestCatalogVerbs_IdentityDoesNotOfferTheVerbNobodyAsks(t *testing.T) {
	offerings := treeOfferings(t)
	if len(offerings) == 0 {
		t.Fatal("каталог не отдал ни одного ресурса — предпосылка пробы сломана")
	}

	identity, ok := offeringOf(offerings, identityResource)
	if !ok {
		t.Fatalf("каталог не знает ресурса %s — утверждать о его наборе нечего", identityResource)
	}
	if !identity.HasVerbRelations {
		t.Fatalf("%s объявлен неглагольным — тогда «не предлагает delete» верно by construction "+
			"и не означает ничего", identityResource)
	}

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 1: ресурс продолжает предлагать читающие глаголы
	// Иначе отрицание ниже зеленело бы на пустом наборе.
	for _, verb := range []string{"get", "list"} {
		if !contains(identity.Offered, verb) {
			t.Fatalf("%s больше не предлагает `%s` (набор %v) — у этого глагола читатель ЕСТЬ "+
				"(UserService/Get, UserService/ListOperations), и сужение его не касается; "+
				"пока набор пуст, утверждение об отсутствии `delete` вакуумно",
				identityResource, verb, identity.Offered)
		}
	}

	// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 2: обычный ресурс `delete` предлагает ─────────
	// Иначе «на iam.user его нет» читалось бы как «его нет нигде», то есть как
	// поломка каталога, а не как сужение набора одного типа.
	neighbour, ok := offeringOf(offerings, neighbourOfIdentity)
	if !ok {
		t.Fatalf("каталог не знает ресурса %s — контраст, ради которого он выбран, исчез",
			neighbourOfIdentity)
	}
	if !contains(neighbour.Offered, "delete") {
		t.Fatalf("%s больше не предлагает `delete` (набор %v) — сужение задело не только %s, "+
			"и это уже не предмет #1189", neighbourOfIdentity, neighbour.Offered, identityResource)
	}

	// ── Предмет ─────────────────────────────────────────────────────────────
	if contains(identity.Offered, "delete") {
		t.Errorf("%s предлагает редактору `delete` (набор %v), а спросить его некому: "+
			"каталог прав не несёт ни одной записи с парой (iam_user, v_delete) — снятие строки "+
			"личности спрашивает identity_remover (#1131). Роль, авторованная этим глаголом, "+
			"выдаётся и материализуется, но не энфорсится нигде",
			identityResource, identity.Offered)
	}

	t.Logf("перепись: ресурсов каталога %d; %s предлагает %v; %s предлагает %v",
		len(offerings), identityResource, identity.Offered,
		neighbourOfIdentity, neighbour.Offered)
}

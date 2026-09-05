// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// derivation_integration_test.go — право, которое модель ВЫВОДИТ, находится.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ПРОВЕРЯЕТСЯ И ПОЧЕМУ ЭТО НЕ ОТТЕНОК
//
// Модель не хранит право читателя отдельно: она его выводит. Право читателя
// следует из права редактора, редактора — из администратора, а администратор
// аккаунта и администратор облака держат право на всё, что внутри. Ни одна из
// этих строк не лежит на самом объекте: они лежат ВЫШЕ по цепи и под ДРУГИМ
// именем.
//
// Форма, ищущая имя отношения буквально, ответит на такой вопрос «нет» — то есть
// откажет держателю законного права. Это не приблизительность ответа, а отказ, и
// заметен он был бы по обращению человека, а не по красной пробе.
//
// Проба намеренно ставит источник максимально ДАЛЕКО от вопроса: право лежит на
// кластере, вопрос задан про сеть, между ними проект и аккаунт. Совпадение имён
// исключено — спрашивают `v_get`, а лежит `system_admin`.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
)

// seedChain выстраивает цепь сеть → проект → аккаунт → кластер.
//
// ПО ОДНОМУ РЕБРУ НА ЗВЕНО — ровно так цепь и набирают производители дерева:
// ресурсы vpc, storage и compute шлют ОДНО звено (проект), реестр — два, кластер
// не шлёт никто, а аккаунт достигается с проекта его собственным ребром.
// Замыкание (строка на каждого предка) — форма, которой в продукте НЕТ, и
// фикстура, кладущая её, делала бы обход вверх ненаблюдаемым: одноразовое
// чтение таблицы дало бы на ней тот же ответ, что и обход, и различить формы
// стало бы нечем.
func seedChain(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	seedTenant(t, ctx, tx)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.resource_parent_edge
		   (object_type, object_id, parent_type, parent_id, depth)
		 VALUES ('vpc_network', 'net-1', 'project', 'prj-1', 1),
		        ('project',     'prj-1', 'account', 'acc-1', 1),
		        ('account',     'acc-1', 'cluster', 'cluster_kacho_root', 1)`)
}

func ask(t *testing.T, ctx context.Context, tx pgx.Tx, subject, relation string) relverdict.Verdict {
	t.Helper()
	got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject: subject, ObjectType: "vpc_network", ObjectID: "net-1", Relation: relation,
	})
	if err != nil {
		t.Fatalf("вопрос %s о %s: %v", relation, subject, err)
	}
	return got
}

// Право администратора облака достаёт до листа — под другим именем и через три
// звена цепи.
func TestAsk_CloudAdministratorReachesTheLeaf(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedChain(t, ctx, tx)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject)
			 VALUES ('cluster', 'cluster_kacho_root', 'system_admin', 'user:usr-admin')`)

		if got := ask(t, ctx, tx, "user:usr-admin", "v_get"); got != relverdict.Allow {
			t.Errorf("администратор облака не достал до листа: %s. Строка лежит на кластере "+
				"под именем system_admin, вопрос задан про v_get на сети — форма, ищущая имя "+
				"буквально, отказывает держателю законного права", got)
		}
		// Тот же вывод обязан работать и на мутирующем глаголе: иначе «достаёт»
		// оказалось бы свойством одного отношения, а не вывода.
		if got := ask(t, ctx, tx, "user:usr-admin", "v_delete"); got != relverdict.Allow {
			t.Errorf("вывод сработал на чтении и не сработал на удалении: %s — значит "+
				"находится не право, а совпадение", got)
		}
		// Отрицание рядом: без строки на кластере права нет. Без него утверждение
		// выше зеленело бы и на форме, разрешающей всем.
		if got := ask(t, ctx, tx, "user:usr-2", "v_get"); got != relverdict.Deny {
			t.Errorf("посторонний получил право администратора облака: %s", got)
		}
	})
}

// Владелец аккаунта — источник структурный: он держит право на всё внутри
// СВОЕГО аккаунта и ни на что вне его.
func TestAsk_AccountOwnerReachesInsideAndNotOutside(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedChain(t, ctx, tx)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject)
			 VALUES ('account', 'acc-1', 'owner', 'user:usr-owner')`)

		if got := ask(t, ctx, tx, "user:usr-owner", "v_update"); got != relverdict.Allow {
			t.Errorf("владелец аккаунта не достал до объекта внутри аккаунта: %s", got)
		}

		// Сеть ЧУЖОГО аккаунта тем же владельцем не достаётся. Отрицание несущее:
		// без него «достаёт» было бы неотличимо от «достаёт до всего».
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.accounts (id, name, owner_user_id)
			 VALUES ('acc-2', 'other-account', 'usr-1') ON CONFLICT DO NOTHING`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('vpc_network', 'net-9', 'account', 'acc-2', 1)`)
		other, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-owner", ObjectType: "vpc_network", ObjectID: "net-9",
			Relation: "v_update",
		})
		if err != nil {
			t.Fatalf("вопрос о чужом объекте: %v", err)
		}
		if other != relverdict.Deny {
			t.Errorf("владелец одного аккаунта достал объект другого: %s", other)
		}
	})
}

// Отношение, которого модель не знает, — ОШИБКА, а не отказ.
//
// Отказ на опечатку в имени ищут в правах и не находят: строки-то нет ни у кого.
func TestAsk_RelationUnknownToTheModelIsAnErrorNotADenial(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedChain(t, ctx, tx)
		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-1",
			Relation: "v_gte",
		})
		if err == nil {
			t.Fatalf("отношение, которого в модели нет, принято молча и дало вердикт %s", got)
		}
		if got != relverdict.Unknown {
			t.Errorf("вердикт %s при ошибке — вызывающий не отличит опечатку от отказа", got)
		}
	})
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// producerdict_integration_test.go — цепь и зеркало, записанные НАСТОЯЩИМ
// писателем, читаются вопросом о доступе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТОГО НЕ ПОКАЗЫВАЛА НИ ОДНА СОСЕДНЯЯ ПРОБА
//
// Все остальные пробы пакета сеют цепь и зеркало ЛИТЕРАЛОМ, в том словаре, каким
// спрашивает читатель. Такая фикстура внутренне непротиворечива с запросом и
// потому зелена ровно на том дефекте, которым сама себя кормит: соединение
// сходится на данных, которых писатель не производит.
//
// Здесь посев идёт ЧЕРЕЗ ПИСАТЕЛЯ (`resource_mirror.UpsertTx`) — тем же вызовом
// и с тем же входом, каким его зовёт применение регистрации ресурса. Значение,
// которое туда уезжает, берётся из КАТАЛОГА напрямую (`authzmap.DottedType`), а
// не из функции читателя: иначе фикстура и продукт звали бы одно и то же, и
// проба доказывала бы согласие запроса С САМИМ СОБОЙ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ
//
// ИСХОД РАЗРЕШЕНИЯ, а не факт вызова. Проба, утверждающая «писатель позвал
// перевод», зелена и на переводе в другую сторону; проба, утверждающая
// «выдача на проект доходит до ресурса», — нет.
//
// Каждое утверждение стоит В ПАРЕ с отрицанием: «доступ есть» без «у постороннего
// нет» одинаково зеленеет на запросе, разрешающем всем.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/pkg/ownerregister"
	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
)

// catalogFormOf — имя типа в словаре КАТАЛОГА, взятое у каталога напрямую.
//
// Не через переводчик читателя: подмена перевода сместила бы обе стороны
// одинаково и осталась бы незамеченной (тот же довод, что у seedRole).
func catalogFormOf(t *testing.T, modelType string) string {
	t.Helper()
	dotted, known := authzmap.DottedType(modelType)
	if !known {
		t.Fatalf("тип %q не объявлен в каталоге — проба сравнивала бы словарь с самим собой",
			modelType)
	}
	return dotted
}

// registerAsProducerDoes повторяет вход применения регистрации: строка зеркала
// названа словарём КАТАЛОГА, цепь предков выводится общей функцией владельца.
func registerAsProducerDoes(
	t *testing.T, ctx context.Context, tx pgx.Tx, objectID string, labels map[string]string,
) {
	t.Helper()
	if _, err := resource_mirror.UpsertTx(ctx, tx, resource_mirror.Row{
		ObjectType:      catalogFormOf(t, "vpc_network"),
		ObjectID:        objectID,
		ParentProjectID: "prj-1",
		ParentAccountID: "acc-1",
		ParentChain:     ownerregister.ParentChain(nil, "prj-1", "acc-1"),
		Labels:          labels,
	}); err != nil {
		t.Fatalf("регистрация объекта %s: %v", objectID, err)
	}
}

// seedProjectBinding выдаёт роль на проект — область, из которой право обязано
// дойти до ресурса по цепи.
func seedProjectBinding(t *testing.T, ctx context.Context, tx pgx.Tx, bindingID, roleID string) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kaname.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		 VALUES ($1, 'user', 'usr-1', $2, 'project', 'prj-1', 'ACTIVE')`, bindingID, roleID)
	exec(t, ctx, tx,
		`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ($1, 'user', 'usr-1')`, bindingID)
}

// Выдача на проект доходит до ресурса, чью цепь записал настоящий писатель.
func TestAsk_ChainWrittenByTheProducerReachesTheGrant(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-prod", "vpc_network", "get", "anchor", "{}")
		seedProjectBinding(t, ctx, tx, "acb-prod", "rol-prod")
		registerAsProducerDoes(t, ctx, tx, "net-1", nil)

		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if got != relverdict.Allow {
			t.Errorf("выдача на проект не дошла до ресурса, зарегистрированного НАСТОЯЩИМ "+
				"писателем: %s. Цепь записана, вопрос задан — значит соединение по цепи "+
				"не совпало ни на одном шаге, и отказ неотличим от честного", got)
		}

		// Отрицание рядом: посторонний права не получает. Без него «allow» выше
		// зеленело бы и на запросе, разрешающем всем.
		other, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-2", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if other != relverdict.Deny {
			t.Errorf("посторонний получил право: %s", other)
		}
	})
}

// Разбор оснований называет НОСИТЕЛЯ выдачи — проект, а не сам объект.
//
// Вопрос задают ради «что снять»; основание, названное без носителя или не
// названное вовсе, отправляет администратора снимать строку туда, где её нет.
func TestExpand_ChainWrittenByTheProducerNamesTheGrantScope(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-exp", "vpc_network", "get", "anchor", "{}")
		seedProjectBinding(t, ctx, tx, "acb-exp", "rol-exp")
		registerAsProducerDoes(t, ctx, tx, "net-1", nil)

		sources, err := relverdict.Expand(ctx, tx, "vpc_network", "net-1", "v_get")
		if err != nil {
			t.Fatalf("разбор: %v", err)
		}
		var named bool
		for _, s := range sources {
			if s.Kind == "binding" && s.ScopeType == "project" && s.ScopeID == "prj-1" {
				named = true
			}
		}
		if !named {
			t.Errorf("основание на проекте не названо (получено %d оснований: %+v) — "+
				"администратор не узнает, какую строку снимать", len(sources), sources)
		}
	})
}

// Метки, записанные писателем в зеркало, читаются меточной ветвью правила.
func TestAsk_LabelsWrittenByTheProducerAreFound(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-lbl", "vpc_network", "get", "labels", `{"env":"prod"}`)
		seedProjectBinding(t, ctx, tx, "acb-lbl", "rol-lbl")
		registerAsProducerDoes(t, ctx, tx, "net-1", map[string]string{"env": "prod"})
		registerAsProducerDoes(t, ctx, tx, "net-2", map[string]string{"env": "dev"})

		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if got != relverdict.Allow {
			t.Errorf("выдача по метке не достигла объекта, чьи метки записал НАСТОЯЩИЙ "+
				"писатель: %s. Метка совпадает — значит спрошено не то место", got)
		}

		// Отрицание рядом: непомеченный объект права не даёт. Без него «allow»
		// зеленело бы и на ветви, читающей метки как совпавшие всегда.
		other, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-2", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if other != relverdict.Deny {
			t.Errorf("объект с ЧУЖОЙ меткой получил право: %s", other)
		}
	})
}

// Перечисление берёт кандидатов там, где писатель их положил.
func TestList_ObjectWrittenByTheProducerIsACandidate(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-lst", "vpc_network", "get", "anchor", "{}")
		seedProjectBinding(t, ctx, tx, "acb-lst", "rol-lst")
		registerAsProducerDoes(t, ctx, tx, "net-1", nil)

		ids, _, err := relverdict.List(ctx, tx, relverdict.ListQuery{
			Subject: "user:usr-1", ObjectType: "vpc_network", Relation: "v_get", Limit: 10,
		})
		if err != nil {
			t.Fatalf("перечисление: %v", err)
		}
		if len(ids) != 1 || ids[0] != "net-1" {
			t.Errorf("перечисление не нашло объект, зарегистрированный НАСТОЯЩИМ писателем: "+
				"%v. Пустая страница за живые права неотличима от честного «ничего не "+
				"доступно»", ids)
		}

		// Отрицание рядом: посторонний не видит ничего.
		none, _, err := relverdict.List(ctx, tx, relverdict.ListQuery{
			Subject: "user:usr-2", ObjectType: "vpc_network", Relation: "v_get", Limit: 10,
		})
		if err != nil {
			t.Fatalf("перечисление: %v", err)
		}
		if len(none) != 0 {
			t.Errorf("посторонний увидел объекты: %v", none)
		}
	})
}

// Перечисление субъектов называет того, кому выдано на проект.
func TestSubjects_ChainWrittenByTheProducerNamesTheGrantee(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-sub", "vpc_network", "get", "anchor", "{}")
		seedProjectBinding(t, ctx, tx, "acb-sub", "rol-sub")
		registerAsProducerDoes(t, ctx, tx, "net-1", nil)

		subjects, _, err := relverdict.Subjects(ctx, tx, relverdict.SubjectsQuery{
			ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get", Limit: 10,
		})
		if err != nil {
			t.Fatalf("перечисление субъектов: %v", err)
		}
		var found bool
		for _, s := range subjects {
			if s == "user:usr-1" {
				found = true
			}
		}
		if !found {
			t.Errorf("держатель выдачи на проект не назван среди субъектов: %v", subjects)
		}
	})
}

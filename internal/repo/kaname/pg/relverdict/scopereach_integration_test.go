// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// scopereach_integration_test.go — ОБЛАСТЬ ВЕРДИКТА ДОСТАЁТ ДО КОРНЯ НА ТОЙ
// ЦЕПИ, КОТОРУЮ ПРОИЗВОДИТ ДЕРЕВО.
//
// # Что здесь изменилось и почему проба перевёрнута
//
// Прежде рядом стояли две пробы: одна доставала до корня на цепи, ДОСЕЯННОЙ до
// полной, вторая закрепляла КАК ЕСТЬ, что на цепи из одного звена — той, что
// шлёт vpc, — выдача на аккаунт и факт администратора облака на кластере не
// находятся. Вторая была объявлена сигнальной: её покраснение означало «предмет
// закрыт», а не поломку. Предмет закрыт (kacho#740), поэтому она снята, и на её
// место встало утверждение о НОВОМ поведении.
//
// # Откуда теперь берутся звенья выше проекта
//
// Из собственной схемы iam, а не из сообщения производителя. Предок проекта —
// его аккаунт (`projects.account_id`), предок аккаунта — кластер (синглтон
// `clusters`); обе величины принадлежат iam и всегда актуальны. Цепь областей
// читается представлением `resource_scope_edge`: к рёбрам, присланным
// владельцами ресурсов, оно ДОБАВЛЯЕТ эти два звена там, где владелец о них
// молчит. Копии при этом не заводится — звено И ЕСТЬ строка `projects`, поэтому
// переезд проекта в другой аккаунт виден следующим же вопросом, а не после
// перерегистрации всех его ресурсов.
//
// # Почему фикстура сеется ПРОИЗВОДИТЕЛЕМ, а не сырым SQL
//
// Сырой SQL позволяет положить цепь любой формы, в том числе той, которой в
// продукте не бывает. Тогда «область достаёт до корня» становится свойством
// ФИКСТУРЫ: она сама кладёт то, что потом проверяет. Регистрация идёт тем же
// вызовом, которым её делает продукт, и ровно с тем содержанием, которое шлёт
// vpc: `ParentChain(nil, projectID, "")` — одно звено.

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/pkg/ownerregister"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/resource_mirror"
)

// registerThroughProducer — ОДНА регистрация, проведённая единственным
// производителем рёбер дерева.
//
// Форма вызова — та, которой шлют регистрации; содержание — то, которое шлёт
// названный потребитель. Проверка `Applied` не формальность: молча не
// применившаяся регистрация оставила бы пробу зелёной ни на чём.
func registerThroughProducer(t *testing.T, ctx context.Context, tx pgx.Tx,
	objectType, objectID string, chain []string, project, account string, version time.Time) {
	t.Helper()
	out, err := resource_mirror.UpsertTx(ctx, tx, resource_mirror.Row{
		ObjectType:      objectType,
		ObjectID:        objectID,
		ParentProjectID: project,
		ParentAccountID: account,
		ParentChain:     chain,
		SourceVersion:   version,
	})
	if err != nil {
		t.Fatalf("регистрация %s:%s через производителя: %v", objectType, objectID, err)
	}
	if !out.Applied {
		t.Fatalf("регистрация %s:%s не применилась — фикстура ничего не посеяла",
			objectType, objectID)
	}
}

// seedChainThroughProducer — цепь, названная владельцем ЦЕЛИКОМ, звено за
// звеном.
//
// Это вторая из двух законных форм: владелец, чья иерархия глубже проекта
// (реестр над репозиторием), обязан назвать её сам — вывести её из области
// доставки нельзя. Здесь она изображена на проекте и аккаунте, чтобы проба
// судила ИМЕННО присланную цепь, без участия достройки схемой.
//
// Что происходит, когда владелец шлёт ОДНО звено (а так шлют vpc, compute и
// storage), утверждает соседняя проба — там выше проекта поднимает уже схема.
func seedChainThroughProducer(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	base := time.Now().UTC().Truncate(time.Microsecond)
	regs := []struct {
		objectType, objectID string
		chain                []string
		project, account     string
	}{
		// Сеть vpc: ровно то, что шлёт vpc — ParentChain(nil, project, "").
		// Тип называется словарём КАТАЛОГА: им назван `resource_mirror.object_type`,
		// и перевод в словарь модели делает сам производитель.
		{catalogFormOf(t, "vpc_network"), "net-1", ownerregister.ParentChain(nil, "prj-1", ""), "prj-1", ""},
		{catalogFormOf(t, "project"), "prj-1", ownerregister.ParentChain(nil, "", "acc-1"), "", "acc-1"},
		{catalogFormOf(t, "account"), "acc-1", []string{"cluster:cluster_root"}, "", ""},
	}
	for i, r := range regs {
		registerThroughProducer(t, ctx, tx, r.objectType, r.objectID, r.chain,
			r.project, r.account, base.Add(time.Duration(i)*time.Millisecond))
	}
}

// TestScopeReachesTheRootOnTheChainProducersActuallyWrite — цепь, названная
// владельцем ЦЕЛИКОМ, поднимается до корня.
//
// Красная, пока область вердикта читается ОДНИМ обращением к таблице рёбер: у
// сети лежит одно ребро (проект), и ни аккаунт, ни кластер в область не попадают.
func TestScopeReachesTheRootOnTheChainProducersActuallyWrite(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-acc", "vpc_network", "get", "anchor", "{}")
		seedChainThroughProducer(t, ctx, tx)

		// ПРЕДПОСЫЛКА, названная числом: у сети РОВНО ОДНО ребро. Проба стоит
		// именно на той форме, которую производит дерево, и это проверяется,
		// а не подразумевается.
		var links int
		if err := tx.QueryRow(ctx,
			`SELECT count(*)::int FROM kaname.resource_parent_edge
			  WHERE object_type = 'vpc_network' AND object_id = 'net-1'`).Scan(&links); err != nil {
			t.Fatalf("перепись рёбер объекта: %v", err)
		}
		if links != 1 {
			t.Fatalf("у сети %d рёбер, ожидалось РОВНО ОДНО: фикстура положила форму, которой "+
				"производители не производят, и проба судила бы не то состояние", links)
		}
		t.Logf("предпосылка: у объекта арендатора %d ребро — цепь до корня собирается ОБХОДОМ", links)

		// (1) Выдача на АККАУНТ — два звена вверх.
		exec(t, ctx, tx,
			`INSERT INTO kaname.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ('acb-acc', 'user', 'usr-1', 'rol-acc', 'account', 'acc-1', 'ACTIVE')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-acc', 'user', 'usr-1')`)

		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("вопрос о выдаче на аккаунт: %v", err)
		}
		if got != relverdict.Allow {
			t.Errorf("выдача на АККАУНТ не достала до объекта арендатора: %s. Область вердикта "+
				"схлопнулась до «объект + проект», и отказ неотличим от честного", got)
		}

		// (2) Прямой факт администратора облака на КЛАСТЕРЕ — три звена вверх.
		exec(t, ctx, tx,
			`INSERT INTO kaname.users (id, external_id, email, account_id)
			 VALUES ('usr-admin', 'ext-admin', 'admin@kacho.local', 'acc-1')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
			 VALUES ('cluster', 'cluster_root', 'system_admin', 'user:usr-admin')`)

		admin, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-admin", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("вопрос администратора облака: %v", err)
		}
		if admin != relverdict.Allow {
			t.Errorf("администратор облака не достал до объекта арендатора: %s. Это аварийный "+
				"путь §«Три уровня супер-доступа»: он обязан работать независимо от состояния "+
				"конвейеров материализации", admin)
		}

		// ОТРИЦАНИЕ рядом с положительным: чужой аккаунт по-прежнему не достаёт.
		exec(t, ctx, tx,
			`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ('acc-9', 'foreign', 'usr-1')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.users (id, external_id, email, account_id)
			 VALUES ('usr-out', 'ext-out', 'out@kacho.local', 'acc-1')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ('acb-foreign', 'user', 'usr-out', 'rol-acc', 'account', 'acc-9', 'ACTIVE')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-foreign', 'user', 'usr-out')`)
		outsider, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-out", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("вопрос постороннего: %v", err)
		}
		if outsider != relverdict.Deny {
			t.Errorf("выдача на ЧУЖОЙ аккаунт достала до объекта: %s — положительные утверждения "+
				"выше зеленели бы на форме, которая разрешает всем", outsider)
		}
	})
}

// TestScopeReachesTheRootOnTheChainTheTreeActuallyProduces — kacho#740.
//
// # Предмет
//
// Владельцы ресурсов шлют ОДНО звено — проект, — и рёбер выше проекта не пишет
// никто: объектов типа project и account не регистрирует ни один сервис, включая
// сам iam. Пока цепь состояла ТОЛЬКО из присланного, обход доходил до проекта и
// там останавливался: выдача на аккаунт и факт администратора облака на кластере
// не находились, и отказ был НЕОТЛИЧИМ от честного.
//
// Теперь звенья выше проекта достраивает схема — из тех самых строк `projects` и
// `accounts`, которые iam и так держит. Проба утверждает исход на цепи, которую
// дерево ДЕЙСТВИТЕЛЬНО производит: одно ребро у объекта, ни одного у проекта и
// аккаунта.
//
// # Почему отрицания стоят рядом и почему их два
//
// Первое — чужой аккаунт: без него положительные утверждения зеленели бы на
// форме, разрешающей всем. Второе — объект под проектом, которого iam не знает:
// без него нельзя отличить «схема достроила по данным» от «схема достраивает
// всегда». Достройка обязана иметь предмет, а не быть безусловной.
func TestScopeReachesTheRootOnTheChainTheTreeActuallyProduces(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-any", "vpc_network", "get", "anchor", "{}")

		base := time.Now().UTC().Truncate(time.Microsecond)
		// ТОЛЬКО то звено, которое дерево действительно производит: vpc шлёт
		// ParentChain(nil, projectID, "") — один проект и ничего больше.
		registerThroughProducer(t, ctx, tx, catalogFormOf(t, "vpc_network"), "net-1",
			ownerregister.ParentChain(nil, "prj-1", ""), "prj-1", "", base)
		// Второй объект — под проектом, которого в `projects` НЕТ. Достройке не
		// из чего взять аккаунт, и цепь обязана остановиться.
		registerThroughProducer(t, ctx, tx, catalogFormOf(t, "vpc_network"), "net-7",
			ownerregister.ParentChain(nil, "prj-unknown", ""), "prj-unknown", "",
			base.Add(time.Millisecond))

		var edges int
		if err := tx.QueryRow(ctx,
			`SELECT count(*)::int FROM kaname.resource_parent_edge`).Scan(&edges); err != nil {
			t.Fatalf("перепись рёбер: %v", err)
		}
		if edges != 2 {
			t.Fatalf("рёбер в базе %d, ожидалось РОВНО ДВА (по одному на объект): фикстура "+
				"положила больше, чем производит дерево, и проба судила бы не то состояние", edges)
		}
		t.Logf("на цепи, которую производит дерево, рёбер всего %d — по одному звену у объекта", edges)

		ask := func(subject, objectID string) relverdict.Verdict {
			t.Helper()
			got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
				Subject: subject, ObjectType: "vpc_network", ObjectID: objectID, Relation: "v_get",
			})
			if err != nil {
				t.Fatalf("вопрос о %s над %s: %v", subject, objectID, err)
			}
			return got
		}
		grant := func(bindingID, scopeType, scopeID, subjectID string) {
			t.Helper()
			exec(t, ctx, tx,
				`INSERT INTO kaname.access_bindings
				   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
				 VALUES ($1, 'user', $4, 'rol-any', $2, $3, 'ACTIVE')`,
				bindingID, scopeType, scopeID, subjectID)
			exec(t, ctx, tx,
				`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
				 VALUES ($1, 'user', $2)`, bindingID, subjectID)
		}

		// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ПЕРВЫМ: до проекта обход доходит. Без него
		// утверждения ниже ничего не сказали бы о высоте цепи.
		grant("acb-prj", "project", "prj-1", "usr-1")
		if got := ask("user:usr-1", "net-1"); got != relverdict.Allow {
			t.Fatalf("выдача на ПРОЕКТ не достала до объекта: %s. Контроль провален, и "+
				"утверждения ниже ничего не говорят о высоте цепи", got)
		}
		exec(t, ctx, tx, `DELETE FROM kaname.access_bindings WHERE id = 'acb-prj'`)
		t.Log("контроль: выдача на проект — allow, обход до непосредственного предка работает")

		// (1) Выдача на АККАУНТ — два звена вверх, второе достроено схемой.
		grant("acb-acc", "account", "acc-1", "usr-1")
		if got := ask("user:usr-1", "net-1"); got != relverdict.Allow {
			t.Errorf("выдача на АККАУНТ не достала до объекта арендатора: %s. Владелец шлёт "+
				"одно звено, а предок проекта — его аккаунт — обязан браться из собственной "+
				"схемы iam, иначе верхний ярус выдач недостижим, а отказ неотличим от честного", got)
		}

		// (2) Прямой факт администратора облака на КЛАСТЕРЕ — три звена вверх.
		exec(t, ctx, tx,
			`INSERT INTO kaname.users (id, external_id, email, account_id)
			 VALUES ('usr-admin', 'ext-admin', 'admin@kacho.local', 'acc-1')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.relation_fact (object_type, object_id, relation, subject)
			 VALUES ('cluster', 'cluster_root', 'system_admin', 'user:usr-admin')`)
		if got := ask("user:usr-admin", "net-1"); got != relverdict.Allow {
			t.Errorf("администратор облака не достал до объекта арендатора: %s. Это аварийный "+
				"путь §«Три уровня супер-доступа»: он обязан работать независимо от состояния "+
				"конвейеров материализации", got)
		}

		// (3) ОТРИЦАНИЕ: объект под проектом, которого iam не знает, до корня не
		// поднимается — ни выдачей на аккаунт, ни фактом на кластере.
		if got := ask("user:usr-1", "net-7"); got != relverdict.Deny {
			t.Errorf("выдача на аккаунт достала до объекта под НЕИЗВЕСТНЫМ проектом: %s — "+
				"значит достройка безусловна и выдумывает предка, которого в данных нет", got)
		}
		if got := ask("user:usr-admin", "net-7"); got != relverdict.Deny {
			t.Errorf("администратор облака достал до объекта под НЕИЗВЕСТНЫМ проектом: %s — "+
				"см. выше: достройка обязана читать данные, а не подставлять корень всякому", got)
		}

		// (4) ОТРИЦАНИЕ: чужой аккаунт не достаёт и через достроенное звено.
		exec(t, ctx, tx,
			`INSERT INTO kaname.accounts (id, name, owner_user_id) VALUES ('acc-9', 'foreign', 'usr-1')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.users (id, external_id, email, account_id)
			 VALUES ('usr-out', 'ext-out', 'out@kacho.local', 'acc-1')`)
		grant("acb-foreign", "account", "acc-9", "usr-out")
		if got := ask("user:usr-out", "net-1"); got != relverdict.Deny {
			t.Errorf("выдача на ЧУЖОЙ аккаунт достала до объекта: %s — положительные "+
				"утверждения выше зеленели бы на форме, которая разрешает всем", got)
		}
	})
}

// TestAllFourEntryPointsAgreeOnAGrantAboveTheImmediateParent — В-3.
//
// # Дыра в покрытии, а не живой дефект
//
// Гейт формы области сверяет ТЕКСТ рекурсивного шага, приведённый к виду без
// номеров параметров. После нормализации `$7`, `$5` и `$3` неразличимы, поэтому
// подмена привязки — предел обхода вместо размера страницы — гейту невидима, а в
// `list.go` эти два параметра стоят рядом. Текстовый гейт этого класса не ловит
// by construction: он сверяет форму, а привязка — свойство вызова.
//
// Ловит его поведение, и до сих пор его никто не спрашивал: проб, читающих
// перечисление, субъектов и основания на выдаче ВЫШЕ непосредственного предка, в
// дереве не было ни одной. Все четыре точки входа сегодня сходятся — эта проба
// закрепляет схождение, чтобы расхождение стало видимым.
//
// Цепь берётся ТА, КОТОРУЮ ПРОИЗВОДИТ ДЕРЕВО (одно звено): расхождение между
// формами возможно и на достроенном схемой звене, а на досеянной полной цепи
// достройка не участвовала бы вовсе.
func TestAllFourEntryPointsAgreeOnAGrantAboveTheImmediateParent(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-acc", "vpc_network", "get", "anchor", "{}")
		registerThroughProducer(t, ctx, tx, catalogFormOf(t, "vpc_network"), "net-1",
			ownerregister.ParentChain(nil, "prj-1", ""), "prj-1", "",
			time.Now().UTC().Truncate(time.Microsecond))

		// Выдача на АККАУНТ — два звена вверх от объекта.
		exec(t, ctx, tx,
			`INSERT INTO kaname.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ('acb-acc', 'user', 'usr-1', 'rol-acc', 'account', 'acc-1', 'ACTIVE')`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-acc', 'user', 'usr-1')`)

		// (1) точечный вердикт
		verdict, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("точечный вердикт: %v", err)
		}

		// (2) перечисление объектов
		ids, _, err := relverdict.List(ctx, tx, relverdict.ListQuery{
			Subject: "user:usr-1", ObjectType: "vpc_network", Relation: "v_get", Limit: 50,
		})
		if err != nil {
			t.Fatalf("перечисление: %v", err)
		}
		listed := false
		for _, id := range ids {
			if id == "net-1" {
				listed = true
			}
		}

		// (3) перечисление субъектов
		subs, _, err := relverdict.Subjects(ctx, tx, relverdict.SubjectsQuery{
			ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get", Limit: 50,
		})
		if err != nil {
			t.Fatalf("перечисление субъектов: %v", err)
		}
		named := false
		for _, s := range subs {
			if s == "user:usr-1" {
				named = true
			}
		}

		// (4) разбор оснований
		grounds, err := relverdict.Expand(ctx, tx, "vpc_network", "net-1", "v_get")
		if err != nil {
			t.Fatalf("разбор оснований: %v", err)
		}

		t.Logf("выдача на аккаунт (два звена вверх): вердикт %s · в перечислении %v · "+
			"среди субъектов %v · оснований %d", verdict, listed, named, len(grounds))

		// СОГЛАСИЕ ЧЕТЫРЁХ. Расхождение здесь означает, что одна из форм
		// поднимается по цепи не на ту высоту, — а по какой причине (иной
		// предикат, иная привязка параметра), скажет уже разбор.
		if verdict != relverdict.Allow {
			t.Errorf("точечный вердикт %s при выдаче на аккаунт и цепи из одного звена", verdict)
		}
		if !listed {
			t.Errorf("перечисление не вернуло объект, который точечный вердикт разрешает: "+
				"формы отвечают на разной высоте цепи (вернулось %v)", ids)
		}
		if !named {
			t.Errorf("перечисление субъектов не назвало обладателя права: %v", subs)
		}
		if len(grounds) == 0 {
			t.Error("разбор не назвал ни одного основания там, где право есть: " +
				"обратный вопрос молчит про источник, по которому доступ реально выдан")
		}
	})
}

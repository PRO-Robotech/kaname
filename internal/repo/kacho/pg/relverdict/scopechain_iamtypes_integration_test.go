// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// scopechain_iamtypes_integration_test.go — ЦЕПЬ ОБЛАСТЕЙ ДОСТРАИВАЕТ ЗВЕНО ПЯТИ
// СОБСТВЕННЫМ ТИПАМ iam, И ВЫДАЧА НАВЕРХУ ДО НИХ ДОХОДИТ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (#785, приёмка R7-4, сценарии 06…10)
//
// Рёбра дерева пишет регистрация ресурса у владельца прав, и зовут её пять
// сервисов-соседей — только для СВОИХ объектов. Своих iam не регистрирует
// вовсе, поэтому у пользователя, группы, служебной учётки, роли и привязки
// множество областей состояло из них самих: выдача, сделанная НА АККАУНТ или НА
// ПРОЕКТ, до них не доходила, тогда как действующий решатель её разрешает.
// Отказ при этом НЕОТЛИЧИМ ОТ ЧЕСТНОГО — ни у вызывающего, ни в журнале.
//
// Миграция 785001 достраивает звено из СХЕМЫ, колонкой собственной строки
// объекта. Здесь утверждается, что из этого получается на вопросе о доступе.
//
// ─────────────────────────────────────────────────────────────────────────────
// СПРАШИВАЕТСЯ ОДНА ФОРМА, И ЭТО РЕШЕНИЕ ПРИЁМКИ, А НЕ УПУЩЕНИЕ
//
// `When` каждого сценария ниже задаёт вопрос ФОРМЕ E (`relverdict.Ask`) и
// только ей. Согласие двух форм на одном входе несут другие сценарии той же
// под-фазы — перепись источников (R7-4-11) и теневая сверка на стенде
// (R7-4-12), где обе формы отвечают рядом. Движок здесь не поднимается: проба
// этого слоя его не строит, и попытка спросить «обе формы» дала бы пробу,
// которую в этом слое не написать (приёмка §3.4).
//
// Прочтение «раз спрошена одна форма — паритет проверен» тоже неверно: группа B
// доказывает, что форма E отвечает САМОСОГЛАСОВАННО, и ничего сверх этого.
//
// ─────────────────────────────────────────────────────────────────────────────
// УТВЕРЖДАЕТСЯ ИСХОД ВОПРОСА, А НЕ СТРОКА ПРЕДСТАВЛЕНИЯ
//
// «Представление вернуло строку» — утверждение о форме, и оно осталось бы
// зелёным при любой ошибке в том, КАК эту строку читает обход. Спрашивается то
// же, что спрашивает продукт. Единственное исключение — R7-4-09: его предмет
// САМО ЗВЕНО (какой области принадлежит привязка), и там цепь спрашивается
// прямо; но и он несёт вердиктного близнеца, иначе «предка нет» означало бы и
// «область вне закрытого набора», и «ветвь не работает вовсе».
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕМ СЕЮТСЯ ФИКСТУРЫ — И ГДЕ ПРОИЗВОДИТЕЛЯ НЕТ
//
// Правило приёмки: фикстура сеется тем же производителем, каким её производит
// продукт. Здесь это разложилось на три случая, и каждый назван, потому что
// умолчание в этом месте однажды уже сделало гейт зелёным при вырезанном
// производителе:
//
//	· ПРОЕКЦИЯ ЖУРНАЛА (`relation_fact`) — производитель ровно один, триггер
//	  `relation_fact_follows_journal` на строке `kacho_iam.fga_outbox`. Всё, что
//	  ей принадлежит — указатель проекта на аккаунт, прямой факт администратора,
//	  — кладётся через `pointerThroughJournal`, а не прямой вставкой.
//	· РЁБРА ДЕРЕВА (`resource_parent_edge`) — производитель один,
//	  `resource_mirror.UpsertTx`. Для ПЯТИ ТИПОВ этой пробы он не зовётся
//	  НИКОГДА и не должен: ребро им обязана дать ветвь представления. Прямой
//	  посев ребра здесь запрещён — он обошёл бы ровно ту ветвь, которая и
//	  является предметом, и проба зеленела бы на данных, которых продукт не
//	  производит.
//	· СТРОКИ СОСТОЯНИЯ iam (`users`/`groups`/`service_accounts`/`roles`/
//	  `access_bindings`) — производителя, достижимого из этого слоя, У НИХ НЕТ:
//	  их пишут use-case'ы поверх `Repository`, а проба держит голую транзакцию.
//	  Поэтому они кладутся настоящими колонками и под настоящими ограничениями —
//	  так же, как их кладут соседние пробы пакета (`seedTenant`). Строка И ЕСТЬ
//	  объект: указатель на область лежит её собственной колонкой, поэтому посев
//	  строки — это и есть посев указателя, а не его подмена.

import (
	"context"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho-iam/internal/authzcascade"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
)

// ─────────────────────────────────────────────────────────────────────────────
// Обвязка
// ─────────────────────────────────────────────────────────────────────────────

// r74OwnObject — объект СОБСТВЕННОГО типа iam, заведённый внутри аккаунта пробы.
type r74OwnObject struct {
	// modelType — тип в том виде, в каком его называет вопрос о доступе.
	modelType string
	// id — идентификатор объекта.
	id string
	// what — чем этот объект является для читателя отчёта.
	what string
}

// r74FiveOwnTypes — пять объектов, по одному на собственный тип iam.
//
// Перечень ВЫПИСАН, а не выведен, и это осознанно: сценарии 06…10 приёмки
// говорят про пять ИМЕНОВАННЫХ типов и про то, ЧТО у каждого является областью
// (у роли — аккаунт либо проект, у привязки — её область), а такого знания в
// `DerivableTypes` нет. Полноту перечня против объявленного множества держит
// гейт Г1 (`scopechaincoverage_gate_test.go`); здесь она проверяется ПРЕДПОСЫЛКОЙ
// ниже, чтобы выписанный перечень не пережил появление шестого типа молча.
var r74FiveOwnTypes = []r74OwnObject{
	{modelType: "iam_user", id: "usr-own", what: "пользователь аккаунта"},
	{modelType: "iam_group", id: "grp-own", what: "группа аккаунта"},
	{modelType: "iam_service_account", id: "sac-own", what: "служебная учётка аккаунта"},
	{modelType: "iam_role", id: "rol-own", what: "роль аккаунта"},
	{modelType: "iam_access_binding", id: "acb-own", what: "привязка с областью «проект»"},
}

// r74AssertFiveTypesAreTheDerivableOnesMinusHierarchy — ПРЕДПОСЫЛКА перечня.
//
// Выписанный перечень не сдвинулся бы от нового типа сам. Сверка с объявленным
// множеством выводимых, за вычетом двух ярусов иерархии (аккаунт и проект — у
// них своя ветвь и свои пробы с #740/#781), делает его расхождение отказом
// первой же пробы, а не тихим сужением предмета.
func r74AssertFiveTypesAreTheDerivableOnesMinusHierarchy(t *testing.T) {
	t.Helper()
	want := make([]string, 0, len(authzcascade.DerivableTypes))
	for ty := range authzcascade.DerivableTypes {
		if ty == "account" || ty == "project" {
			continue
		}
		want = append(want, ty)
	}
	got := make([]string, 0, len(r74FiveOwnTypes))
	for _, o := range r74FiveOwnTypes {
		got = append(got, o.modelType)
	}
	sort.Strings(want)
	sort.Strings(got)
	if len(want) != len(got) {
		t.Fatalf("перечень пробы и объявленное множество выводимых разошлись: объявлено (без "+
			"аккаунта и проекта) %v, у пробы %v — сценарии 06…10 судили бы не тот предмет",
			want, got)
	}
	for i := range want {
		if want[i] != got[i] {
			t.Fatalf("перечень пробы и объявленное множество выводимых разошлись на позиции %d: "+
				"%q против %q (объявлено %v, у пробы %v)", i, want[i], got[i], want, got)
		}
	}
	t.Logf("предпосылка: собственных типов iam с выводимым предком %d, у каждого есть объект пробы", len(got))
}

// r74SeedCluster кладёт кластер-синглтон: он внешний ключ системной роли и
// вершина цепи. Идентификатор фиксирован ограничением схемы.
func r74SeedCluster(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.clusters (id, name) VALUES ('cluster_kacho_root', 'kacho')
		 ON CONFLICT DO NOTHING`)
}

// r74InertRole — роль, которая не раздаёт НИЧЕГО: ни проекции глаголов, ни
// селектора. Нужна как внешний ключ привязки-объекта, и именно инертная: роль с
// глаголами сделала бы саму привязку-фикстуру источником права, и «доступ есть»
// перестало бы говорить о звене.
const r74InertRole = "rol-inert"

func r74SeedInertRole(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	r74SeedCluster(t, ctx, tx)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.roles (id, name, permissions, rules, cluster_id)
		 VALUES ($1, 'inert.role', '[]'::jsonb,
		         jsonb_build_array(jsonb_build_object(
		             'module',    'test',
		             'resources', jsonb_build_array('*'),
		             'verbs',     jsonb_build_array('get'))),
		         'cluster_kacho_root')`, r74InertRole)
}

// r74SeedFiveOwnObjects кладёт по одному объекту каждого собственного типа iam
// внутрь аккаунта `acc-1`.
//
// Указатель на область у каждого — СОБСТВЕННАЯ КОЛОНКА строки: `account_id` у
// первых трёх, `account_id` у роли, пара `resource_type`/`resource_id` у
// привязки. Ребра в `resource_parent_edge` не кладётся НИ ОДНОГО — его обязана
// дать ветвь представления, и это проверяется предпосылкой числом.
//
// Область привязки-объекта — ПРОЕКТ, а не аккаунт: так у неё выходит ДВА звена
// вверх (привязка → проект → аккаунт), и «выдача на аккаунт достала» перестаёт
// быть утверждением про одно чтение.
func r74SeedFiveOwnObjects(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	r74SeedInertRole(t, ctx, tx)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
		 VALUES ('usr-own', 'ext-own', 'own@kacho.local', 'acc-1')`)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.groups (id, account_id, name) VALUES ('grp-own', 'acc-1', 'grp-own')`)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.service_accounts (id, account_id, name)
		 VALUES ('sac-own', 'acc-1', 'sac-own')`)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.roles (id, name, permissions, rules, account_id)
		 VALUES ('rol-own', 'own_account_role', '[]'::jsonb,
		         jsonb_build_array(jsonb_build_object(
		             'module',    'test',
		             'resources', jsonb_build_array('*'),
		             'verbs',     jsonb_build_array('get'))),
		         'acc-1')`)
	r74SeedBinding(t, ctx, tx, "acb-own", "usr-1", r74InertRole, "project", "prj-1")

	// ПРЕДПОСЫЛКА ЧИСЛОМ: ни у одного из пяти нет ПРИСЛАННОГО ребра. Иначе
	// «выдача достала» говорило бы о ребре фикстуры, а не о ветви представления,
	// — и ровно этим умолчанием соседняя проба меточной оси зеленеет на
	// собственноручно положенном ребре.
	var sent int
	if err := tx.QueryRow(ctx,
		`SELECT count(*)::int FROM kacho_iam.resource_parent_edge
		  WHERE object_type = ANY($1::text[])`,
		[]string{"iam_user", "iam_group", "iam_service_account", "iam_role", "iam_access_binding"},
	).Scan(&sent); err != nil {
		t.Fatalf("перепись присланных рёбер собственных типов: %v", err)
	}
	if sent != 0 {
		t.Fatalf("присланных рёбер у собственных типов iam %d, ожидался НОЛЬ: их не пишет ни "+
			"один производитель, и проба на таком состоянии судила бы фикстуру, а не ветвь", sent)
	}
}

// r74SeedBinding кладёт выдачу и её строку субъекта.
//
// Область субъекта заполняет триггер схемы (миграция 732001) — она берётся у
// самой выдачи, и назвать её здесь значило бы завести второе место об одном
// предмете.
func r74SeedBinding(t *testing.T, ctx context.Context, tx pgx.Tx,
	bindingID, subjectID, roleID, scopeType, scopeID string) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		 VALUES ($1, 'user', $2, $3, $4, $5, 'ACTIVE')`,
		bindingID, subjectID, roleID, scopeType, scopeID)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ($1, 'user', $2)`, bindingID, subjectID)
}

// r74SeedGrantRole — роль, раздающая глагол `get` на ВСЕ ПЯТЬ собственных типов
// iam одной ветвью-якорем.
//
// Одна роль, а не пять: выдача в сценарии одна («роль на аккаунт»), и разбивать
// её на пять значило бы проверять пять разных выдач вместо одной.
//
// Тип кладётся словарём КАТАЛОГА, взятым у каталога напрямую (`catalogFormOf`), а
// не переводчиком читателя: общая функция сместила бы обе стороны одинаково, и
// неверный перевод остался бы незамеченным — тот же довод, что у `seedRole`.
func r74SeedGrantRole(t *testing.T, ctx context.Context, tx pgx.Tx, roleID string) {
	t.Helper()
	r74SeedCluster(t, ctx, tx)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.roles (id, name, permissions, rules, cluster_id)
		 VALUES ($1, 'probe.grant', '[]'::jsonb,
		         jsonb_build_array(jsonb_build_object(
		             'module',    'test',
		             'resources', jsonb_build_array('*'),
		             'verbs',     jsonb_build_array('get'))),
		         'cluster_kacho_root')`, roleID)
	catalog := make([]string, 0, len(r74FiveOwnTypes))
	for _, o := range r74FiveOwnTypes {
		ct := catalogFormOf(t, o.modelType)
		catalog = append(catalog, ct)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.role_verb (role_id, object_type, verb) VALUES ($1, $2, 'get')`,
			roleID, ct)
	}
	// Ветвь ОДНА — якорная: она разрешает тип в области независимо от меток,
	// поэтому исход зависит от того, попал ли объект в ОБЛАСТЬ, а не от меток.
	// Именно область и является предметом.
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.role_rule_selectors
		   (role_id, rule_fp, arm, object_types, match_labels)
		 VALUES ($1, 'fp-1', 'anchor', $2::text[], '{}'::jsonb)`, roleID, catalog)
}

// r74Ask — вопрос форме E. Ошибка запроса — ОШИБКА, а не отказ: вернуть её как
// «нет прав» значило бы записать невыполненное в согласие.
func r74Ask(t *testing.T, ctx context.Context, tx pgx.Tx,
	subject, objectType, objectID, relation string) relverdict.Verdict {
	t.Helper()
	got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject: subject, ObjectType: objectType, ObjectID: objectID, Relation: relation,
	})
	if err != nil {
		t.Fatalf("вопрос «%s → %s над %s:%s»: %v", subject, relation, objectType, objectID, err)
	}
	return got
}

// r74ChainParents — что ЦЕПЬ называет предком объекта, в форме `<тип>:<id>`.
//
// Читается то же представление, которое читает обход вердикта. `suppress` гасит
// рёбра названных типов — это и есть инъекция «у типа нет ветви» (см. гейт Г1);
// на пустом срезе выражение тождественно обычному чтению цепи.
func r74ChainParents(t *testing.T, ctx context.Context, tx pgx.Tx,
	objectType, objectID string, suppress []string) []string {
	t.Helper()
	if suppress == nil {
		suppress = []string{}
	}
	rows, err := tx.Query(ctx,
		`SELECT parent_type || ':' || parent_id
		   FROM kacho_iam.resource_scope_edge
		  WHERE object_type = $1 AND object_id = $2
		    AND NOT (object_type = ANY ($3::text[]))
		  ORDER BY 1`, objectType, objectID, suppress)
	if err != nil {
		t.Fatalf("чтение цепи для %s:%s: %v", objectType, objectID, err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if err := rows.Scan(&p); err != nil {
			t.Fatalf("разбор звена %s:%s: %v", objectType, objectID, err)
		}
		out = append(out, p)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("чтение цепи для %s:%s: %v", objectType, objectID, err)
	}
	return out
}

// r74SeedForeignAccount кладёт ЧУЖОЙ аккаунт и пользователя в нём.
func r74SeedForeignAccount(t *testing.T, ctx context.Context, tx pgx.Tx, accountID, userID string) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.accounts (id, name, owner_user_id) VALUES ($1, $1, $2)`,
		accountID, userID)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
		 VALUES ($1, $1, $1 || '@kacho.local', $2)`, userID, accountID)
}

// ─────────────────────────────────────────────────────────────────────────────
// R7-4-06
// ─────────────────────────────────────────────────────────────────────────────

// TestR7_4_06_AccountGrantReachesIAMsOwnTypes — R7-4-06.
//
// # Что утверждается
//
// Выдача роли НА АККАУНТ доходит до объекта каждого из пяти собственных типов
// iam. Это и есть расширение охвата, которое достраивает 785001: администратор
// аккаунта получает управление содержимым своего аккаунта.
//
// # Три контроля, и ни один не факультативен
//
//	S2 — субъект БЕЗ единой выдачи: обе стороны отказывают. Без него «allow»
//	     зеленело бы на форме, которая разрешает всем;
//	S3 — та же выдача в ЧУЖОМ аккаунте: пересечение аренд закрыто. Без него
//	     «звено есть» было бы неотличимо от «звено ведёт куда попало»;
//	S4 — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: выдача ПРЯМО НА ОБЪЕКТ отвечала `allow` и до
//	     правки и обязана отвечать `allow` после. Без него «стало лучше»
//	     неотличимо от «форма стала отвечать всем да».
//
// # Почему проба красна ДО правки и по какой причине
//
// До 785001 представление `resource_scope_edge` знает три ветви: присланные
// рёбра, предок проекта из проекции журнала, предок аккаунта из схемы. У пяти
// собственных типов iam присланного ребра нет НИ ОДНОГО (это проверено
// предпосылкой), поэтому область объекта состоит из него самого, выдача на
// аккаунт в неё не попадает и S1 получает `deny` по всем пяти. Красное на S1
// при зелёном S4 — это и есть нужная причина; красное на S4 означало бы
// сломанную фикстуру, а не предмет.
func TestR7_4_06_AccountGrantReachesIAMsOwnTypes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		r74AssertFiveTypesAreTheDerivableOnesMinusHierarchy(t)
		seedTenant(t, ctx, tx)
		r74SeedFiveOwnObjects(t, ctx, tx)
		r74SeedGrantRole(t, ctx, tx, "rol-grant")

		// S1 — выдача на АККАУНТ `acc-1`.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
			 VALUES ('usr-s1', 'ext-s1', 's1@kacho.local', 'acc-1')`)
		r74SeedBinding(t, ctx, tx, "acb-s1", "usr-s1", "rol-grant", "account", "acc-1")

		// S2 — без единой выдачи.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
			 VALUES ('usr-s2', 'ext-s2', 's2@kacho.local', 'acc-1')`)

		// S3 — такая же выдача в ЧУЖОМ аккаунте.
		r74SeedForeignAccount(t, ctx, tx, "acc-9", "usr-s3")
		r74SeedBinding(t, ctx, tx, "acb-s3", "usr-s3", "rol-grant", "account", "acc-9")

		// S4 — положительный контроль: выдача ПРЯМО на каждый объект.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
			 VALUES ('usr-s4', 'ext-s4', 's4@kacho.local', 'acc-1')`)
		for _, o := range r74FiveOwnTypes {
			r74SeedBinding(t, ctx, tx,
				"acb-s4-"+o.modelType, "usr-s4", "rol-grant", o.modelType, o.id)
		}

		for _, o := range r74FiveOwnTypes {
			// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ ПЕРВЫМ: вопрос, отвечавший `allow` и до
			// правки, обязан отвечать так же. Провал здесь означает сломанную
			// обвязку, и утверждения ниже тогда не говорят ни о чём.
			if got := r74Ask(t, ctx, tx, "user:usr-s4", o.modelType, o.id, "v_get"); got != relverdict.Allow {
				t.Fatalf("КОНТРОЛЬ ПРОВАЛЕН: выдача ПРЯМО на объект %s (%s:%s) не дала права: %s. "+
					"Этот вопрос отвечал allow и до достройки звена, значит сломана обвязка пробы, "+
					"а не предмет — и утверждения ниже ничего не говорят", o.what, o.modelType, o.id, got)
			}

			// ПРЕДМЕТ: выдача на АККАУНТ доходит до объекта.
			if got := r74Ask(t, ctx, tx, "user:usr-s1", o.modelType, o.id, "v_get"); got != relverdict.Allow {
				t.Errorf("выдача роли на АККАУНТ acc-1 не достала до объекта %s (%s:%s): %s. "+
					"Указатель на область лежит колонкой собственной строки объекта, а цепь его "+
					"не читает — область схлопнулась до самого объекта, выдача верхнего яруса "+
					"недостижима, и отказ НЕОТЛИЧИМ ОТ ЧЕСТНОГО (#785)", o.what, o.modelType, o.id, got)
			}

			// ОТРИЦАТЕЛЬНЫЙ КОНТРОЛЬ: без выдачи прав нет.
			if got := r74Ask(t, ctx, tx, "user:usr-s2", o.modelType, o.id, "v_get"); got != relverdict.Deny {
				t.Errorf("субъект БЕЗ единой выдачи получил доступ к %s (%s:%s): %s — значит "+
					"утверждение выше зеленело бы на форме, которая разрешает всем",
					o.what, o.modelType, o.id, got)
			}

			// КОНТРОЛЬ ПЕРЕСЕЧЕНИЯ АРЕНД: выдача в чужом аккаунте не достаёт.
			if got := r74Ask(t, ctx, tx, "user:usr-s3", o.modelType, o.id, "v_get"); got != relverdict.Deny {
				t.Errorf("выдача на ЧУЖОЙ аккаунт acc-9 достала до объекта %s (%s:%s): %s — "+
					"звено подставляется безусловно, а не читается из колонки объекта",
					o.what, o.modelType, o.id, got)
			}
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// R7-4-07
// ─────────────────────────────────────────────────────────────────────────────

// TestR7_4_07_ProjectGrantReachesTheBindingAndTheProjectRole — R7-4-07.
//
// # Что утверждается
//
// Выдача НА ПРОЕКТ доходит до двух объектов, чья область — проект: до привязки с
// этой областью и до ПРОЕКТНОЙ роли. У проектной роли `account_id` пуст по
// ограничению `roles_definition_tier_xor`, поэтому без проектной ветви её цепь
// пуста ЦЕЛИКОМ — не «короче», а пуста (решение Р3).
//
// # Почему тот же вопрос задаётся ещё и АККАУНТНОМУ субъекту
//
// Чтобы утверждение говорило о ЦЕПИ, а не об одном звене. Аккаунтный субъект
// достаёт до этих объектов только обходом `объект → проект → аккаунт`, где
// первое звено даёт схема (785001), а второе — проекция журнала (781001). Одно
// чтение сюда не доходит by construction.
//
// # Почему проба красна ДО правки
//
// До 785001 ни у проектной роли, ни у привязки нет ни присланного ребра, ни
// выведенного: область каждой состоит из неё самой. Проектный субъект получает
// `deny`, аккаунтный — тоже. Отрицание (выдача на ДРУГОЙ проект) при этом зелено
// и до правки — поэтому оно здесь и не одиноко: без положительной половины оно
// зеленело бы на цепи, которой нет вовсе.
func TestR7_4_07_ProjectGrantReachesTheBindingAndTheProjectRole(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		r74SeedInertRole(t, ctx, tx)
		r74SeedGrantRole(t, ctx, tx, "rol-grant")

		// ВТОРОЙ ПРОЕКТ ТОГО ЖЕ АККАУНТА — и он заведён ПОЛНОЦЕННО, с
		// указателем в журнале. Отрицание на калечной фикстуре объясняется
		// фикстурой, а не предметом.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.projects (id, account_id, name) VALUES ('prj-2', 'acc-1', 'second-project')`)
		pointerThroughJournal(t, ctx, tx, "project", "prj-2", "account", "account:acc-1")

		// ПРОЕКТНАЯ роль: аккаунта у неё нет по ограничению схемы.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.roles (id, name, permissions, rules, project_id)
			 VALUES ('rol-proj', 'own_project_role', '[]'::jsonb,
			         jsonb_build_array(jsonb_build_object(
			             'module',    'test',
			             'resources', jsonb_build_array('*'),
			             'verbs',     jsonb_build_array('get'))),
			         'prj-1')`)
		// ПРЕДПОСЫЛКА: аккаунта у проектной роли действительно нет — иначе она
		// доставалась бы аккаунтной ветвью (5a), и проба судила бы не ту ветвь.
		var roleAccount string
		if err := tx.QueryRow(ctx,
			`SELECT COALESCE(account_id, '') FROM kacho_iam.roles WHERE id = 'rol-proj'`).Scan(&roleAccount); err != nil {
			t.Fatalf("перепись аккаунта проектной роли: %v", err)
		}
		if roleAccount != "" {
			t.Fatalf("у проектной роли аккаунт %q, ожидался пустой: тогда она достаётся аккаунтной "+
				"ветвью, и проба ничего не сказала бы о проектной", roleAccount)
		}
		t.Log("предпосылка: у проектной роли account_id пуст — до аккаунта она поднимается только обходом")

		// Привязка с областью «проект».
		r74SeedBinding(t, ctx, tx, "acb-proj", "usr-1", r74InertRole, "project", "prj-1")

		// Субъект с выдачей на ПРОЕКТ prj-1.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
			 VALUES ('usr-p1', 'ext-p1', 'p1@kacho.local', 'acc-1')`)
		r74SeedBinding(t, ctx, tx, "acb-p1", "usr-p1", "rol-grant", "project", "prj-1")

		// Субъект с выдачей на ДРУГОЙ проект того же аккаунта.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
			 VALUES ('usr-p2', 'ext-p2', 'p2@kacho.local', 'acc-1')`)
		r74SeedBinding(t, ctx, tx, "acb-p2", "usr-p2", "rol-grant", "project", "prj-2")

		// Субъект с выдачей на АККАУНТ.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
			 VALUES ('usr-pa', 'ext-pa', 'pa@kacho.local', 'acc-1')`)
		r74SeedBinding(t, ctx, tx, "acb-pa", "usr-pa", "rol-grant", "account", "acc-1")

		targets := []r74OwnObject{
			{modelType: "iam_access_binding", id: "acb-proj", what: "привязка с областью «проект»"},
			{modelType: "iam_role", id: "rol-proj", what: "проектная роль"},
		}
		for _, o := range targets {
			if got := r74Ask(t, ctx, tx, "user:usr-p1", o.modelType, o.id, "v_get"); got != relverdict.Allow {
				t.Errorf("выдача на ПРОЕКТ prj-1 не достала до объекта %s (%s:%s): %s. Область "+
					"объекта названа колонкой его собственной строки, а цепь её не читает",
					o.what, o.modelType, o.id, got)
			}
			if got := r74Ask(t, ctx, tx, "user:usr-p2", o.modelType, o.id, "v_get"); got != relverdict.Deny {
				t.Errorf("выдача на ДРУГОЙ проект prj-2 достала до объекта %s (%s:%s): %s — "+
					"звено ведёт не туда, куда указывает колонка", o.what, o.modelType, o.id, got)
			}
			if got := r74Ask(t, ctx, tx, "user:usr-pa", o.modelType, o.id, "v_get"); got != relverdict.Allow {
				t.Errorf("выдача на АККАУНТ acc-1 не достала до объекта %s (%s:%s): %s. Цепь "+
					"обязана подниматься ОБХОДОМ «объект → проект → аккаунт»: первое звено даёт "+
					"схема, второе — проекция журнала; одним чтением сюда не дойти",
					o.what, o.modelType, o.id, got)
			}
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// R7-4-08
// ─────────────────────────────────────────────────────────────────────────────

// TestR7_4_08_CloudAdministratorReachesIAMsOwnTypesThroughTheAccount — R7-4-08.
//
// # Что утверждается
//
// Прямой факт администратора облака на КЛАСТЕРЕ достаёт до объекта каждого из
// пяти собственных типов iam. Путь идёт `объект → аккаунт → кластер` (у
// привязки с областью «проект» — на звено длиннее), и это тот самый аварийный
// путь, который `security.md` §«Три уровня супер-доступа» держит каскадом
// именно затем, чтобы он работал, когда сломалось всё остальное.
//
// # Почему это блокирующее свойство, а не «ответ стал полнее»
//
// Отказ на верхнем ярусе байт-в-байт неотличим от честного. Пока цепь не
// доходила до кластера, администратор облака не имел пути к содержимому iam — и
// узнать об этом было неоткуда.
//
// # Почему рядом стоит субъект БЕЗ факта
//
// Иначе «allow» зеленело бы на форме, которая разрешает всякому; факт на
// кластере — самое широкое право в дереве, и проверять его без отрицания
// бессмысленно.
//
// # Почему проба красна ДО правки
//
// Раскладка модели даёт источник «факт `system_admin` на предке типа `cluster`».
// Пока у объекта нет звена к аккаунту, кластер в его область не попадает, и
// источник не совпадает ни с одной строкой: `deny` по всем пяти.
func TestR7_4_08_CloudAdministratorReachesIAMsOwnTypesThroughTheAccount(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		r74SeedFiveOwnObjects(t, ctx, tx)

		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
			 VALUES ('usr-cloud', 'ext-cloud', 'cloud@kacho.local', 'acc-1')`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
			 VALUES ('usr-plain', 'ext-plain', 'plain@kacho.local', 'acc-1')`)
		// Факт кладётся ЖУРНАЛОМ — единственным производителем проекции.
		pointerThroughJournal(t, ctx, tx,
			"cluster", "cluster_kacho_root", "system_admin", "user:usr-cloud")

		for _, o := range r74FiveOwnTypes {
			if got := r74Ask(t, ctx, tx, "user:usr-cloud", o.modelType, o.id, "v_get"); got != relverdict.Allow {
				t.Errorf("администратор облака не достал до объекта %s (%s:%s): %s. Цепь не "+
					"доходит от объекта до кластера, и аварийный путь §«Три уровня супер-доступа» "+
					"отвечает отказом, НЕОТЛИЧИМЫМ от честного", o.what, o.modelType, o.id, got)
			}
			if got := r74Ask(t, ctx, tx, "user:usr-plain", o.modelType, o.id, "v_get"); got != relverdict.Deny {
				t.Errorf("субъект БЕЗ факта администратора получил доступ к %s (%s:%s): %s — "+
					"значит утверждение выше зеленело бы на форме, разрешающей всякому",
					o.what, o.modelType, o.id, got)
			}
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// R7-4-09
// ─────────────────────────────────────────────────────────────────────────────

// r74ScopedBinding — привязка и то, чего от её области ждёт закрытый набор.
type r74ScopedBinding struct {
	id         string
	scopeType  string
	scopeID    string
	wantParent string // пусто — предка быть НЕ должно
	why        string
}

// TestR7_4_09_BindingOutsideTheThreeScopesGetsNoParent — R7-4-09.
//
// # Что утверждается
//
// Привязка получает предка ТОГО ТИПА, который называет её область, и только для
// трёх областных значений закрытого набора (`isBindableScope`). Привязка,
// областью которой является ресурс арендатора, и привязка с областью `'*'`
// предка НЕ получают — и это НЕ потеря, а законный исход (решение Р8): у такой
// области нет яруса иерархии, к которому можно подняться.
//
// # Почему здесь спрашивается цепь, а не только вердикт
//
// Предмет сценария — САМО ЗВЕНО: чей области принадлежит привязка. Но «предка
// нет» само по себе означает и «область вне набора», и «ветвь не работает
// вовсе», поэтому положительный близнец обязателен и стоит в той же таблице:
// три области получают предка, две — нет. Рядом — вердиктный близнец: он
// говорит, ЧТО предок значит, и что его отсутствие означает недостижимость, а
// не тишину.
//
// # Почему проба красна ДО правки
//
// До 785001 предка не получает НИ ОДНА из пяти: положительная половина красна
// целиком. Отрицательная половина зелена и до правки — этого мало, чтобы
// считать сценарий выполненным, и ровно затем половины и стоят рядом.
func TestR7_4_09_BindingOutsideTheThreeScopesGetsNoParent(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		r74SeedInertRole(t, ctx, tx)

		bindings := []r74ScopedBinding{
			{id: "acb-c-acc", scopeType: "account", scopeID: "acc-1",
				wantParent: "account:acc-1", why: "область — аккаунт, ярус иерархии есть"},
			{id: "acb-c-prj", scopeType: "project", scopeID: "prj-1",
				wantParent: "project:prj-1", why: "область — проект, ярус иерархии есть"},
			{id: "acb-c-clu", scopeType: "cluster", scopeID: "cluster_kacho_root",
				wantParent: "cluster:cluster_kacho_root", why: "область — кластер, ярус иерархии есть"},
			{id: "acb-c-res", scopeType: "vpc_network", scopeID: "net-1",
				wantParent: "", why: "область — ресурс арендатора: яруса, к которому подниматься, нет"},
			{id: "acb-c-any", scopeType: "*", scopeID: "*",
				wantParent: "", why: "область — подстановка: конкретного объекта она не называет"},
		}
		for _, b := range bindings {
			r74SeedBinding(t, ctx, tx, b.id, "usr-1", r74InertRole, b.scopeType, b.scopeID)
		}

		var withParent, without int
		for _, b := range bindings {
			got := r74ChainParents(t, ctx, tx, "iam_access_binding", b.id, nil)
			switch {
			case b.wantParent == "":
				without++
				if len(got) != 0 {
					t.Errorf("привязка %s (%s) получила предка %v, а не должна была: %s. Набор "+
						"областей, дающих предка, ЗАКРЫТ (project|account|cluster), и расширять "+
						"его молча значит вести обход к ярусу, которого у этой области нет",
						b.id, b.scopeType, got, b.why)
				}
			case len(got) != 1 || got[0] != b.wantParent:
				withParent++
				t.Errorf("привязка %s (%s) назвала предком %v, ожидалось ровно [%s]: %s",
					b.id, b.scopeType, got, b.wantParent, b.why)
			default:
				withParent++
			}
		}
		t.Logf("осмотрено привязок %d: с предком ожидалось %d, без предка ожидалось %d",
			len(bindings), withParent, without)
		if withParent == 0 || without == 0 {
			t.Fatalf("одна из половин пробы пуста (с предком %d, без предка %d) — тогда вторая "+
				"половина ничего не утверждает: «предка нет» стало бы неотличимо от «ветвь мертва»",
				withParent, without)
		}

		// ВЕРДИКТНЫЙ БЛИЗНЕЦ: что предок ЗНАЧИТ. Администратор аккаунта достаёт
		// до привязки своей области и НЕ достаёт до той, чья область вне набора.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
			 VALUES ('usr-adm', 'ext-adm', 'adm@kacho.local', 'acc-1')`)
		pointerThroughJournal(t, ctx, tx, "account", "acc-1", "admin", "user:usr-adm")

		if got := r74Ask(t, ctx, tx, "user:usr-adm", "iam_access_binding", "acb-c-acc", "v_get"); got != relverdict.Allow {
			t.Errorf("администратор аккаунта не достал до привязки СВОЕЙ области: %s — предок "+
				"есть, а обход его не читает", got)
		}
		if got := r74Ask(t, ctx, tx, "user:usr-adm", "iam_access_binding", "acb-c-res", "v_get"); got != relverdict.Deny {
			t.Errorf("администратор аккаунта достал до привязки, чья область — ресурс арендатора: "+
				"%s. Предка у неё нет by construction, и доступ означал бы, что область берётся "+
				"не из её колонок", got)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// R7-4-10
// ─────────────────────────────────────────────────────────────────────────────

// TestR7_4_10_RevokedBindingKeepsItsParentAndReturnsNoGrant — R7-4-10.
//
// # Что утверждается — форма E, и только она
//
// Отозванная привязка сохраняет предка: строка жива, отзыв записан, а звено
// выводится из КОЛОНОК СТРОКИ и статуса не читает (решение Р4). Поэтому
// администратор её аккаунта по-прежнему достаёт до самой записи — отозванную
// выдачу надо иметь возможность прочитать и удалить. Прежний получатель при
// этом теряет доступ К ОБЛАСТИ: указатель на привязку выдачи не восстанавливает.
//
// # Что здесь НЕ повторяется
//
// То же свойство на стороне ДВИЖКА уже закреплено —
// `service/cascade_queue_independence_integration_test.go`,
// `TestRevokedBindingStaysManageableAndGrantsNothing`. Здесь утверждается
// сторона формы E: тот же исход, полученный чтением своей БД.
//
// # «И когда очередь отстала» — проверяется числом, а не словом
//
// Указателя привязки в проекции журнала нет НИ ОДНОГО (перепись ниже), и
// присланного ребра тоже нет. Значит `allow` администратора не может прийти
// ниоткуда, кроме как из колонок самой строки.
//
// # Почему проба красна ДО правки и какая её половина
//
// Красна половина про администратора: без ветви (6) у привязки нет предка, её
// область состоит из неё самой, факт `admin` на аккаунте в неё не попадает —
// `deny`. Половина «прежний получатель потерял доступ к области» зелена и ДО
// правки: её держит отбор `status = 'ACTIVE' AND revoked_at IS NULL` в ветви
// выдач, которого 785001 не касается. Она здесь не как предмет, а как
// обязательная пара: без неё «администратор достаёт» было бы неотличимо от
// «форма вернула права всем, включая отозванных».
func TestR7_4_10_RevokedBindingKeepsItsParentAndReturnsNoGrant(t *testing.T) {
	if testing.Short() {
		t.Skip("integration")
	}
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		r74SeedGrantRole(t, ctx, tx, "rol-grant")

		// Роль, дающая получателю право НА ОБЛАСТЬ (на сам аккаунт).
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.roles (id, name, permissions, rules, cluster_id)
			 VALUES ('rol-scope', 'probe.scope', '[]'::jsonb,
			         jsonb_build_array(jsonb_build_object(
			             'module',    'test',
			             'resources', jsonb_build_array('*'),
			             'verbs',     jsonb_build_array('get'))),
			         'cluster_kacho_root')`)
		accountCatalog := catalogFormOf(t, "account")
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.role_verb (role_id, object_type, verb) VALUES ('rol-scope', $1, 'get')`,
			accountCatalog)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.role_rule_selectors
			   (role_id, rule_fp, arm, object_types, match_labels)
			 VALUES ('rol-scope', 'fp-1', 'anchor', ARRAY[$1::text], '{}'::jsonb)`, accountCatalog)

		// Получатель выдачи и администратор аккаунта.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
			 VALUES ('usr-grantee', 'ext-grantee', 'grantee@kacho.local', 'acc-1')`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
			 VALUES ('usr-adm', 'ext-adm', 'adm@kacho.local', 'acc-1')`)
		pointerThroughJournal(t, ctx, tx, "account", "acc-1", "admin", "user:usr-adm")

		r74SeedBinding(t, ctx, tx, "acb-rev", "usr-grantee", "rol-scope", "account", "acc-1")

		// ПРЕДПОСЫЛКА: выдача ДЕЙСТВУЕТ. Без неё «отозван — значит нет прав»
		// осталось бы верным и на форме, которая не давала их никогда.
		if got := r74Ask(t, ctx, tx, "user:usr-grantee", "account", "acc-1", "v_get"); got != relverdict.Allow {
			t.Fatalf("ПРЕДПОСЫЛКА ПРОВАЛЕНА: действующая выдача не дала получателю права на область: "+
				"%s. Тогда её отзыв ничего не отнимает, и утверждение ниже вакуумно", got)
		}
		t.Log("предпосылка: действующая выдача даёт получателю право на область — отзыву есть что отнять")

		// ОТЗЫВ ровно так, как его делает продукт: строка жива, статус сменён.
		exec(t, ctx, tx,
			`UPDATE kacho_iam.access_bindings
			    SET status = 'REVOKED', revoked_at = now(), revoked_by_user_id = 'usr-adm'
			  WHERE id = 'acb-rev'`)

		// ПРЕДПОСЫЛКА «ОЧЕРЕДЬ ОТСТАЛА», названная числами: ни доставленного
		// указателя, ни присланного ребра у привязки нет.
		delivered := countScalar(t, ctx, tx,
			`SELECT count(*)::int FROM kacho_iam.relation_fact
			  WHERE object_type = 'iam_access_binding' AND object_id = 'acb-rev'`)
		sent := countScalar(t, ctx, tx,
			`SELECT count(*)::int FROM kacho_iam.resource_parent_edge
			  WHERE object_type = 'iam_access_binding' AND object_id = 'acb-rev'`)
		if delivered != 0 || sent != 0 {
			t.Fatalf("у привязки нашлись доставленный указатель (%d) либо присланное ребро (%d) — "+
				"предмет пробы исчез: она судила бы доставку, а не вывод из строки", delivered, sent)
		}
		t.Log("предпосылка: доставленных указателей у привязки 0, присланных рёбер 0 — " +
			"всё, что ответит ниже, выведено из колонок её строки")

		// ЗВЕНО СОХРАНЕНО: статус его не касается.
		if got := r74ChainParents(t, ctx, tx, "iam_access_binding", "acb-rev", nil); len(got) != 1 || got[0] != "account:acc-1" {
			t.Errorf("отозванная привязка назвала предком %v, ожидалось ровно [account:acc-1]. "+
				"Звено обязано выводиться из колонок области и не читать статус (Р4)", got)
		}

		// ПРЕДМЕТ: запись остаётся читаемой и удаляемой её администратором.
		if got := r74Ask(t, ctx, tx, "user:usr-adm", "iam_access_binding", "acb-rev", "v_delete"); got != relverdict.Allow {
			t.Errorf("администратор аккаунта не достал до ОТОЗВАННОЙ привязки: %s. Отозванная "+
				"выдача — запись, которую обязаны иметь возможность прочитать и удалить; отняв "+
				"это, мы получаем запертую запись ровно тогда, когда конвейеры отстают", got)
		}

		// ПАРА: выдачи отзыв не возвращает.
		if got := r74Ask(t, ctx, tx, "user:usr-grantee", "account", "acc-1", "v_get"); got != relverdict.Deny {
			t.Errorf("прежний получатель сохранил право на ОБЛАСТЬ после отзыва: %s — указатель "+
				"на привязку не смеет восстанавливать выдачу", got)
		}

		// КОНТРОЛЬ ЧУЖОГО: администратор acc-1 не достаёт до привязки чужого
		// аккаунта. Без него «администратор достаёт» зеленело бы на форме,
		// которая разрешает администратору всё подряд.
		r74SeedForeignAccount(t, ctx, tx, "acc-9", "usr-foreign")
		r74SeedBinding(t, ctx, tx, "acb-foreign", "usr-foreign", "rol-scope", "account", "acc-9")
		if got := r74Ask(t, ctx, tx, "user:usr-adm", "iam_access_binding", "acb-foreign", "v_delete"); got != relverdict.Deny {
			t.Errorf("администратор acc-1 достал до привязки ЧУЖОГО аккаунта acc-9: %s — звено "+
				"ведёт не туда, куда указывает колонка области", got)
		}
	})
}

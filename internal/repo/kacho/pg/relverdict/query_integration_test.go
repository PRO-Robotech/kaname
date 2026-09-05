// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// query_integration_test.go — вердикт формы E на НАСТОЯЩЕЙ схеме iam.
//
// # Почему интеграционная, а не юнит
//
// Предмет — запрос: он либо согласуется с реальными таблицами, либо нет, и
// подставной репозиторий об этом не скажет ничего. Проба, доказывающая, что
// SQL компилируется, доказывала бы свойство текста, а не доступа.
//
// # Что утверждается по каждому источнику
//
// По одному сценарию на источник — и по отрицанию рядом с каждым. Отрицание без
// положительного контроля зеленеет на сломанном запросе: «нет прав» и «запрос
// ничего не находит никогда» дают один ответ.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho/pkg/pgtest"
)

func withTx(t *testing.T, fn func(ctx context.Context, tx pgx.Tx)) {
	t.Helper()
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, pgtest.NewDB(t))
	if err != nil {
		t.Fatalf("пул: %v", err)
	}
	t.Cleanup(pool.Close)
	tx, err := pool.Begin(ctx)
	if err != nil {
		t.Fatalf("транзакция: %v", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	fn(ctx, tx)
}

// exec — короткая обёртка: посев в пробе не должен тонуть в проверках ошибок.
func exec(t *testing.T, ctx context.Context, tx pgx.Tx, sql string, args ...any) {
	t.Helper()
	if _, err := tx.Exec(ctx, sql, args...); err != nil {
		t.Fatalf("посев (%s): %v", sql, err)
	}
}

// seedTenant кладёт минимальную арендную обвязку: аккаунт, проект, пользователя.
//
// Сеется НАСТОЯЩИМИ строками, а не обходом внешних ключей. Проба, снимающая FK
// ради удобства, доказывала бы работу запроса на данных, которых в проде не
// бывает, — и первое же расхождение схемы с моделью в голове осталось бы
// незамеченным. Ровно этот вид расхождения проба здесь и нашла пять раз.
func seedTenant(t *testing.T, ctx context.Context, tx pgx.Tx) {
	t.Helper()
	// Ссылка КРУГОВАЯ: у аккаунта есть владелец-пользователь, у пользователя —
	// аккаунт. Разрешается это отложенным внешним ключом владельца
	// (`DEFERRABLE INITIALLY DEFERRED`, см. data-integrity.md): аккаунт вставляется
	// первым, ссылаясь на ещё не существующего владельца, и ключ проверяется на
	// COMMIT. Порядок несущий — обратный даёт отказ сразу.
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.accounts (id, name, owner_user_id)
		 VALUES ('acc-1', 'test-account', 'usr-1') ON CONFLICT DO NOTHING`)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.users (id, external_id, email, account_id)
		 VALUES ('usr-1', 'ext-1', 'usr-1@kacho.local', 'acc-1') ON CONFLICT DO NOTHING`)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.projects (id, account_id, name) VALUES ('prj-1', 'acc-1', 'test-project')
		 ON CONFLICT DO NOTHING`)
	// Указатель на аккаунт — В ЖУРНАЛ, потому что его туда кладёт САМ ПРОДУКТ:
	// `Project.Create` со-коммитит иерархический кортеж в той же транзакции, что
	// строку `projects` (проба `project must co-commit project→account hierarchy`).
	//
	// Фикстура, писавшая ОДНУ строку состояния, строила проект, о котором движок
	// отношений не знает вовсе, — состояние, которого продукт не производит. Пока
	// цепь брала предка из `projects`, это было незаметно; с #781 предок берётся
	// оттуда же, откуда его берёт движок, и умолчание фикстуры стало видно.
	pointerThroughJournal(t, ctx, tx, "project", "prj-1", "account", "account:acc-1")
}

// seedRole кладёт роль и её проекцию глаголов.
// seedRole кладёт роль, её проекцию глаголов и селектор ОДНОЙ ветви.
//
// Ветвь параметром, а не всегда якорь: якорная ветвь разрешает весь тип в
// области независимо от меток, поэтому роль, несущая её ВМЕСТЕ с меточной,
// сделала бы проверку меток бессмысленной — и проба зеленела бы на запросе,
// который метки не читает вовсе.
func seedRole(t *testing.T, ctx context.Context, tx pgx.Tx, roleID, objType, verb, arm string, labels string) {
	t.Helper()
	// Роль системная — но `is_system` НЕ задаётся: с миграции 0056 это
	// вычисляемая колонка (`cluster_id IS NOT NULL`). Ровно этот вид расхождения
	// модели схемы с деревом проба и ловит: посев, обходящий настоящие
	// ограничения, доказывал бы работу запроса на данных, которых в проде нет.
	// Пустые `permissions` законны только при непустых `rules`
	// (`roles_permissions_valid`): роль обязана хоть чем-то адресовать объекты.
	// Проекция глаголов при этом кладётся отдельно — она и есть предмет запроса.
	// Кластер — внешний ключ роли, и он СИНГЛТОН: идентификатор фиксирован
	// ограничением схемы. Сеем настоящий, а не обходим FK: фикстура, снимающая
	// ограничение, доказывала бы работу запроса на данных, которых в проде нет.
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.clusters (id, name) VALUES ('cluster_kacho_root', 'kacho')
		 ON CONFLICT DO NOTHING`)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.roles (id, name, permissions, rules, cluster_id)
		 VALUES ($1, $2, '[]'::jsonb,
		         jsonb_build_array(jsonb_build_object(
		             'module',    'test',
		             'resources', jsonb_build_array('*'),
		             'verbs',     jsonb_build_array($3::text))),
		         'cluster_kacho_root')`, roleID, "test."+verb, verb)
	// ТИП КЛАДЁТСЯ В ТОЙ ФОРМЕ, В КАКОЙ ЕГО КЛАДЁТ ПРОД, — точечной. Вопрос о
	// доступе приходит формой модели прав, и посев её же доказывал бы согласие
	// запроса с фикстурой, а не с продом: соединение сходилось бы на данных,
	// которых в проде не бывает. Перевод берётся ТОТ ЖЕ, каким его делает
	// читатель, — второго словаря в дереве не заводится.
	// Посев берёт КАТАЛОГ напрямую, а не функцию читателя. Иначе фикстура и
	// продукт зовут одно и то же, и проба доказывает согласие запроса С САМИМ
	// СОБОЙ: неверный переводчик сместил бы обе стороны одинаково и остался бы
	// незамеченным. Проверено инъекцией — при общей функции подмена перевода
	// НЕ роняла ни одной пробы.
	grantType, known := authzmap.DottedType(objType)
	if !known {
		grantType = objType
	}
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.role_verb (role_id, object_type, verb) VALUES ($1, $2, $3)`,
		roleID, grantType, verb)
	// Без селектора роль не адресует ни одного объекта — и это верно, а не
	// пробел фикстуры.
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.role_rule_selectors
		   (role_id, rule_fp, arm, object_types, match_labels)
		 VALUES ($1, 'fp-1', $2, ARRAY[$3::text], $4::jsonb)`,
		roleID, arm, grantType, labels)
}

// Источник 1 — прямой факт.
func TestAsk_DirectFactAllows(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.relation_fact (object_type, object_id, relation, subject)
			 VALUES ('vpc_network', 'net-1', 'v_get', 'user:usr-1')`)

		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if got != relverdict.Allow {
			t.Errorf("прямой факт не дал права: %v", got)
		}

		// Отрицание рядом: другой субъект права не получает. Без него «allow»
		// выше зеленело бы и на запросе, который разрешает всем.
		other, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-2", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if other != relverdict.Deny {
			t.Errorf("чужой субъект получил право: %v", other)
		}
	})
}

// Источник 2 — выдача роли на ПРЕДКА объекта. Ради этого и заведена цепь.
func TestAsk_BindingOnAncestorAllows(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-view", "vpc_network", "get", "anchor", "{}")
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('vpc_network', 'net-1', 'project', 'prj-1', 1)`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ('acb-1', 'user', 'usr-1', 'rol-view', 'project', 'prj-1', 'ACTIVE')`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-1', 'user', 'usr-1')`)

		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if got != relverdict.Allow {
			t.Errorf("выдача на предка не достигла объекта: %v — ровно тот дефект, ради "+
				"которого заведена цепь", got)
		}

		// Отрицание: глагол, которого роль не даёт.
		noVerb, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_delete",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if noVerb != relverdict.Deny {
			t.Errorf("роль дала глагол, которого в её проекции нет: %v", noVerb)
		}

		// Отрицание: объект ВНЕ области выдачи (нет ребра к prj-1).
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('vpc_network', 'net-2', 'project', 'prj-2', 1)`)
		outside, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-2", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if outside != relverdict.Deny {
			t.Errorf("выдача на один проект достала объект другого: %v", outside)
		}
	})
}

// Источник 3 — выдача по МЕТКАМ: право следует за меткой объекта.
func TestAsk_LabelSelectorFollowsTheObjectLabels(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-env", "vpc_network", "get", "labels", `{"env":"prod"}`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('vpc_network', 'net-1', 'project', 'prj-1', 1)`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_mirror (object_type, object_id, labels)
			 VALUES ($1, 'net-1', '{"env":"prod"}'::jsonb)`,
			catalogFormOf(t, "vpc_network"))
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ('acb-2', 'user', 'usr-1', 'rol-env', 'project', 'prj-1', 'ACTIVE')`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-2', 'user', 'usr-1')`)
		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if got != relverdict.Allow {
			t.Errorf("выдача по метке не достигла помеченного объекта: %v", got)
		}

		// СМЕНА МЕТКИ — один UPDATE, и право уходит СРАЗУ. Ради этого свойства
		// произведение и не материализуется: иначе смена метки требовала бы
		// пересчёта доступа для всех субъектов с меточными выдачами.
		exec(t, ctx, tx,
			`UPDATE kacho_iam.resource_mirror SET labels = '{"env":"dev"}'::jsonb
			  WHERE object_type = $1 AND object_id = 'net-1'`,
			catalogFormOf(t, "vpc_network"))
		after, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if after != relverdict.Deny {
			t.Errorf("после смены метки право осталось: %v — предикат вычисляется на чтении "+
				"именно затем, чтобы этого не случалось", after)
		}
	})
}

// Источник 4 — членство в группе: субъектом выдачи бывает группа.
func TestAsk_GroupMembershipAllows(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-grp", "vpc_network", "get", "anchor", "{}")
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('vpc_network', 'net-1', 'project', 'prj-1', 1)`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.groups (id, account_id, name) VALUES ('grp-1', 'acc-1', 'devs')
			 ON CONFLICT DO NOTHING`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
			 VALUES ('acb-3', 'group', 'grp-1', 'rol-grp', 'project', 'prj-1', 'ACTIVE')`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-3', 'group', 'grp-1')`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.group_members (group_id, member_type, member_id)
			 VALUES ('grp-1', 'user', 'usr-1')`)

		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if got != relverdict.Allow {
			t.Errorf("членство в группе не дало права: %v", got)
		}

		// Отрицание: не член группы права не получает — иначе выдача группе
		// означала бы выдачу всем.
		outsider, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-9", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if outsider != relverdict.Deny {
			t.Errorf("не член группы получил право: %v", outsider)
		}
	})
}

// Отозванная и истёкшая выдача не дают права — оба состояния проверяются, потому
// что они разные колонки и разойтись могут независимо.
func TestAsk_RevokedAndExpiredBindingsDoNotAllow(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedRole(t, ctx, tx, "rol-rev", "vpc_network", "get", "anchor", "{}")
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('vpc_network', 'net-1', 'project', 'prj-1', 1)`)
		// Отозванная.
		// Отзыв двигает ОБЕ колонки — статус и метку времени: их согласованность
		// закреплена ограничением схемы. Посев, ставящий одну, проверял бы
		// состояние, которого в проде не бывает.
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_bindings
			   (id, subject_type, subject_id, role_id, resource_type, resource_id, status, revoked_at)
			 VALUES ('acb-r', 'user', 'usr-1', 'rol-rev', 'project', 'prj-1', 'REVOKED', now())`)
		exec(t, ctx, tx,
			`INSERT INTO kacho_iam.access_binding_subjects (binding_id, subject_type, subject_id)
			 VALUES ('acb-r', 'user', 'usr-1')`)

		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("запрос: %v", err)
		}
		if got != relverdict.Deny {
			t.Errorf("отозванная выдача дала право: %v — отзыв обязан действовать сразу", got)
		}
	})
}

// Неполный вопрос — ошибка, а не Deny.
func TestAsk_IncompleteQuestionIsAnErrorNotADenial(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err == nil {
			t.Fatal("пустой субъект принят — отдавать за него Deny значит выдавать незнание " +
				"за отказ, и сравнение с движком показало бы согласие вместо расхождения")
		}
		if got != relverdict.Unknown {
			t.Errorf("исход = %v, ожидался unknown", got)
		}
	})
}

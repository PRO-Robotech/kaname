// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package relverdict_test

// applieddict_integration_test.go — ИМЯ ТИПА В СЛОВАРЕ КАТАЛОГА ВЕРДИКТ БЕРЁТ У
// ЖИВОЙ СТРОКИ, А НЕ У ТАБЛИЦЫ, ПОРОЖДЁННОЙ СБОРКОЙ (kacho#1986).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТОГО НЕ ПОКАЗЫВАЕТ НИ ОДНА СОСЕДНЯЯ ПРОБА
//
// Соседи сеют каталог тем же переходником, каким его читает вердикт
// (`authzmap.DottedType`), поэтому обе стороны смещаются одинаково и соединение
// сходится на данных, которых применение манифеста не производит. Здесь строка
// каталога заводится ПРИМЕНЕНИЕМ — прямой записью в `catalog_resource`, как это
// делает применитель, — и имя для посева берётся ОТТУДА ЖЕ, из живой строки.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПЕРЕИМЕНОВАНИЕ, А НЕ ЦЕЛИКОМ НОВЫЙ ТИП
//
// Целиком новый тип модели вердикта В ЭТОМ ХАРНЕССЕ не достигает: план права
// компилируется у `authzmodel.Shared()` — у модели ПРОЦЕССА, — а прогон этого
// пакета её не ставит, поэтому она остаётся вшитым каноном, и незнакомый ей тип
// отвергается раньше словаря: `Deny` с признаком «тип не объявлен».
//
// ЭТО СВОЙСТВО ХАРНЕССА, А НЕ ПРОДУКТА, и разница несущая. Здесь стояло «модель
// ВШИТА в двоичный файл» без оговорки — утверждение, верное на своей ревизии и
// ложное сегодня: модель процесса СОБИРАЕТСЯ из доставленных манифестов на
// старте (`cmd/kacho-iam` → `installComposedModel`, #1969), и целиком новый тип
// вердикта достигает. Прочитав прежнюю редакцию, следующий заключил бы, что
// такого входа не бывает вовсе, — и не стал бы искать дефект там, где он есть.
//
// Сквозной путь «манифест → каталог → проекция → собранная модель → вердикт»
// утверждает проба соседнего пакета,
// `pg.TestDoD1_TypeUnknownToTheBuildReachesTheVerdictThroughTheComposedModel`
// (сценарии приёмки `IAM-MB-1-06`/`-08`): её харнесс модель ставит, и потому
// вход, невыразимый здесь, там законен. Здесь оно названо, чтобы фикстура не
// выглядела произвольной.
//
// Переименование ресурса — форма применения, которую схема несёт явно
// (`superseded_by` у снятой строки), и она даёт РОВНО тот вход, ради которого
// правка сделана: тип модели прежний (план строится), а имя каталога у него
// новое, и таблица сборки знает СТАРОЕ. Ambiguity здесь не теоретическая —
// `catalog_resource_object_type_live_uk UNIQUE (object_type, live)` допускает
// две строки одного типа модели, снятую и живую, и обе видны переводу.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ
//
// ОТВЕТ вердикта, а не форма вызова: перечисление отдаёт объект, селектор меток
// его покрывает. Рядом — ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ на типе, чью строку применение
// не трогало: без него «пусто» неотличимо от «запрос не отбирает ничего вовсе».

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kacho/pkg/ownerregister"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/relverdict"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/pg/resource_mirror"
)

// appliedCatalogTypeName — имя типа в словаре КАТАЛОГА по ЖИВОЙ строке.
//
// Читается тем же вопросом, каким его обязан читать продукт, и НЕ через
// переходник читателя: иначе фикстура и продукт зовут одно и то же, и проба
// доказывает согласие запроса с самим собой.
func appliedCatalogTypeName(t *testing.T, ctx context.Context, tx pgx.Tx, modelType string) string {
	t.Helper()
	var dotted string
	if err := tx.QueryRow(ctx,
		`SELECT dotted FROM kacho_iam.catalog_resource
		  WHERE object_type = $1 AND live`, modelType).Scan(&dotted); err != nil {
		t.Fatalf("живой строки каталога для типа %q нет: %v", modelType, err)
	}
	return dotted
}

// applyRenamesTheResource — применение манифеста переименовывает ресурс: прежняя
// строка снимается, новая заводится с ТЕМ ЖЕ типом модели прав.
//
// Проекции ролей, ссылавшиеся на снятое имя, переселяются ДО снятия строки —
// порядок несущий, обратный упирается в ключ живости (`role_verb_type_fk`).
func applyRenamesTheResource(t *testing.T, ctx context.Context, tx pgx.Tx,
	module, oldResource, newResource, modelType string) {
	t.Helper()
	oldDotted := module + "." + oldResource
	newDotted := module + "." + newResource
	exec(t, ctx, tx, `DELETE FROM kacho_iam.role_verb WHERE object_type = $1`, oldDotted)
	exec(t, ctx, tx,
		`DELETE FROM kacho_iam.role_rule_ref WHERE module = $1 AND resource = $2`,
		module, oldResource)
	exec(t, ctx, tx,
		`DELETE FROM kacho_iam.catalog_verb WHERE module = $1 AND resource = $2`,
		module, oldResource)
	exec(t, ctx, tx,
		`UPDATE kacho_iam.catalog_resource
		    SET live = false, retired_at = now(), retired_reason = 'renamed by apply',
		        superseded_by = $2
		  WHERE dotted = $1`, oldDotted, newDotted)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.catalog_resource (module, resource, dotted, object_type)
		 VALUES ($1, $2, $3, $4)`, module, newResource, newDotted, modelType)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.catalog_verb (module, resource, verb) VALUES ($1, $2, 'get')`,
		module, newResource)
}

// seedRoleForCatalogType — роль, чья проекция названа ЖИВЫМ именем каталога.
func seedRoleForCatalogType(t *testing.T, ctx context.Context, tx pgx.Tx,
	roleID, catalogType, verb, arm, labels string) {
	t.Helper()
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
		         'cluster_kacho_root')`, roleID, roleID+"."+verb, verb)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.role_verb (role_id, object_type, verb) VALUES ($1, $2, $3)`,
		roleID, catalogType, verb)
	exec(t, ctx, tx,
		`INSERT INTO kacho_iam.role_rule_selectors
		   (role_id, rule_fp, arm, object_types, match_labels)
		 VALUES ($1, 'fp-applied', $2, ARRAY[$3::text], $4::jsonb)`,
		roleID, arm, catalogType, labels)
}

// registerUnderCatalogType — регистрация объекта настоящим писателем зеркала.
func registerUnderCatalogType(t *testing.T, ctx context.Context, tx pgx.Tx,
	catalogType, objectID string, labels map[string]string) {
	t.Helper()
	if _, err := resource_mirror.UpsertTx(ctx, tx, resource_mirror.Row{
		ObjectType:      catalogType,
		ObjectID:        objectID,
		ParentProjectID: "prj-1",
		ParentAccountID: "acc-1",
		ParentChain:     ownerregister.ParentChain(nil, "prj-1", "acc-1"),
		Labels:          labels,
	}); err != nil {
		t.Fatalf("регистрация объекта %s типа %s: %v", objectID, catalogType, err)
	}
}

// Перечисление отдаёт объект типа, чью строку каталога завело ПРИМЕНЕНИЕ.
func TestList_EnumeratesAnObjectOfATypeIntroducedByApply(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)

		// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ — тип, чью строку применение не трогало.
		untouched := appliedCatalogTypeName(t, ctx, tx, "compute_instance")
		seedRoleForCatalogType(t, ctx, tx, "rol-untouched", untouched, "get", "anchor", "{}")
		seedProjectBinding(t, ctx, tx, "acb-untouched", "rol-untouched")
		registerUnderCatalogType(t, ctx, tx, untouched, "ins-1", nil)

		// ПРЕДМЕТ — тип, чьё имя каталога завело применение.
		applyRenamesTheResource(t, ctx, tx, "vpc", "network", "networkPolicy", "vpc_network")
		applied := appliedCatalogTypeName(t, ctx, tx, "vpc_network")
		if applied == "vpc.network" {
			t.Fatalf("фикстура не переименовала ресурс: живое имя каталога осталось %q — "+
				"проба сравнивала бы словарь сборки с самим собой", applied)
		}
		seedRoleForCatalogType(t, ctx, tx, "rol-applied", applied, "get", "anchor", "{}")
		seedProjectBinding(t, ctx, tx, "acb-applied", "rol-applied")
		registerUnderCatalogType(t, ctx, tx, applied, "net-1", nil)

		control, _, err := relverdict.List(ctx, tx, relverdict.ListQuery{
			Subject: "user:usr-1", ObjectType: "compute_instance", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("перечисление (контроль): %v", err)
		}
		if len(control) != 1 || control[0] != "ins-1" {
			t.Fatalf("ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ не прошёл: перечисление типа, чью строку "+
				"каталога применение не трогало, вернуло %v вместо [ins-1]. Пустой ответ "+
				"по предмету ниже был бы неотличим от запроса, не отбирающего ничего", control)
		}

		got, _, err := relverdict.List(ctx, tx, relverdict.ListQuery{
			Subject: "user:usr-1", ObjectType: "vpc_network", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("перечисление: %v", err)
		}
		if len(got) != 1 || got[0] != "net-1" {
			t.Errorf("перечисление не отобрало объект типа, чью строку каталога завело "+
				"ПРИМЕНЕНИЕ: получено %v вместо [net-1]. Живое имя каталога — %q, а таблица, "+
				"порождённая сборкой, переводит тот же тип модели иначе; соединение по "+
				"`resource_mirror.object_type` не совпадает НИКОГДА и молча — клиент видит "+
				"«прав нет», а не «что-то сломалось»", got, applied)
		}
	})
}

// Селектор меток покрывает объект типа, чью строку каталога завело ПРИМЕНЕНИЕ.
func TestAsk_LabelSelectorCoversAnObjectOfATypeIntroducedByApply(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)

		// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ — тот же вопрос на нетронутом типе.
		untouched := appliedCatalogTypeName(t, ctx, tx, "compute_instance")
		seedRoleForCatalogType(t, ctx, tx, "rol-lbl-untouched", untouched, "get", "labels",
			`{"env":"prod"}`)
		seedProjectBinding(t, ctx, tx, "acb-lbl-untouched", "rol-lbl-untouched")
		registerUnderCatalogType(t, ctx, tx, untouched, "ins-1", map[string]string{"env": "prod"})

		applyRenamesTheResource(t, ctx, tx, "vpc", "network", "networkPolicy", "vpc_network")
		applied := appliedCatalogTypeName(t, ctx, tx, "vpc_network")
		seedRoleForCatalogType(t, ctx, tx, "rol-lbl-applied", applied, "get", "labels",
			`{"env":"prod"}`)
		seedProjectBinding(t, ctx, tx, "acb-lbl-applied", "rol-lbl-applied")
		registerUnderCatalogType(t, ctx, tx, applied, "net-1", map[string]string{"env": "prod"})
		registerUnderCatalogType(t, ctx, tx, applied, "net-2", map[string]string{"env": "dev"})

		control, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "compute_instance", ObjectID: "ins-1",
			Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("вопрос (контроль): %v", err)
		}
		if control != relverdict.Allow {
			t.Fatalf("ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ не прошёл: выдача по метке на нетронутом типе "+
				"дала %s. Отказ по предмету ниже был бы неотличим от меточной ветви, "+
				"не совпадающей ни с чем", control)
		}

		got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-1", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("вопрос: %v", err)
		}
		if got != relverdict.Allow {
			t.Errorf("селектор меток не покрыл объект типа, чью строку каталога завело "+
				"ПРИМЕНЕНИЕ: %s. Живое имя каталога — %q; левое соединение меток идёт по "+
				"имени из таблицы, порождённой сборкой, и меток не находит — выдача по "+
				"селектору объект не покрывает", got, applied)
		}

		// Отрицание рядом: непомеченный объект права не даёт и после правки.
		other, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
			Subject: "user:usr-1", ObjectType: "vpc_network", ObjectID: "net-2", Relation: "v_get",
		})
		if err != nil {
			t.Fatalf("вопрос (отрицание): %v", err)
		}
		if other != relverdict.Deny {
			t.Errorf("объект с чужой меткой получил право: %s", other)
		}
	})
}

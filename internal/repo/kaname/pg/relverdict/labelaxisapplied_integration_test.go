// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// labelaxisapplied_integration_test.go — ОСЬ МЕТОК ВЫБИРАЕТСЯ ПО ЖИВОЙ СТРОКЕ
// КАТАЛОГА, а не по таблице, ПОРОЖДЁННОЙ СБОРКОЙ (kacho#2036, пункт 1 предиката
// эпика #1027).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Ось меток отвечает на один вопрос: держит ли iam объект этого типа В СВОЕЙ
// таблице — или объект живёт в зеркале ресурсов. Ответ выводится из ТОЧЕЧНОГО
// имени типа: домен относит к собственным всё, что названо `iam.*`
// (`domain.FeedSourceForType`).
//
// Точечное имя брала `authzmap.DottedType` — оболочка над `tables_gen.go`,
// порождённой сборкой из манифестов ДЕРЕВА. Живое точечное имя пишет
// ПРИМЕНЕНИЕ манифеста в `kaname.catalog_resource`, и оно от сборочного
// расходится: применение вправе и переименовать ресурс, и передать его другому
// модулю. Расхождение по границе `iam.` меняет ОСЬ — то есть место, у которого
// спрашивают метки.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО НЕ ПОЙМАЛА НИ ОДНА СОСЕДНЯЯ ПРОБА
//
// Соседи сеют роль тем же переходником, каким ось читает вердикт
// (`authzmap.DottedType` в `seedRole`), а свои объекты кладут ровно туда, куда
// этот же переходник и указывает. Обе стороны смещаются одинаково, и совпадение
// доказывает согласие запроса С САМИМ СОБОЙ. Здесь строка каталога заводится
// ПРИМЕНЕНИЕМ — прямой записью, как это делает применитель, — а имя для посева
// берётся ОТТУДА ЖЕ, из живой строки.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ФИКСТУРА — ПЕРЕДАЧА РЕСУРСА ДРУГОМУ МОДУЛЮ
//
// Форма выбрана не за экзотичность, а потому что она ЕДИНСТВЕННАЯ, на которой
// расхождение видно ВЕРДИКТОМ, и это установлено перебором, а не вкусом:
//
//	переименование ресурса внутри модуля  `iam.group` → `iam.userGroup`
//	    обе стороны границы `iam.` не пересекают — ось та же, вердикт тот же;
//	целиком новый тип, сборке неизвестный
//	    план права его отвергает РАНЬШЕ оси (`Deny` + «тип не объявлен»), и до
//	    выбора оси вопрос не доходит вовсе;
//	передача ресурса другому модулю      `iam.group` → `directory.group`
//	    границу пересекает — ось меняется, и вердикт меняется вместе с ней.
//
// Содержательно форма законна: МОДУЛЬ, которому живая строка каталога отдаёт
// тип, определяет, каким именем объекты этого типа регистрируются в зеркале
// (писатель зеркала берёт имя из каталога, `resource_mirror/model_dictionary.go`,
// #1982). Значит писатель уже следует каталогу — и читатель обязан следовать
// ему же. Пока читатель ходит в таблицу сборки, писатель кладёт объект в
// зеркало, а читатель спрашивает метки у `kaname.groups`, где строки нет и не
// будет: ответ «нет» неотличим от честного отказа по правам.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ И ПОЧЕМУ КОНТРОЛЕЙ ДВА
//
// Утверждается ВЕРДИКТ, а не форма вызова. Рядом — ДВА положительных контроля,
// по одному на каждую ось, оба на типах, чьей строки применение не трогало:
//
//	зеркало         (`compute_instance`) — иначе «разрешено» у предмета было бы
//	                  неотличимо от запроса, разрешающего всё;
//	своя таблица    (`project`)          — иначе починка была бы неотличима от
//	                  подмены оси: перевести ВСЁ на зеркало значило бы обрушить
//	                  ровно те семь типов, ради которых своя ось и заведена.
//
// Одного контроля не хватает ни в какой комбинации: первый молчит о том, что
// собственная ось выжила, второй — о том, что зеркальная не сломана.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// appliedAxisAccount — область выдачи во всех трёх ветвях пробы. Одна намеренно:
// различаться обязан ТИП, а не обвязка, иначе расхождение исхода объясняется
// фикстурой, а не предметом.
const appliedAxisAccount = "acc-1"

// applyHandsTheResourceToAnotherModule — применение передаёт ресурс другому
// модулю: прежняя строка снимается с преемником, новая заводится с ТЕМ ЖЕ типом
// модели прав.
//
// Порядок несущий, и обратный упирается в ключи живости: проекции ролей и
// глаголы каталога, ссылающиеся на снимаемую строку, уезжают ДО её снятия
// (`role_verb_type_fk`, `catalog_verb_resource_live_fk`).
func applyHandsTheResourceToAnotherModule(t *testing.T, ctx context.Context, tx pgx.Tx,
	oldModule, newModule, resource, modelType string,
) {
	t.Helper()
	oldDotted := oldModule + "." + resource
	newDotted := newModule + "." + resource
	exec(t, ctx, tx, `DELETE FROM kaname.role_verb WHERE object_type = $1`, oldDotted)
	exec(t, ctx, tx,
		`DELETE FROM kaname.role_rule_ref WHERE module = $1 AND resource = $2`,
		oldModule, resource)
	exec(t, ctx, tx,
		`DELETE FROM kaname.catalog_verb WHERE module = $1 AND resource = $2`,
		oldModule, resource)
	exec(t, ctx, tx,
		`INSERT INTO kaname.catalog_module (module) VALUES ($1) ON CONFLICT DO NOTHING`,
		newModule)
	exec(t, ctx, tx,
		`UPDATE kaname.catalog_resource
		    SET live = false, retired_at = now(), retired_reason = 'handed over by apply',
		        superseded_by = $2
		  WHERE dotted = $1`, oldDotted, newDotted)
	exec(t, ctx, tx,
		`INSERT INTO kaname.catalog_resource (module, resource, dotted, object_type)
		 VALUES ($1, $2, $3, $4)`, newModule, resource, newDotted, modelType)
	exec(t, ctx, tx,
		`INSERT INTO kaname.catalog_verb (module, resource, verb) VALUES ($1, $2, 'get')`,
		newModule, resource)
}

// liveCatalogName — живое точечное имя типа, прочитанное У КАТАЛОГА.
//
// Читается своим вопросом, а НЕ функцией продукта: иначе фикстура и продукт
// зовут одно и то же, и проба доказывает согласие запроса с самим собой.
func liveCatalogName(t *testing.T, ctx context.Context, tx pgx.Tx, modelType string) string {
	t.Helper()
	var dotted string
	if err := tx.QueryRow(ctx,
		`SELECT dotted FROM kaname.catalog_resource
		  WHERE object_type = $1 AND live`, modelType).Scan(&dotted); err != nil {
		t.Fatalf("живой строки каталога для типа %q нет: %v", modelType, err)
	}
	return dotted
}

// seedLabelGrantOnCatalogType — роль с МЕТОЧНОЙ ветвью на названном имени
// КАТАЛОГА плюс выдача её на аккаунт.
//
// Ветвь одна — меточная: роль, несущая рядом якорную, разрешила бы весь тип в
// области независимо от меток, и проба зеленела бы на запросе, который метки не
// читает вовсе.
func seedLabelGrantOnCatalogType(t *testing.T, ctx context.Context, tx pgx.Tx,
	roleID, bindingID, catalogType, labels string,
) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kaname.clusters (id, name) VALUES ('cluster_root', 'kacho')
		 ON CONFLICT DO NOTHING`)
	exec(t, ctx, tx,
		`INSERT INTO kaname.roles (id, name, permissions, rules, cluster_id)
		 VALUES ($1, $2, '[]'::jsonb,
		         jsonb_build_array(jsonb_build_object(
		             'module',    'test',
		             'resources', jsonb_build_array('*'),
		             'verbs',     jsonb_build_array('get'))),
		         'cluster_root')`, roleID, roleID+".get")
	exec(t, ctx, tx,
		`INSERT INTO kaname.role_verb (role_id, object_type, verb) VALUES ($1, $2, 'get')`,
		roleID, catalogType)
	exec(t, ctx, tx,
		`INSERT INTO kaname.role_rule_selectors
		   (role_id, rule_fp, arm, object_types, match_labels)
		 VALUES ($1, $2, 'labels', ARRAY[$3::text], $4::jsonb)`,
		roleID, "fp-"+roleID, catalogType, labels)
	exec(t, ctx, tx,
		`INSERT INTO kaname.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		 VALUES ($1, 'user', 'usr-1', $2, 'account', $3, 'ACTIVE')`,
		bindingID, roleID, appliedAxisAccount)
	exec(t, ctx, tx,
		`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ($1, 'user', 'usr-1')`, bindingID)
}

// parentEdgeToAccount — цепь предка объекта. Тип в ней назван формой МОДЕЛИ:
// именно ею вопрос о доступе адресует объект.
func parentEdgeToAccount(t *testing.T, ctx context.Context, tx pgx.Tx, modelType, objectID string) {
	t.Helper()
	exec(t, ctx, tx,
		`INSERT INTO kaname.resource_parent_edge
		   (object_type, object_id, parent_type, parent_id, depth)
		 VALUES ($1, $2, 'account', $3, 1)`, modelType, objectID, appliedAxisAccount)
}

// askApplied — вопрос «может ли субъект пробы прочитать объект».
func askApplied(t *testing.T, ctx context.Context, tx pgx.Tx,
	modelType, objectID string,
) relverdict.Verdict {
	t.Helper()
	got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject: "user:usr-1", ObjectType: modelType, ObjectID: objectID, Relation: "v_get",
	})
	if err != nil {
		t.Fatalf("вопрос о %s:%s: %v", modelType, objectID, err)
	}
	return got
}

// TestAsk_LabelAxisFollowsTheLiveCatalogNotTheBuildTable — меточная выдача
// достаёт объект типа, чей МОДУЛЬ сменило применение, и не теряет ни одной из
// двух осей на типах манифеста.
func TestAsk_LabelAxisFollowsTheLiveCatalogNotTheBuildTable(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)

		// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 1: ось ЗЕРКАЛА на типе манифеста ──────────
		mirrorType := liveCatalogName(t, ctx, tx, "compute_instance")
		seedLabelGrantOnCatalogType(t, ctx, tx,
			"rol-ctl-mirror", "acb-ctl-mirror", mirrorType, `{"env":"prod"}`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_mirror (object_type, object_id, labels)
			 VALUES ($1, 'ins-7', '{"env":"prod"}'::jsonb)`, mirrorType)
		parentEdgeToAccount(t, ctx, tx, "compute_instance", "ins-7")

		// ── ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ 2: ось СВОЕЙ ТАБЛИЦЫ на типе манифеста ────
		ownType := liveCatalogName(t, ctx, tx, "project")
		seedLabelGrantOnCatalogType(t, ctx, tx,
			"rol-ctl-own", "acb-ctl-own", ownType, `{"env":"prod"}`)
		exec(t, ctx, tx,
			`INSERT INTO kaname.projects (id, account_id, name, labels)
			 VALUES ('prj-7', 'acc-1', 'axis-control-project', '{"env":"prod"}'::jsonb)`)
		parentEdgeToAccount(t, ctx, tx, "project", "prj-7")

		// ── ПРЕДМЕТ: тип, чей модуль сменило ПРИМЕНЕНИЕ ──────────────────────
		applyHandsTheResourceToAnotherModule(t, ctx, tx, "iam", "directory", "group", "iam_group")
		applied := liveCatalogName(t, ctx, tx, "iam_group")
		if applied == "iam.group" {
			t.Fatalf("фикстура не передала ресурс: живое имя каталога осталось %q — "+
				"проба сравнивала бы словарь сборки с самим собой", applied)
		}
		seedLabelGrantOnCatalogType(t, ctx, tx,
			"rol-applied", "acb-applied", applied, `{"env":"prod"}`)
		// Объект кладётся В ЗЕРКАЛО и под ЖИВЫМ именем каталога — ровно туда и
		// ровно так, как его положил бы писатель зеркала, читающий тот же
		// каталог (#1982).
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_mirror (object_type, object_id, labels)
			 VALUES ($1, 'grp-7', '{"env":"prod"}'::jsonb)`, applied)
		parentEdgeToAccount(t, ctx, tx, "iam_group", "grp-7")

		// ── Контроли обязаны пройти ПЕРВЫМИ ──────────────────────────────────
		if got := askApplied(t, ctx, tx, "compute_instance", "ins-7"); got != relverdict.Allow {
			t.Fatalf("ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ (ось зеркала) не прошёл: вердикт %v вместо "+
				"Allow. Отказ по предмету ниже был бы неотличим от запроса, не "+
				"разрешающего ничего вовсе", got)
		}
		if got := askApplied(t, ctx, tx, "project", "prj-7"); got != relverdict.Allow {
			t.Fatalf("ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ (ось своей таблицы) не прошёл: вердикт %v "+
				"вместо Allow. Собственная ось iam обрушена — значит починка предмета "+
				"свелась бы к подмене оси на зеркальную для ВСЕХ типов", got)
		}

		// ── Предмет ──────────────────────────────────────────────────────────
		if got := askApplied(t, ctx, tx, "iam_group", "grp-7"); got != relverdict.Allow {
			t.Fatalf("меточная выдача не достала объект типа, чей модуль сменило "+
				"ПРИМЕНЕНИЕ: вердикт %v вместо Allow. Живое имя каталога — %q, и объект "+
				"зарегистрирован под ним в зеркале; таблица, ПОРОЖДЁННАЯ СБОРКОЙ, "+
				"переводит тот же тип модели как `iam.group`, и ось выбирается по ней — "+
				"метки спрашиваются у `kaname.groups`, где строки этого объекта нет и "+
				"не будет. Ответ «нет» неотличим от честного отказа по правам", got, applied)
		}

		// ── Сторона ОТРИЦАНИЯ: метка снята — право обязано уйти ──────────────
		// Без неё «разрешено» выше зеленело бы на запросе, разрешающем всё.
		exec(t, ctx, tx,
			`UPDATE kaname.resource_mirror SET labels = '{"env":"dev"}'::jsonb
			  WHERE object_type = $1 AND object_id = 'grp-7'`, applied)
		if got := askApplied(t, ctx, tx, "iam_group", "grp-7"); got != relverdict.Deny {
			t.Fatalf("после смены метки право на объекте типа, переданного применением, "+
				"осталось: %v — значит утверждение выше ничего не проверяло", got)
		}
	})
}

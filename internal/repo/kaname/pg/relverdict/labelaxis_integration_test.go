// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict_test

// labelaxis_integration_test.go — меточная выдача обязана доставать объект НА
// ОБЕИХ осях: и через зеркало ресурсов, и по собственной таблице iam.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ПРОБА НА КАЖДЫЙ ТИП, А НЕ ОДНА «НА ОСЬ»
//
// Ось выбирается ПО ТИПУ, и выбор этот — перечень: тип, которого в перечне нет,
// уезжает на ось зеркала, где объекта собственного типа iam не бывает by
// construction. Одна проба «на ось» зеленела бы на первом же типе и не говорила
// бы ничего про остальные шесть. Поэтому единица пробы — ТИП, а полнота перечня
// проверяется отдельно, против реестра осей.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СМЕНА МЕТКИ ПРОВЕРЯЕТСЯ В ОБЕ СТОРОНЫ
//
// Отрицание без положительного близнеца неотличимо от «путь мёртв»: запрос,
// который не находит НИЧЕГО НИКОГДА, отвечает «нет» и на снятой метке — и такой
// ответ читается как исправная работа. Именно так дефект и дожил до сюда.
// Поэтому каждая проба снимает метку (право обязано уйти) И возвращает её (право
// обязано вернуться): две стороны одного предиката, ни одна не достаточна.

import (
	"context"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

// labelScopeAccount — область, на которую сделана меточная выдача во всех пробах
// файла. Одна на все типы намеренно: различаться между пробами обязан ТИП, а не
// обвязка, иначе расхождение исхода объясняется фикстурой, а не предметом.
const labelScopeAccount = "acc-1"

// iamDirectProbe — как посеять ОБЪЕКТ собственного типа iam с метками.
//
// Строка кладётся в СВОЮ таблицу настоящими колонками, а не в зеркало: зеркало
// собственных типов iam не держит вовсе — они совпадают по меткам запросом к
// своей таблице, — и фикстура, подложившая строку зеркала, доказывала бы работу
// на данных, которых в проде не бывает.
type iamDirectProbe struct {
	// objectType — тип в той форме, в какой его называет вопрос о доступе
	// (`account`, `project`, `iam_user`, …).
	objectType string
	// objectID — идентификатор объекта пробы.
	objectID string
	// seedSQL — $1 идентификатор, $2 метки (jsonb).
	seedSQL string
	// relabelSQL — $1 идентификатор, $2 новые метки: смена метки одним UPDATE.
	relabelSQL string
}

// iamDirectProbes — по одной пробе на каждый собственный тип iam.
//
// Перечень ВЫПИСАН здесь, а его полнота сверяется с реестром осей отдельной
// пробой. Выписанный и сверяемый перечень ловит обе ошибки — «завели тип без
// пробы» и «оставили пробу на снятый тип»; перечень, ВЫВЕДЕННЫЙ из реестра, не
// поймал бы ни одной, потому что совпал бы с ним всегда.
var iamDirectProbes = []iamDirectProbe{
	{
		objectType: "account", objectID: "acc-2",
		seedSQL: `INSERT INTO kaname.accounts (id, name, owner_user_id, labels)
		          VALUES ($1, 'probe-account', 'usr-1', $2::jsonb)`,
		relabelSQL: `UPDATE kaname.accounts SET labels = $2::jsonb WHERE id = $1`,
	},
	{
		objectType: "project", objectID: "prj-9",
		seedSQL: `INSERT INTO kaname.projects (id, account_id, name, labels)
		          VALUES ($1, 'acc-1', 'probe-project', $2::jsonb)`,
		relabelSQL: `UPDATE kaname.projects SET labels = $2::jsonb WHERE id = $1`,
	},
	{
		objectType: "iam_user", objectID: "usr-9",
		seedSQL: `INSERT INTO kaname.users (id, external_id, email, account_id, labels)
		          VALUES ($1, 'ext-9', 'usr-9@kacho.local', 'acc-1', $2::jsonb)`,
		relabelSQL: `UPDATE kaname.users SET labels = $2::jsonb WHERE id = $1`,
	},
	{
		objectType: "iam_service_account", objectID: "sac-9",
		seedSQL: `INSERT INTO kaname.service_accounts (id, account_id, name, labels)
		          VALUES ($1, 'acc-1', 'probe-sa', $2::jsonb)`,
		relabelSQL: `UPDATE kaname.service_accounts SET labels = $2::jsonb WHERE id = $1`,
	},
	{
		objectType: "iam_group", objectID: "grp-9",
		seedSQL: `INSERT INTO kaname.groups (id, account_id, name, labels)
		          VALUES ($1, 'acc-1', 'probe-group', $2::jsonb)`,
		relabelSQL: `UPDATE kaname.groups SET labels = $2::jsonb WHERE id = $1`,
	},
	{
		objectType: "iam_role", objectID: "rol-9",
		seedSQL: `INSERT INTO kaname.roles (id, name, permissions, rules, cluster_id, labels)
		          VALUES ($1, 'probe.role', '[]'::jsonb,
		                  jsonb_build_array(jsonb_build_object(
		                      'module', 'test', 'resources', jsonb_build_array('*'),
		                      'verbs', jsonb_build_array('get'))),
		                  'cluster_root', $2::jsonb)`,
		relabelSQL: `UPDATE kaname.roles SET labels = $2::jsonb WHERE id = $1`,
	},
	{
		objectType: "iam_access_binding", objectID: "acb-9",
		// Область у объекта-выдачи ДРУГАЯ (проект, не аккаунт): пара «субъект ×
		// роль × область» уникальна среди действующих выдач, и повтор области
		// столкнулся бы с этим ограничением, а не с предметом пробы.
		seedSQL: `INSERT INTO kaname.access_bindings
		            (id, subject_type, subject_id, role_id, resource_type, resource_id, status, labels)
		          VALUES ($1, 'user', 'usr-1', 'rol-lbl', 'project', 'prj-1', 'ACTIVE', $2::jsonb)`,
		relabelSQL: `UPDATE kaname.access_bindings SET labels = $2::jsonb WHERE id = $1`,
	},
}

// probeTypes — типы проб как МНОЖЕСТВО: порядок объявления к предмету сверки
// отношения не имеет.
func probeTypes() []string {
	out := make([]string, 0, len(iamDirectProbes))
	for _, p := range iamDirectProbes {
		out = append(out, p.objectType)
	}
	sort.Strings(out)
	return out
}

// seedLabelGrant кладёт роль с МЕТОЧНОЙ ветвью и выдачу её на аккаунт.
//
// Ветвь одна — меточная: роль, несущая рядом якорную, разрешила бы весь тип в
// области независимо от меток, и проба зеленела бы на запросе, который метки не
// читает вовсе.
func seedLabelGrant(t *testing.T, ctx context.Context, tx pgx.Tx, objectType string) {
	t.Helper()
	seedRole(t, ctx, tx, "rol-lbl", objectType, "get", "labels", `{"env":"prod"}`)
	exec(t, ctx, tx,
		`INSERT INTO kaname.access_bindings
		   (id, subject_type, subject_id, role_id, resource_type, resource_id, status)
		 VALUES ('acb-lbl', 'user', 'usr-1', 'rol-lbl', 'account', $1, 'ACTIVE')`, labelScopeAccount)
	exec(t, ctx, tx,
		`INSERT INTO kaname.access_binding_subjects (binding_id, subject_type, subject_id)
		 VALUES ('acb-lbl', 'user', 'usr-1')`)
}

// askLabelled — вопрос «может ли субъект пробы прочитать объект».
func askLabelled(t *testing.T, ctx context.Context, tx pgx.Tx, objectType, objectID string) relverdict.Verdict {
	t.Helper()
	got, _, err := relverdict.Ask(ctx, tx, relverdict.Query{
		Subject: "user:usr-1", ObjectType: objectType, ObjectID: objectID, Relation: "v_get",
	})
	if err != nil {
		t.Fatalf("вопрос о %s:%s: %v", objectType, objectID, err)
	}
	return got
}

// TestAsk_LabelGrantReachesEveryIAMDirectType — меточная выдача достаёт объект
// СОБСТВЕННОГО типа iam, и право следует за меткой в обе стороны.
func TestAsk_LabelGrantReachesEveryIAMDirectType(t *testing.T) {
	for _, p := range iamDirectProbes {
		t.Run(p.objectType, func(t *testing.T) {
			withTx(t, func(ctx context.Context, tx pgx.Tx) {
				seedTenant(t, ctx, tx)
				seedLabelGrant(t, ctx, tx, p.objectType)
				exec(t, ctx, tx, p.seedSQL, p.objectID, `{"env":"prod"}`)
				exec(t, ctx, tx,
					`INSERT INTO kaname.resource_parent_edge
					   (object_type, object_id, parent_type, parent_id, depth)
					 VALUES ($1, $2, 'account', $3, 1)`, p.objectType, p.objectID, labelScopeAccount)

				if got := askLabelled(t, ctx, tx, p.objectType, p.objectID); got != relverdict.Allow {
					t.Fatalf("меточная выдача не достала %s:%s — вердикт %v; на этом типе "+
						"условие меток не выполняется никогда, если ось ответа выбрана "+
						"не по типу", p.objectType, p.objectID, got)
				}

				// Сторона ОТРИЦАНИЯ: метка снята — право обязано уйти.
				exec(t, ctx, tx, p.relabelSQL, p.objectID, `{"env":"dev"}`)
				if got := askLabelled(t, ctx, tx, p.objectType, p.objectID); got != relverdict.Deny {
					t.Fatalf("после смены метки право на %s:%s осталось: %v",
						p.objectType, p.objectID, got)
				}

				// Сторона ПОЛОЖИТЕЛЬНАЯ: метка возвращена — право обязано вернуться.
				// Без неё отрицание выше зеленеет на мёртвом пути.
				exec(t, ctx, tx, p.relabelSQL, p.objectID, `{"env":"prod"}`)
				if got := askLabelled(t, ctx, tx, p.objectType, p.objectID); got != relverdict.Allow {
					t.Fatalf("метка возвращена, а право на %s:%s не вернулось: %v — значит "+
						"отрицание выше ничего не утверждало", p.objectType, p.objectID, got)
				}
			})
		})
	}
}

// TestAsk_LabelGrantStillReachesTheMirrorAxis — ЗАКОННЫЙ БЛИЗНЕЦ: тип чужого
// сервиса по-прежнему отвечает по зеркалу.
//
// Без него починка собственных типов iam неотличима от подмены оси: перевести
// все типы на собственные таблицы значило бы обрушить ровно те пятнадцать, ради
// которых зеркало и заведено.
func TestAsk_LabelGrantStillReachesTheMirrorAxis(t *testing.T) {
	withTx(t, func(ctx context.Context, tx pgx.Tx) {
		seedTenant(t, ctx, tx)
		seedLabelGrant(t, ctx, tx, "vpc_network")
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_mirror (object_type, object_id, labels)
			 VALUES ($1, 'net-9', '{"env":"prod"}'::jsonb)`,
			catalogFormOf(t, "vpc_network"))
		exec(t, ctx, tx,
			`INSERT INTO kaname.resource_parent_edge
			   (object_type, object_id, parent_type, parent_id, depth)
			 VALUES ('vpc_network', 'net-9', 'account', $1, 1)`, labelScopeAccount)

		if got := askLabelled(t, ctx, tx, "vpc_network", "net-9"); got != relverdict.Allow {
			t.Fatalf("меточная выдача перестала доставать объект зеркала: %v", got)
		}
		exec(t, ctx, tx,
			`UPDATE kaname.resource_mirror SET labels = '{"env":"dev"}'::jsonb
			  WHERE object_type = $1 AND object_id = 'net-9'`,
			catalogFormOf(t, "vpc_network"))
		if got := askLabelled(t, ctx, tx, "vpc_network", "net-9"); got != relverdict.Deny {
			t.Fatalf("после смены метки право на объекте зеркала осталось: %v", got)
		}
	})
}

// TestEveryIAMDirectAxisHasAProbe — реестр осей и перечень проб совпадают как
// МНОЖЕСТВА.
//
// Без этой сверки перечень проб — просто список, который кто-то однажды написал:
// заведённый следом тип получил бы ось и не получил пробы, и «на каждый тип есть
// проба» осталось бы верным ровно про вчерашнее дерево. Сверка двусторонняя
// намеренно — она обязана ловить и «тип без пробы», и «пробу на снятый тип».
func TestEveryIAMDirectAxisHasAProbe(t *testing.T) {
	axes := relverdict.IAMDirectLabelAxes()
	registry := make([]string, 0, len(axes))
	for _, a := range axes {
		if a.Table == "" {
			t.Errorf("ось типа %q объявлена без таблицы — такой записи нечего выбирать",
				a.ObjectType)
		}
		registry = append(registry, a.ObjectType)
	}
	sort.Strings(registry)

	probes := probeTypes()
	t.Logf("осмотрено: осей в реестре %d, проб %d", len(registry), len(probes))
	if len(registry) != len(probes) {
		t.Fatalf("реестр осей и перечень проб разошлись: реестр %v, пробы %v", registry, probes)
	}
	for i := range registry {
		if registry[i] != probes[i] {
			t.Fatalf("реестр осей и перечень проб разошлись на позиции %d: %q против %q "+
				"(реестр %v, пробы %v)", i, registry[i], probes[i], registry, probes)
		}
	}
}

// TestReverseAnswersReachEveryIAMDirectType — три ОБРАТНЫХ вопроса отвечают на
// той же оси, что прямой.
//
// Прямой вердикт и обратные вопросы раскладываются одной раскладкой модели, но
// МЕСТО, где лежат метки, каждый из четырёх запросов называет сам. Проба только
// на прямом вердикте оставила бы три запроса с прежним соединением и зеленела бы
// на них — то есть закрыла бы громкий подслучай и оставила три тихих.
func TestReverseAnswersReachEveryIAMDirectType(t *testing.T) {
	for _, p := range iamDirectProbes {
		t.Run(p.objectType, func(t *testing.T) {
			withTx(t, func(ctx context.Context, tx pgx.Tx) {
				seedTenant(t, ctx, tx)
				seedLabelGrant(t, ctx, tx, p.objectType)
				exec(t, ctx, tx, p.seedSQL, p.objectID, `{"env":"prod"}`)
				exec(t, ctx, tx,
					`INSERT INTO kaname.resource_parent_edge
					   (object_type, object_id, parent_type, parent_id, depth)
					 VALUES ($1, $2, 'account', $3, 1)`, p.objectType, p.objectID, labelScopeAccount)

				ids, _, err := relverdict.List(ctx, tx, relverdict.ListQuery{
					Subject: "user:usr-1", ObjectType: p.objectType, Relation: "v_get",
				})
				if err != nil {
					t.Fatalf("перечисление объектов %s: %v", p.objectType, err)
				}
				if !contains(ids, p.objectID) {
					t.Errorf("перечисление не назвало %s:%s, доступный по метке: %v",
						p.objectType, p.objectID, ids)
				}

				subjects, _, err := relverdict.Subjects(ctx, tx, relverdict.SubjectsQuery{
					ObjectType: p.objectType, ObjectID: p.objectID, Relation: "v_get",
				})
				if err != nil {
					t.Fatalf("перечисление субъектов %s: %v", p.objectType, err)
				}
				if !contains(subjects, "user:usr-1") {
					t.Errorf("перечисление субъектов не назвало держателя меточной выдачи на "+
						"%s:%s: %v", p.objectType, p.objectID, subjects)
				}

				sources, err := relverdict.Expand(ctx, tx, p.objectType, p.objectID, "v_get")
				if err != nil {
					t.Fatalf("разбор оснований %s: %v", p.objectType, err)
				}
				if !hasLabelBinding(sources) {
					t.Errorf("разбор не назвал меточное основание на %s:%s: %+v",
						p.objectType, p.objectID, sources)
				}

				// Отрицание рядом с каждым из трёх: метка снята — все три обязаны
				// перестать называть. Без него положительные утверждения выше
				// зеленели бы и на запросе, который разрешает всё.
				exec(t, ctx, tx, p.relabelSQL, p.objectID, `{"env":"dev"}`)
				ids, _, err = relverdict.List(ctx, tx, relverdict.ListQuery{
					Subject: "user:usr-1", ObjectType: p.objectType, Relation: "v_get",
				})
				if err != nil {
					t.Fatalf("перечисление после смены метки: %v", err)
				}
				if contains(ids, p.objectID) {
					t.Errorf("после смены метки перечисление всё ещё называет %s:%s",
						p.objectType, p.objectID)
				}
				subjects, _, err = relverdict.Subjects(ctx, tx, relverdict.SubjectsQuery{
					ObjectType: p.objectType, ObjectID: p.objectID, Relation: "v_get",
				})
				if err != nil {
					t.Fatalf("субъекты после смены метки: %v", err)
				}
				if contains(subjects, "user:usr-1") {
					t.Errorf("после смены метки субъекты всё ещё называют держателя выдачи на %s:%s",
						p.objectType, p.objectID)
				}
				sources, err = relverdict.Expand(ctx, tx, p.objectType, p.objectID, "v_get")
				if err != nil {
					t.Fatalf("разбор после смены метки: %v", err)
				}
				if hasLabelBinding(sources) {
					t.Errorf("после смены метки разбор всё ещё называет меточное основание на %s:%s",
						p.objectType, p.objectID)
				}
			})
		})
	}
}

// contains — вхождение в перечень.
func contains(set []string, want string) bool {
	for _, s := range set {
		if s == want {
			return true
		}
	}
	return false
}

// hasLabelBinding — среди оснований названа выдача по МЕТОЧНОЙ ветви.
//
// Ветвь названа в самом основании (`<id> (labels)`), поэтому проверяется именно
// она, а не «есть хоть какое-то основание»: последнее зеленело бы на якорной
// ветви, то есть на праве, которое метки не читает.
func hasLabelBinding(sources []relverdict.Source) bool {
	for _, s := range sources {
		if s.Kind == "binding" && strings.Contains(s.Detail, "(labels)") {
			return true
		}
	}
	return false
}

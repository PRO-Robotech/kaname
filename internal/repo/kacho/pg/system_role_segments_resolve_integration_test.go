// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// system_role_segments_resolve_integration_test.go — ИСХОД приведения правил
// системных ролей к словарю глаголов, утверждённый на конечном состоянии базы.
//
// Гейт дерева на глагольную половину сегмента живёт рядом
// (seed_rule_verb_resolvability_integration_test.go) и судит СВОЙСТВО дерева;
// здесь утверждается то, что несёт посев.
//
// Приёмка: services/iam/docs/engineering/acceptance/system-role-segments-resolve.md
// Сценарии IAM-SV-1-01, -04, -07. Задача продукта kacho#1815.
//
// # Здесь стояли ещё три пробы — они сняты вместе со своим предметом
//
// Сценарии IAM-SV-1-12, -13, -14 утверждали о ТЕЛЕ миграции
// 20260901231022: идемпотентность её повтора, её отказ вместо догадки при
// полуподстановке, и то, что её предпосылка утверждается отдельно от предмета.
// Тело читалось из поставки, а каталог приводился к ревизии той миграции —
// иначе предпосылка отказывала законно и заслоняла предмет (kacho#1867).
//
// Свод 171 миграции в одну первичную снял ФАЙЛ, а с ним и предмет всех трёх:
// «миграции с префиксом 20260901231022 в поставке нет». Переносить их некуда —
// идемпотентность повтора и отказ предпосылки суть свойства ШАГА, а шага больше
// нет. Живая половина этого предмета — «всякий глагол, названный правилом,
// объявлен своим типом» — принадлежит гейту дерева по соседству и здесь не
// пересказывается.
package pg_test

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/internal/pgtest"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// segmentMigrationPrefix — имя миграции, ПРОИЗВЕДШЕЙ это состояние. Стоит
// здесь ради находки: она обязана называть, что смотреть. Файла в поставке
// больше нет — свод сложил его в первичную, — и текст его никем не читается;
// исторической ссылкой имя остаётся законным, координатой дерева — нет.
const segmentMigrationPrefix = "20260901231022"

// TestIAMSV101_RuleRefOrphanTraceIsGone — IAM-SV-1-01: следа объявления не
// остаётся.
//
// `role_grant_orphan` со `source = 'rule_ref'` — запись о ПЕРЕСЕЛЕНИИ
// объявления, а не о выдаче. Запись, которой больше нечего описывать, —
// находка: она утверждала бы, что объявление живо, при том что его нет.
func TestIAMSV101_RuleRefOrphanTraceIsGone(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	// Перепись — до вердикта, и по ОБЕИМ популяциям следа: «ноль строк
	// объявления» обязано быть отличимо от «таблица пуста целиком».
	rows, err := pool.Query(ctx, `
		SELECT source, count(*) FROM kacho_iam.role_grant_orphan GROUP BY source ORDER BY source`)
	require.NoError(t, err)
	bySource := map[string]int{}
	for rows.Next() {
		var src string
		var n int
		require.NoError(t, rows.Scan(&src, &n))
		bySource[src] = n
	}
	require.NoError(t, rows.Err())
	t.Logf("след сирот: role_verb=%d, rule_ref=%d", bySource["role_verb"], bySource["rule_ref"])

	// Предпосылка: таблица следа существует и адресуема. Проверяется явно —
	// иначе «ноль строк» приходило бы и от несуществующего предмета.
	var relKind string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT relkind FROM pg_class WHERE oid = 'kacho_iam.role_grant_orphan'::regclass`).Scan(&relKind),
		"предпосылка нарушена: таблицы следа нет — «ноль строк» получено даром")
	require.Equal(t, "r", relKind)

	detail, err := pool.Query(ctx, `
		SELECT object_type, verb, count(*)
		  FROM kacho_iam.role_grant_orphan
		 WHERE source = 'rule_ref'
		 GROUP BY 1, 2 ORDER BY 1, 2`)
	require.NoError(t, err)
	var left []string
	for detail.Next() {
		var objectType, verb string
		var n int
		require.NoError(t, detail.Scan(&objectType, &verb, &n))
		left = append(left, fmt.Sprintf("%s.%s ×%d", objectType, verb, n))
	}
	require.NoError(t, detail.Err())

	require.Emptyf(t, left,
		"объявленные сегменты, не резолвящиеся ни в одно право, остались в следе: %s.\n"+
			"Их снимает миграция %s вместе с их предметом — глаголом правила; "+
			"остаток означает, что снят не весь предмет либо предикат снятия несимметричен "+
			"предикату постановки (kacho#1815, §2.7 приёмки).", strings.Join(left, ", "), segmentMigrationPrefix)
}

// TestIAMSV107_RuleRefProjectionEqualsWhatRulesDeclare — IAM-SV-1-07: проекция
// объявленных сегментов равна тому, что правила ОБЪЯВЛЯЮТ.
//
// Почему это красное ДО миграции: обратное заполнение 1030001 клало в проекцию
// только резолвящееся, а `domain.RuleRefsOf` даёт ВСЕ объявленные сегменты.
// Разница — ровно те двадцать. После приведения правил к словарю обе стороны
// говорят об одном.
func TestIAMSV107_RuleRefProjectionEqualsWhatRulesDeclare(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()

	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	declared := map[string]map[string]bool{}
	roleName := map[string]string{}
	rows, err := pool.Query(ctx, `SELECT id, name, rules FROM kacho_iam.roles ORDER BY id`)
	require.NoError(t, err)
	var roles, refs int
	for rows.Next() {
		var id, name string
		var raw []byte
		require.NoError(t, rows.Scan(&id, &name, &raw))
		roles++
		roleName[id] = name
		if len(raw) == 0 {
			continue
		}
		rules, derr := domain.DecodeRules(raw)
		require.NoErrorf(t, derr, "роль %s (%s): rules не декодируются", id, name)
		set := map[string]bool{}
		for _, ref := range domain.RuleRefsOf(rules) {
			set[ref.Module+"."+ref.Resource+"."+ref.Verb] = true
			refs++
		}
		if len(set) > 0 {
			declared[id] = set
		}
	}
	require.NoError(t, rows.Err())

	projected := map[string]map[string]bool{}
	prows, err := pool.Query(ctx, `
		SELECT role_id, module, resource, COALESCE(verb, '') FROM kacho_iam.role_rule_ref`)
	require.NoError(t, err)
	var projectedRows int
	for prows.Next() {
		var roleID, module, resource, verb string
		require.NoError(t, prows.Scan(&roleID, &module, &resource, &verb))
		projectedRows++
		if projected[roleID] == nil {
			projected[roleID] = map[string]bool{}
		}
		projected[roleID][module+"."+resource+"."+verb] = true
	}
	require.NoError(t, prows.Err())

	t.Logf("осмотрено: ролей=%d, объявленных сегментов=%d, строк проекции=%d", roles, refs, projectedRows)
	require.NotZerof(t, roles, "предпосылка нарушена: ни одной роли")
	require.NotZerof(t, refs, "предпосылка нарушена: ни одного объявленного сегмента — "+
		"равенство множеств было бы получено даром")
	require.NotZerof(t, projectedRows, "предпосылка нарушена: проекция пуста")

	var diff []string
	for id, want := range declared {
		got := projected[id]
		for seg := range want {
			if !got[seg] {
				diff = append(diff, fmt.Sprintf("объявлено, но не спроецировано: роль %q, сегмент %s", roleName[id], seg))
			}
		}
	}
	for id, got := range projected {
		want := declared[id]
		for seg := range got {
			if !want[seg] {
				diff = append(diff, fmt.Sprintf("спроецировано, но не объявлено: роль %q, сегмент %s", roleName[id], seg))
			}
		}
	}
	sort.Strings(diff)
	require.Emptyf(t, diff, "проекция объявленных сегментов разошлась с правилами (%d расхождений):\n%s",
		len(diff), strings.Join(diff, "\n"))
}

// TestIAMSV104_VerdictProjectionIsUnchanged — IAM-SV-1-04: ХАРАКТЕРИЗУЮЩИЙ
// ЗАМОК, а не RED. Дерево уже даёт это поведение, и проба обязана ПЕРЕЖИТЬ
// изменение: требовать от неё красноты запрещено.
//
// Утверждается то, ради чего вся правка защитима: набор глаголов, который
// РЕАЛЬНО получает арендатор, до и после приведения правил один и тот же.
// Приведение схлопывается в снятие второго имени того, что уже названо.
//
// Почему не через таблицу `role_verb`: в фикстуре, применяющей только миграции,
// она пуста — её наполняет досев на старте. Утверждение через неё было бы
// `0 = 0`, то есть вакуумным. Граница названа, а не обойдена.
func TestIAMSV104_VerdictProjectionIsUnchanged(t *testing.T) {
	cases := []struct {
		fgaType string
		before  []string
		after   []string
	}{
		{
			fgaType: "vpc_network",
			before:  []string{"read", "list", "get"},
			after:   []string{"get", "list"},
		},
		{
			fgaType: "compute_instance",
			before:  []string{"read", "list", "get"},
			after:   []string{"get", "list"},
		},
		{
			fgaType: "nlb_target_group",
			before:  []string{"addTargets", "removeTargets", "get", "list", "listOperations"},
			after:   []string{"addTargets", "removeTargets", "get", "list"},
		},
		{
			fgaType: "nlb_network_load_balancer",
			before:  []string{"getTargetStates", "listOperations", "get", "list"},
			after:   []string{"get", "list"},
		},
		{
			fgaType: "nlb_listener",
			before:  []string{"get", "list", "listOperations"},
			after:   []string{"get", "list"},
		},
	}
	for _, c := range cases {
		t.Run(c.fgaType, func(t *testing.T) {
			typeVerbs := authzmap.VerbsOfType(c.fgaType)
			require.NotEmptyf(t, typeVerbs, "контроль: тип %q обязан объявлять глаголы — "+
				"на пустом наборе обе стороны дали бы nil и равенство прошло бы даром", c.fgaType)

			was := authzmap.GrantedVerbs(c.fgaType, c.before, typeVerbs)
			now := authzmap.GrantedVerbs(c.fgaType, c.after, typeVerbs)
			require.NotEmptyf(t, was, "контроль: набор «до» пуст — сравнение вакуумно")
			sort.Strings(was)
			sort.Strings(now)
			require.Equal(t, was, now,
				"проекция вердикта изменилась: арендатор теряет действие. "+
					"Приведение правил обязано быть снятием ВТОРОГО ИМЕНИ того, что уже названо, "+
					"а не отнятием права (kacho#1815, §2.6 приёмки)")
			t.Logf("%s: до=%v после=%v → выдача %v", c.fgaType, c.before, c.after, now)
		})
	}
}

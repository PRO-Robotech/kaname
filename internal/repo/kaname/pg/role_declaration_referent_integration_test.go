// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// role_declaration_referent_integration_test.go — обход по ОБЪЯВЛЕНИЮ роли:
// каждая названная правилом пара `(модуль, ресурс)` обязана иметь ЖИВУЮ строку
// каталога.
//
// Приёмка: services/iam/docs/engineering/acceptance/roles-pointing-at-moved-resources.md
// (APPROVED круга 2), сценарии IAM-RM-1-01, -05, -06, -07, -14, -15. Задача
// продукта #1825.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ОБХОД, А НЕ ЕЩЁ ОДИН КЛЮЧ
//
// Ключ на объявлении невыразим by construction: `roles.rules` — jsonb, а
// подзапрос в `CHECK` отвергается DDL. Ключи, которые в дереве есть
// (`role_rule_ref_res_fk`, `role_verb_type_fk`), стоят на ПРОЕКЦИЯХ, и писателей
// у проекции сегментов ровно два — создание и правка ПОЛЬЗОВАТЕЛЬСКОЙ роли.
// Системная роль заводится сырым SQL миграции и этим путём не проходит никогда:
// проекции не пишется вовсе, ключу нечего судить, роль существует, назначается и
// не даёт ничего. Обход добавляет ровно то, чего ключу не хватает, — суждение о
// роли, у которой проекции НЕТ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТО НЕ ВТОРОЕ МЕСТО ОБ ОДНОМ ПРЕДМЕТЕ
//
// Сосед `TestIAMSV107_RuleRefProjectionEqualsWhatRulesDeclare` утверждает
// РАВЕНСТВО двух множеств — объявленного и спроецированного — и о живости пары
// не говорит ничего. Этот обход утверждает ЖИВОСТЬ и о равенстве не говорит
// ничего. Предметы разные, и это проверяемо: роль, у которой И объявление, И
// проекция называют снятую пару, оставит соседа зелёным и покраснит этот обход.
//
// Проба TestIAMRM107_… ниже подаёт обе роли разом и утверждает ПОЛОВИНУ этого —
// что обход находит свою и НЕ присваивает чужую. Вторую половину — что предмет
// соседа существует и он его находит — она НЕ утверждает и звать соседа не
// станет: два места об одном предмете разошлись бы молча. Вместо этого она
// проверяет ПРЕДПОСЫЛКУ соседа (проекция у второй роли пуста), иначе её
// молчание об этой роли было бы получено даром.
//
// Третья мыслимая причина расхождения — «пара жива, но проекции нет» — предмет
// СОСЕДА, и здесь она НЕ производится намеренно: находкой её сделал бы обход,
// который судит две разные вещи одним текстом, и читатель шёл бы чинить не то.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТОТ ОБХОД НЕ ГОВОРИТ
//
// Он судит НАМИГРИРОВАННУЮ базу. О состоянии базы после досева на старте он не
// утверждает ничего — это задача продукта #1821.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/pgtest"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// declarationCensus — объём осмотренного. Четыре величины, и ни одна не лишняя:
// «ноль находок» обязано быть отличимо и от «ноль ролей», и от «ноль сегментов»,
// и от «каталог пуст». Подстановочные считаются ОТДЕЛЬНО — они парой не
// являются, и без своего числа их пропуск был бы неотличим от их отсутствия.
type declarationCensus struct {
	Roles        int
	Segments     int
	Wildcards    int
	CatalogPairs int
}

// catalogPair — строка каталога, какой её видит обход.
type catalogPair struct {
	live         bool
	supersededBy string
}

// auditDeclaredPairs — ЯДРО обхода, отделённое от пробы намеренно: инъекция
// обязана звать ту же функцию, что и штатный прогон. Проба со своей копией
// разбора доказывала бы свойство копии.
//
// Возвращает находки (по одной на пару, а не на глагол: единица предиката —
// сегмент объявления) и перепись.
func auditDeclaredPairs(t *testing.T, ctx context.Context, pool *pgxpool.Pool) ([]string, declarationCensus) {
	t.Helper()

	catalog := map[string]catalogPair{}
	crows, err := pool.Query(ctx, `
		SELECT module, resource, live, COALESCE(superseded_by, '')
		  FROM kaname.catalog_resource`)
	require.NoError(t, err, "прочитать каталог ресурсов")
	var c declarationCensus
	for crows.Next() {
		var module, resource, successor string
		var live bool
		require.NoError(t, crows.Scan(&module, &resource, &live, &successor))
		catalog[module+"."+resource] = catalogPair{live: live, supersededBy: successor}
		c.CatalogPairs++
	}
	require.NoError(t, crows.Err())

	rows, err := pool.Query(ctx, `SELECT id, name, rules FROM kaname.roles ORDER BY id`)
	require.NoError(t, err, "прочитать роли")
	type pairKey struct{ role, module, resource string }
	seen := map[pairKey]bool{}
	var findings []string
	for rows.Next() {
		var id, name string
		var raw []byte
		require.NoError(t, rows.Scan(&id, &name, &raw))
		c.Roles++
		if len(raw) == 0 {
			continue
		}
		rules, derr := domain.DecodeRules(raw)
		require.NoErrorf(t, derr, "роль %s (%s): rules не декодируются", id, name)
		for _, r := range rules {
			for _, res := range r.Resources {
				c.Segments++
				// Подстановка называет не имя, а «все»: адресовать ею строку
				// каталога нечего. Пропуск считается отдельным числом.
				if r.Module == "*" || res == "*" {
					c.Wildcards++
					continue
				}
				k := pairKey{role: name, module: r.Module, resource: res}
				if seen[k] {
					continue
				}
				seen[k] = true
				dotted := r.Module + "." + res
				row, known := catalog[dotted]
				switch {
				case !known:
					findings = append(findings, fmt.Sprintf(
						"роль %q, сегмент %s: пара не объявлена каталогом", name, dotted))
				case !row.live && row.supersededBy != "":
					findings = append(findings, fmt.Sprintf(
						"роль %q, сегмент %s: пара снята, преемник %s", name, dotted, row.supersededBy))
				case !row.live:
					findings = append(findings, fmt.Sprintf(
						"роль %q, сегмент %s: пара снята, преемник не объявлен", name, dotted))
				}
			}
		}
	}
	require.NoError(t, rows.Err())
	sort.Strings(findings)
	return findings, c
}

// logCensus — перепись печатается ДО вердикта каждой пробой этого файла.
func logCensus(t *testing.T, c declarationCensus) {
	t.Helper()
	t.Logf("перепись: ролей прочитано %d; сегментов разобрано %d; из них подстановочных %d; "+
		"пар каталога прочитано %d", c.Roles, c.Segments, c.Wildcards, c.CatalogPairs)
}

// premiseViolation — IAM-RM-1-14: чем именно пустой обход НЕГОДЕН, либо пустая
// строка, если он годен.
//
// Отдельной ЧИСТОЙ функцией, а не тремя `require` внутри пробы: способность
// предпосылки сработать иначе недоказуема — опустошить каталог живой базы
// нельзя, его строки держат ключи проекции. Функция же принимает перепись
// напрямую, и её обе стороны утверждает проба без Postgres
// (TestIAMRM114_EmptyWalkIsRedNotGreen).
func premiseViolation(c declarationCensus) string {
	switch {
	case c.Roles == 0:
		return "ПРЕДПОСЫЛКА НАРУШЕНА: ни одной роли — утверждение о живости пар " +
			"получено даром"
	case c.CatalogPairs == 0:
		return "ПРЕДПОСЫЛКА НАРУШЕНА: каталог пуст — сверять сегменты не с чем, " +
			"и всякая пара выглядела бы объявленной"
	case c.Segments == 0:
		return "ПРЕДПОСЫЛКА НАРУШЕНА: ни одного объявленного сегмента — роли без " +
			"правил не дают предмета обходу"
	}
	return ""
}

// requirePremise — тот же вердикт, поданный пробе.
func requirePremise(t *testing.T, c declarationCensus) {
	t.Helper()
	require.Emptyf(t, premiseViolation(c), "пустой обход обязан давать КРАСНОЕ: "+
		"«ноль находок» неотличимо от «ноль прочитанного»")
}

// TestIAMRM114_EmptyWalkIsRedNotGreen — IAM-RM-1-14, обе стороны.
//
// Postgres не нужен: предмет — вердикт о переписи, а не о базе. Это сказано
// вслух, чтобы зелёное этой пробы не читалось шире сделанного: она НЕ
// утверждает, что обход действительно прочитал дерево, — это утверждает сам
// обход своей переписью.
func TestIAMRM114_EmptyWalkIsRedNotGreen(t *testing.T) {
	full := declarationCensus{Roles: 48, Segments: 52, Wildcards: 6, CatalogPairs: 30}
	require.Empty(t, premiseViolation(full),
		"положительный контроль: непустая перепись объявлена негодной — тогда "+
			"отрицание ниже зеленело бы на всём")

	for _, tc := range []struct {
		name   string
		census declarationCensus
		says   string
	}{
		{"ролей ноль", declarationCensus{Segments: 52, CatalogPairs: 30}, "ни одной роли"},
		{"каталог пуст", declarationCensus{Roles: 48, Segments: 52}, "каталог пуст"},
		{"сегментов ноль", declarationCensus{Roles: 48, CatalogPairs: 30}, "ни одного объявленного сегмента"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			v := premiseViolation(tc.census)
			require.NotEmpty(t, v, "пустой обход объявлен годным — «ноль находок» "+
				"стало бы неотличимо от «ноль прочитанного»")
			require.Containsf(t, v, tc.says, "вердикт не называет ПРИЧИНУ негодности: %s", v)
		})
	}
}

// declareRuleFor — правило роли, записанное ПРЯМЫМ оператором, без проекции.
//
// Это не срез угла, а воспроизведение полосы: системная роль заводится сырым SQL
// миграции, писателя проекции на этом пути нет вовсе, и ключ каталога не
// срабатывает. Пиши проба через порт — она проверяла бы полосу
// ПОЛЬЗОВАТЕЛЬСКОЙ роли, у которой ключ и так стоит, то есть другой предмет.
func declareRuleFor(t *testing.T, ctx context.Context, pool *pgxpool.Pool,
	role domain.RoleID, module string, resources []string, verbs []string) {
	t.Helper()
	rules := domain.Rules{{Module: module, Resources: resources, Verbs: verbs}}
	raw, err := domain.EncodeRules(rules)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `UPDATE kaname.roles SET rules = $2 WHERE id = $1`,
		string(role), raw)
	require.NoError(t, err, "объявить правило роли прямым оператором")
}

// TestIAMRM101_DeclaredSegmentsNameALiveCatalogPair — IAM-RM-1-01 и IAM-RM-1-14.
//
// Штатный предикат задачи: на намигрированной базе расхождений НОЛЬ. Красноту
// этого обхода доказывает инъекция ниже, а не состояние дерева, — и это сказано
// вслух, потому что зелёное здесь ожидаемо и само по себе ничего не доказывает.
func TestIAMRM101_DeclaredSegmentsNameALiveCatalogPair(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	findings, c := auditDeclaredPairs(t, ctx, pool)
	logCensus(t, c)
	requirePremise(t, c)

	require.Emptyf(t, findings, "роль называет пару вне ЖИВОГО каталога (%d):\n%s",
		len(findings), strings.Join(findings, "\n"))
}

// TestIAMRM105_AbsentPairIsFoundWithItsCause — IAM-RM-1-05 плюс положительный
// контроль.
//
// Отрицание без положительного контроля неотличимо от обхода, который не нашёл
// НИЧЕГО, потому что ничего и не читал.
func TestIAMRM105_AbsentPairIsFoundWithItsCause(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: живая пара того же модуля в находки не попадает.
	live := catalogRole(t, ctx, pool, "rm105live")
	declareRuleFor(t, ctx, pool, live, "compute", []string{"instance"}, []string{"get"})

	before, c := auditDeclaredPairs(t, ctx, pool)
	logCensus(t, c)
	requirePremise(t, c)
	require.Emptyf(t, before, "контроль: живая пара названа находкой:\n%s",
		strings.Join(before, "\n"))

	// ИНЪЕКЦИЯ: пара, которой в каталоге нет вовсе.
	absent := catalogRole(t, ctx, pool, "rm105absent")
	declareRuleFor(t, ctx, pool, absent, "compute", []string{"nonesuch"}, []string{"get"})

	after, c2 := auditDeclaredPairs(t, ctx, pool)
	logCensus(t, c2)
	require.Len(t, after, 1, "ожидалась ровно одна находка, получено: %v", after)
	require.Contains(t, after[0], "compute.nonesuch")
	require.Contains(t, after[0], "пара не объявлена каталогом",
		"находка называет расхождение вместо ПРИЧИНЫ — читатель пойдёт чинить не то")
}

// TestIAMRM106_RetiredPairIsFoundWithItsSuccessor — IAM-RM-1-06.
//
// У трёх снятых строк каталога преемник ОБЪЯВЛЕН, поэтому находка обязана его
// назвать: у трёх причин три разных исправления, и «переписать правило на
// преемника» исполнимо только если преемник назван.
func TestIAMRM106_RetiredPairIsFoundWithItsSuccessor(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	// Предпосылка пробы — факт каталога, а не наше допущение о нём.
	var successor string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT COALESCE(superseded_by, '') FROM kaname.catalog_resource
		 WHERE module = 'compute' AND resource = 'disk' AND NOT live`).Scan(&successor),
		"ПРЕДПОСЫЛКА НАРУШЕНА: снятой строки compute.disk в каталоге нет")
	require.NotEmpty(t, successor, "ПРЕДПОСЫЛКА НАРУШЕНА: у снятой пары нет преемника")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ: живая пара того же модуля.
	live := catalogRole(t, ctx, pool, "rm106live")
	declareRuleFor(t, ctx, pool, live, "compute", []string{"instance"}, []string{"get"})

	dead := catalogRole(t, ctx, pool, "rm106dead")
	declareRuleFor(t, ctx, pool, dead, "compute", []string{"disk"}, []string{"get"})

	findings, c := auditDeclaredPairs(t, ctx, pool)
	logCensus(t, c)
	requirePremise(t, c)
	require.Len(t, findings, 1, "ожидалась ровно одна находка, получено: %v", findings)
	require.Contains(t, findings[0], "compute.disk")
	require.Contains(t, findings[0], "пара снята")
	require.Containsf(t, findings[0], successor,
		"находка не называет преемника — «переписать правило на преемника» неисполнимо")

	// ВТОРАЯ СТОРОНА: у строки без преемника находка говорит именно это, а не
	// молчит и не обещает того, чего каталог не несёт.
	_, err = pool.Exec(ctx, `
		UPDATE kaname.catalog_resource SET superseded_by = NULL
		 WHERE module = 'compute' AND resource = 'disk' AND NOT live`)
	require.NoError(t, err)

	findings, _ = auditDeclaredPairs(t, ctx, pool)
	require.Len(t, findings, 1)
	require.Contains(t, findings[0], "преемник не объявлен")
}

// TestIAMRM107_CauseIsNotSubstitutedByDivergence — IAM-RM-1-07.
//
// Две роли: одна называет СНЯТУЮ пару (её предмет — этот обход), другая называет
// ЖИВУЮ пару, но проекции у неё нет (её предмет — сосед по равенству множеств).
// Каждая проверка обязана найти СВОЮ и не найти чужую: иначе один текст описывал
// бы два разных исправления.
func TestIAMRM107_CauseIsNotSubstitutedByDivergence(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	retired := catalogRole(t, ctx, pool, "rm107retired")
	declareRuleFor(t, ctx, pool, retired, "compute", []string{"snapshot"}, []string{"get"})

	// Живая пара, объявление есть, проекции нет — прямой оператор её и не пишет.
	unprojected := catalogRole(t, ctx, pool, "rm107unproj")
	declareRuleFor(t, ctx, pool, unprojected, "vpc", []string{"network"}, []string{"get"})

	findings, c := auditDeclaredPairs(t, ctx, pool)
	logCensus(t, c)
	requirePremise(t, c)

	require.Len(t, findings, 1, "обход обязан найти ТОЛЬКО снятую пару, получено: %v", findings)
	require.Contains(t, findings[0], "compute.snapshot")
	for _, f := range findings {
		require.NotContainsf(t, f, "vpc.network",
			"обход присвоил себе предмет соседа: «объявлено, проекции нет» — не его причина")
	}

	// Вторая половина утверждения — что предмет соседа существует и он ЕГО
	// находит — проверяется соседней пробой равенства множеств; звать её отсюда
	// значило бы завести второе место об одном предмете. Здесь утверждается
	// только то, что этот обход её предмета НЕ присваивает.
	var projected int
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.role_rule_ref WHERE role_id = $1`,
		string(unprojected)).Scan(&projected))
	require.Zerof(t, projected, "предпосылка пробы ложна: проекция у роли есть, "+
		"значит расхождения множеств нет и находить соседу нечего")
}

// TestIAMRM115_WildcardIsNotAPair — IAM-RM-1-15.
//
// Подстановка называет не имя, а «все»; адресовать ею строку каталога нечего.
// Пропуск обязан быть виден ОТДЕЛЬНЫМ числом переписи: иначе «пропустили» стало
// бы неотличимо от «не встретили».
func TestIAMRM115_WildcardIsNotAPair(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx := context.Background()
	pool, err := pgxpool.New(ctx, setupTestDB(t))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	_, before := auditDeclaredPairs(t, ctx, pool)

	all := catalogRole(t, ctx, pool, "rm115all")
	declareRuleFor(t, ctx, pool, all, "*", []string{"*"}, []string{"*"})
	half := catalogRole(t, ctx, pool, "rm115half")
	declareRuleFor(t, ctx, pool, half, "vpc", []string{"*"}, []string{"*"})

	findings, c := auditDeclaredPairs(t, ctx, pool)
	logCensus(t, c)
	requirePremise(t, c)
	require.Emptyf(t, findings, "подстановка посчитана парой:\n%s", strings.Join(findings, "\n"))
	require.Equalf(t, before.Wildcards+2, c.Wildcards,
		"перепись не считает подстановочные сегменты отдельно — их пропуск "+
			"неотличим от их отсутствия")

	// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ на том же входе: конкретная мёртвая пара найдена,
	// то есть молчание выше — свойство подстановки, а не немоты обхода.
	dead := catalogRole(t, ctx, pool, "rm115dead")
	declareRuleFor(t, ctx, pool, dead, "compute", []string{"image"}, []string{"get"})
	findings, _ = auditDeclaredPairs(t, ctx, pool)
	require.Len(t, findings, 1, "получено: %v", findings)
	require.Contains(t, findings[0], "compute.image")
}

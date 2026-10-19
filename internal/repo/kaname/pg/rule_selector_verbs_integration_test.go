// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// rule_selector_verbs_integration_test.go — КАРТА ГЛАГОЛОВ ПРАВИЛА НА СТРОКЕ
// СЕЛЕКТОРА: писатель, очередь пересчёта, стражи схемы и вырезание применителем
// каталога (kaname#878).
//
// Каждая проба меняет ровно один факт против законного близнеца. Каталог —
// модуль-проба применителя: типы и глаголы заводятся тем же путём, каким их
// заводит доставленный манифест.

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"testing"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// svWrite — замена селекторов роли продуктовым писателем, одной транзакцией.
func svWrite(ctx context.Context, pool *pgxpool.Pool, role domain.RoleID, sels []domain.RuleSelector) error {
	w, err := kanamepg.New(pool, nil).Writer(ctx)
	if err != nil {
		return err
	}
	if err := w.RolesW().ReplaceRuleSelectors(ctx, role, sels); err != nil {
		_ = w.Rollback(ctx)
		return err
	}
	return w.Commit(ctx)
}

// svRegrain — пересчёт глаголов правил роли продуктовым писателем.
func svRegrain(ctx context.Context, pool *pgxpool.Pool, role domain.RoleID, sels []domain.RuleSelector) error {
	w, err := kanamepg.New(pool, nil).Writer(ctx)
	if err != nil {
		return err
	}
	if err := w.RolesW().RegrainSelectorVerbs(ctx, role, sels); err != nil {
		_ = w.Rollback(ctx)
		return err
	}
	return w.Commit(ctx)
}

// svVerbs — карта глаголов строки селектора; ok=false — строки нет.
func svVerbs(t *testing.T, ctx context.Context, pool *pgxpool.Pool, role domain.RoleID, fp string) (map[string][]string, bool) {
	t.Helper()
	var raw []byte
	err := pool.QueryRow(ctx, `SELECT verbs_by_type FROM kaname.role_rule_selectors
	                            WHERE role_id = $1 AND rule_fp = $2`, string(role), fp).Scan(&raw)
	if err != nil {
		return nil, false
	}
	out := map[string][]string{}
	require.NoError(t, json.Unmarshal(raw, &out))
	for k := range out {
		slices.Sort(out[k])
	}
	return out, true
}

func svPending(t *testing.T, ctx context.Context, pool *pgxpool.Pool, role domain.RoleID) bool {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.role_selector_verbs_pending WHERE role_id = $1`, string(role)).Scan(&n))
	return n > 0
}

func svSQLState(err error) string {
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		return pg.Code
	}
	return ""
}

// svSystemRole — системная роль модуля-пробы сырым SQL: путём миграции, мимо
// пути роли. Применитель каталога её селекторы не укорачивает.
func svSystemRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id, segment string) domain.RoleID {
	t.Helper()
	_, err := pool.Exec(ctx,
		`INSERT INTO kaname.roles (id, name, permissions, rules, cluster_id)
		 VALUES ($1, $2, '["iam.role.*.get"]'::jsonb, '[]'::jsonb, 'cluster_root')`, id, applierProbeModule+"."+segment)
	require.NoErrorf(t, err, "посев системной роли %s", id)
	return domain.RoleID(id)
}

// (д) Писатель отвергает селектор без вычисленных глаголов, и ни одной строки не
// остаётся; близнец с вычисленными глаголами проходит.
func TestSelectorVerbs_WriterRefusesUncomputedGrants(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	_, err := applierOver(t, pool).Apply(ctx, probeManifest(probeResource("svnil", "get")))
	require.NoError(t, err)
	role := catalogRole(t, ctx, pool, "svnil")
	typ := applierProbeModule + ".svnil"

	err = svWrite(ctx, pool, role, []domain.RuleSelector{{RuleFP: "fp-nil", Arm: domain.ArmAnchor, ObjectTypes: []string{typ}}})
	require.Error(t, err, "селектор без вычисленных глаголов обязан быть отвергнут")
	_, present := svVerbs(t, ctx, pool, role, "fp-nil")
	require.False(t, present, "отвергнутая запись оставила строку селектора")

	require.NoError(t, svWrite(ctx, pool, role, []domain.RuleSelector{{RuleFP: "fp-nil", Arm: domain.ArmAnchor,
		ObjectTypes: []string{typ}, Grants: map[string][]string{typ: {"get"}}}}),
		"КОНТРОЛЬ: селектор с вычисленными глаголами обязан записаться")
	got, present := svVerbs(t, ctx, pool, role, "fp-nil")
	require.True(t, present)
	require.Equal(t, map[string][]string{typ: {"get"}}, got)
}

// (г) Правка роли снимает её из очереди пересчёта; близнец — роль без правки
// остаётся в очереди.
func TestSelectorVerbs_RoleEditLeavesTheQueue(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	_, err := applierOver(t, pool).Apply(ctx, probeManifest(probeResource("svedit", "get")))
	require.NoError(t, err)
	edited := catalogRole(t, ctx, pool, "svedita")
	idle := catalogRole(t, ctx, pool, "sveditb")
	for _, r := range []domain.RoleID{edited, idle} {
		_, err := pool.Exec(ctx, `INSERT INTO kaname.role_selector_verbs_pending (role_id) VALUES ($1)`, string(r))
		require.NoError(t, err)
	}
	typ := applierProbeModule + ".svedit"
	require.NoError(t, svWrite(ctx, pool, edited, []domain.RuleSelector{{RuleFP: "fp-e", Arm: domain.ArmAnchor,
		ObjectTypes: []string{typ}, Grants: map[string][]string{typ: {"get"}}}}))
	require.False(t, svPending(t, ctx, pool, edited), "правка роли не сняла её из очереди")
	require.True(t, svPending(t, ctx, pool, idle), "БЛИЗНЕЦ: роль без правки обязана остаться в очереди")
}

// (ж) Применитель каталога, укорачивая селектор роли арендатора, вырезает и
// глаголы снятого типа из карты; глаголы живого типа остаются.
func TestSelectorVerbs_CatalogPruneCutsTheMapKeys(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	_, err := applier.Apply(ctx, probeManifest(probeResource("svkeep", "get"), probeResource("svdrop", "get")))
	require.NoError(t, err)
	role := catalogRole(t, ctx, pool, "svprune")
	keep, drop := applierProbeModule+".svkeep", applierProbeModule+".svdrop"
	require.NoError(t, svWrite(ctx, pool, role, []domain.RuleSelector{{RuleFP: "fp-p", Arm: domain.ArmAnchor,
		ObjectTypes: []string{keep, drop}, Grants: map[string][]string{keep: {"get"}, drop: {"get"}}}}))

	_, err = applier.Apply(ctx, probeManifest(probeResource("svkeep", "get")))
	require.NoError(t, err)
	got, present := svVerbs(t, ctx, pool, role, "fp-p")
	require.True(t, present, "селектор с живым типом обязан остаться укороченным")
	require.Equal(t, map[string][]string{keep: {"get"}}, got, "ключ снятого типа остался в карте")
}

// (з) Пересчёт глаголов строки, чей тип каталог снял после её записи, проходит
// стража живости типов: запись карты ссылок на каталог не меняет. Строка
// системной роли — применитель её не укорачивает. Пересчёт пересекает карту с
// типами строки.
func TestSelectorVerbs_RegrainOfARowWithARetiredTypePassesTheTypeGuard(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	applier := applierOver(t, pool)
	_, err := applier.Apply(ctx, probeManifest(probeResource("svlive", "get"), probeResource("svgone", "get")))
	require.NoError(t, err)
	role := svSystemRole(t, ctx, pool, "rol-sv-sys-z", "svsysz")
	live, gone := applierProbeModule+".svlive", applierProbeModule+".svgone"
	require.NoError(t, svWrite(ctx, pool, role, []domain.RuleSelector{{RuleFP: "fp-z", Arm: domain.ArmAnchor,
		ObjectTypes: []string{live, gone}, Grants: map[string][]string{live: {"get"}, gone: {"get"}}}}))
	_, err = applier.Apply(ctx, probeManifest(probeResource("svlive", "get")))
	require.NoError(t, err)

	require.NoError(t, svRegrain(ctx, pool, role, []domain.RuleSelector{{RuleFP: "fp-z", Arm: domain.ArmAnchor,
		ObjectTypes: []string{live, gone}, Grants: map[string][]string{live: {"get"}}}}),
		"пересчёт строки со снятым типом отвергнут стражем живости")
	got, _ := svVerbs(t, ctx, pool, role, "fp-z")
	require.Equal(t, map[string][]string{live: {"get"}}, got)
}

// Пересчёт пересекает карту с типами СТРОКИ: тип, которого строка не охватывает,
// в карту не попадает. Близнец — тип строки попадает.
func TestSelectorVerbs_RegrainIntersectsTheMapWithTheRowTypes(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	_, err := applierOver(t, pool).Apply(ctx, probeManifest(probeResource("svrow", "get"), probeResource("svalien", "get")))
	require.NoError(t, err)
	role := catalogRole(t, ctx, pool, "svrow")
	row, alien := applierProbeModule+".svrow", applierProbeModule+".svalien"
	require.NoError(t, svWrite(ctx, pool, role, []domain.RuleSelector{{RuleFP: "fp-r", Arm: domain.ArmAnchor,
		ObjectTypes: []string{row}, Grants: map[string][]string{row: {"get"}}}}))
	require.NoError(t, svRegrain(ctx, pool, role, []domain.RuleSelector{{RuleFP: "fp-r", Arm: domain.ArmAnchor,
		ObjectTypes: []string{row, alien}, Grants: map[string][]string{row: {"get"}, alien: {"get"}}}}))
	got, _ := svVerbs(t, ctx, pool, role, "fp-r")
	require.Equal(t, map[string][]string{row: {"get"}}, got, "в карту попал тип, которого строка не охватывает")
}

// Инвариант карты держит СХЕМА: ключи — подмножество типов строки, значения —
// непустые массивы строк. Близнец — законная карта проходит.
func TestSelectorVerbs_MapInvariantIsAConstraint(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	_, err := applierOver(t, pool).Apply(ctx, probeManifest(probeResource("svck", "get")))
	require.NoError(t, err)
	role := catalogRole(t, ctx, pool, "svck")
	typ := applierProbeModule + ".svck"
	require.NoError(t, svWrite(ctx, pool, role, []domain.RuleSelector{{RuleFP: "fp-c", Arm: domain.ArmAnchor,
		ObjectTypes: []string{typ}, Grants: map[string][]string{typ: {"get"}}}}))
	set := func(m string) error {
		_, err := pool.Exec(ctx, `UPDATE kaname.role_rule_selectors SET verbs_by_type = $3::jsonb
		                           WHERE role_id = $1 AND rule_fp = $2`, string(role), "fp-c", m)
		return err
	}
	for name, bad := range map[string]string{
		"ключ вне типов строки": `{"probemod.nosuch": ["get"]}`,
		"пустой массив":         `{"` + typ + `": []}`,
		"не строка в массиве":   `{"` + typ + `": [1]}`,
		"значение — не массив":  `{"` + typ + `": "get"}`,
		"карта — не объект":     `["get"]`,
	} {
		err := set(bad)
		require.Errorf(t, err, "%s: схема приняла карту %s", name, bad)
		require.Equalf(t, "23514", svSQLState(err), "%s: отказ не проверкой (%v)", name, err)
	}
	require.NoError(t, set(`{"`+typ+`": ["get", "list"]}`), "БЛИЗНЕЦ: законная карта обязана записаться")
}

// Модельное имя типа контейнера выводит страж: прямая запись этой колонки его
// будит, и выведенное значение не подменяется.
func TestSelectorVerbs_ContainerModelNameIsDerivedOnItsOwnUpdate(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	_, err := applierOver(t, pool).Apply(ctx, probeManifest(probeResource("svbox", "get"), probeResource("svitem", "get")))
	require.NoError(t, err)
	role := catalogRole(t, ctx, pool, "svbox")
	writeNestedSelector(t, ctx, pool, role, "fp-box", []string{applierProbeModule + ".svitem"}, applierProbeModule+".svbox")
	var derived string
	require.NoError(t, pool.QueryRow(ctx, `SELECT container_object_type FROM kaname.role_rule_selectors
	                                        WHERE role_id = $1 AND rule_fp = 'fp-box'`, string(role)).Scan(&derived))
	require.NotEmpty(t, derived)

	_, err = pool.Exec(ctx, `UPDATE kaname.role_rule_selectors SET container_object_type = 'bogus_type'
	                          WHERE role_id = $1 AND rule_fp = 'fp-box'`, string(role))
	require.NoError(t, err)
	var after string
	require.NoError(t, pool.QueryRow(ctx, `SELECT container_object_type FROM kaname.role_rule_selectors
	                                        WHERE role_id = $1 AND rule_fp = 'fp-box'`, string(role)).Scan(&after))
	require.Equal(t, derived, after, "модельное имя контейнера подменено записью мимо стража")
}

// (л) Переходный страж: вставка строки селектора БЕЗ карты (писатель прежней
// версии службы) получает верхнюю границу — живые глаголы типа — и ставит роль
// в очередь пересчёта. Близнец — вставка с картой пишет её как есть и очереди
// не трогает.
func TestSelectorVerbs_LegacyInsertGetsTheUpperBoundAndTheQueue(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	_, err := applierOver(t, pool).Apply(ctx, probeManifest(probeResource("svold", "get", "update", "delete")))
	require.NoError(t, err)
	legacy := catalogRole(t, ctx, pool, "svolda")
	current := catalogRole(t, ctx, pool, "svoldb")
	typ := applierProbeModule + ".svold"

	_, err = pool.Exec(ctx, `INSERT INTO kaname.role_rule_selectors
	                           (role_id, rule_fp, arm, object_types, match_labels)
	                         VALUES ($1, 'fp-old', 'anchor', ARRAY[$2::text], '{}'::jsonb)`, string(legacy), typ)
	require.NoError(t, err, "вставка писателя прежней версии отвергнута")
	// Верхняя граница — ВСЕ живые глаголы типа в каталоге, а не выписанный
	// перечень: манифест-проба добавляет к объявленным и свои.
	var live []string
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT array_agg(DISTINCT lower(btrim(cv.verb)) ORDER BY lower(btrim(cv.verb)))
		  FROM kaname.catalog_resource cr
		  JOIN kaname.catalog_verb cv ON cv.module = cr.module AND cv.resource = cr.resource
		 WHERE cr.dotted = $1 AND cr.live AND cv.live`, typ).Scan(&live))
	require.Subset(t, live, []string{"delete", "get", "update"}, "КОНТРОЛЬ: каталог не знает объявленных глаголов")
	got, _ := svVerbs(t, ctx, pool, legacy, "fp-old")
	require.Equal(t, map[string][]string{typ: live}, got)
	require.True(t, svPending(t, ctx, pool, legacy), "роль с верхней границей не поставлена в очередь")

	require.NoError(t, svWrite(ctx, pool, current, []domain.RuleSelector{{RuleFP: "fp-cur", Arm: domain.ArmAnchor,
		ObjectTypes: []string{typ}, Grants: map[string][]string{typ: {"get"}}}}))
	got, _ = svVerbs(t, ctx, pool, current, "fp-cur")
	require.Equal(t, map[string][]string{typ: {"get"}}, got)
	require.False(t, svPending(t, ctx, pool, current), "БЛИЗНЕЦ: вычисленная карта роль в очередь не ставит")
}

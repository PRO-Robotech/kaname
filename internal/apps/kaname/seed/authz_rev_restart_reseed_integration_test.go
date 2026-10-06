// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed_test

// authz_rev_restart_reseed_integration_test.go — досев старта службы доступа не
// двигает версию прав строк с прежним содержимым (приёмка NTF-3, kacho#2918,
// Р30 «Колонка версии прав», редакция 39; сценарий NTF3-183 в части версий;
// решения Д133, Д134 B1; полоса K1).
//
// # Предмет
//
// Перезапуск либо выкатка службы доступа исполняет досев системных ролей:
// `BackfillOwnerBindings` → `syncAllSystemRoleSelectorsTx` и
// `ReseedSystemRoleVerbs` → `RolesW().ReplaceRoleVerbs`. Ограда вопроса об
// аудитории отбрасывает каждую строку прав, изменённую не раньше токена `R_E`;
// досев, переписывающий строку тем же содержимым, «изменял» бы её и сужал
// аудиторию всех ожидающих событий на каждом старте. Поэтому:
//
//   - второй досев тем же посевом не меняет `authz_rev` ни одной строки путевых
//     таблиц, которые он трогает;
//   - замена глаголов роли разностная: пара, которая есть и в посеве, и в
//     таблице, не удаляется и не вставляется заново — её физическая строка та
//     же (`xmin` прежний);
//   - близнец по одному факту: у системной роли посевом снят глагол — снята
//     РОВНО эта пара, прочие пары роли и прочих ролей не тронуты.
//
// # Вопрос об аудитории здесь НЕ задаётся
//
// Он — полоса вопроса с оградой; здесь утверждается то, на чём он стоит:
// версия строки не движется без изменения права.
//
// # Порядок внутри пробы несущий
//
// Положительный контроль фикстуры (строки есть, досев прошёл, близнец сменил
// посев) — до вопроса о версии.

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// restartRoleID — системная роль пробы с ДВУМЯ глаголами на одном типе: у
// близнеца снимается один, и второй обязан остаться той же строкой.
const restartRoleID = "rol-arv-restart"

// restartRulesBoth / restartRulesOne — посев «до» и посев близнеца. Отличаются
// РОВНО одним фактом: глагол `get` снят.
const (
	restartRulesBoth = `[{"module":"iam","resources":["user"],"verbs":["get","list"]}]`
	restartRulesOne  = `[{"module":"iam","resources":["user"],"verbs":["list"]}]`
)

// fullBoot — досев старта целиком, в том порядке, в каком его исполняет корень:
// владельческие выдачи с селекторами системных ролей одной транзакцией, затем
// проекция глаголов — транзакцией на роль.
func fullBoot(ctx context.Context, pool *pgxpool.Pool) error {
	return bootBindingsAndVerbs(ctx, pool)
}

// revisionedKey — ключ строки права каждой таблицы, которую трогает досев
// старта. Значимое содержимое строки входит в ключ, поэтому одинаковый ключ
// после досева — та же строка права.
var revisionedKey = []struct{ table, key string }{
	{"kaname.access_bindings", "id"},
	{"kaname.access_binding_subjects", "binding_id || '|' || subject_type || '|' || subject_id"},
	{"kaname.role_verb", "role_id || '|' || object_type || '|' || verb"},
	{"kaname.role_rule_selectors", "role_id || '|' || rule_fp"},
	{"kaname.group_members", "group_id || '|' || member_type || '|' || member_id"},
	{"kaname.relation_fact", "object_type || '|' || object_id || '|' || relation || '|' || subject || '|' || condition_name"},
	{"kaname.accounts", "id"},
	{"kaname.projects", "id"},
	{"kaname.users", "id"},
	{"kaname.service_accounts", "id"},
	{"kaname.groups", "id"},
	{"kaname.roles", "id"},
}

// keysOf — множество ключей строк таблицы (без версии): положительный контроль
// и сравнение «та же строка права».
func keysOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table, key string) []string {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT (`+key+`)::text FROM `+table)
	require.NoErrorf(t, err, "фикстура: ключи %s не читаются", table)
	defer rows.Close()
	var out []string
	for rows.Next() {
		var k string
		require.NoError(t, rows.Scan(&k))
		out = append(out, k)
	}
	require.NoError(t, rows.Err())
	sort.Strings(out)
	return out
}

// versionsOf — ключ строки → её версия прав. Отказ чтения — красный с именем
// таблицы: колонки нет — это и есть отсутствующая возможность.
func versionsOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, table, key string) map[string]string {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT (`+key+`)::text, authz_rev::text FROM `+table)
	require.NoErrorf(t, err, "версия прав строк %s не читается (Р30 «Колонка версии прав»)", table)
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k string
		var v *string
		require.NoError(t, rows.Scan(&k, &v))
		require.NotNilf(t, v, "%s: у строки %s версия прав пуста", table, k)
		out[k] = *v
	}
	require.NoError(t, rows.Err())
	return out
}

// physicalRowsOfRole — пара роли → `xmin` её физической строки. Удаление и
// повторная вставка той же пары дают новый `xmin`; разностная замена — прежний.
func physicalRowsOfRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID string) map[string]string {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT object_type || '|' || verb, xmin::text FROM kaname.role_verb WHERE role_id = $1`, roleID)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]string{}
	for rows.Next() {
		var k, x string
		require.NoError(t, rows.Scan(&k, &x))
		out[k] = x
	}
	require.NoError(t, rows.Err())
	return out
}

// seedRestartWorld — системная роль с двумя глаголами и аккаунт без
// владельческой выдачи (её заведёт досев): досев старта трогает привязки,
// субъекты привязок, факты иерархии, селекторы и проекцию глаголов.
func seedRestartWorld(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	pairs := catalogfixture.Facts().RoleVerbsFromSelectors(mustRules(t, restartRulesBoth).MaterializingSelectors())
	require.Lenf(t, pairs, 2, "фикстура: посев роли пробы раскрывается в %d пар, а нужно две "+
		"(иначе снимать у близнеца нечего): %v", len(pairs), pairs)
	seedProbeSystemRole(t, ctx, pool, restartRoleID, "probe.arv.restart", restartRulesBoth)
	seedProbeAccountWithoutOwnerBinding(t, ctx, pool, "arvrst")
}

func mustRules(t *testing.T, raw string) domain.Rules {
	t.Helper()
	r, err := domain.DecodeRules([]byte(raw))
	require.NoError(t, err, "фикстура: правила посева не разбираются")
	return r
}

// requireBootTouchedEveryTable — положительный контроль: после досева в
// таблицах, которые он пишет, строки есть. Без него «версии не сдвинулись»
// читалось бы и на досеве, не пишущем ничего.
func requireBootTouchedEveryTable(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	for _, table := range []string{"kaname.access_bindings", "kaname.access_binding_subjects",
		"kaname.role_verb", "kaname.role_rule_selectors"} {
		var n int
		require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM `+table).Scan(&n))
		require.Positivef(t, n, "фикстура: после досева в %s строк нет — сравнение версий вакуумно", table)
	}
	require.Len(t, physicalRowsOfRole(t, ctx, pool, restartRoleID), 2,
		"фикстура: у роли пробы после досева не две пары")
}

// TestNTF3183_RestartReseedRewritesNoRoleVerbPair — второй досев тем же посевом
// оставляет КАЖДУЮ пару проекции глаголов той же физической строкой: замена
// разностная, а не «снять всё — положить заново» (Р30, ред. 39).
func TestNTF3183_RestartReseedRewritesNoRoleVerbPair(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)
	seedRestartWorld(t, ctx, pool)
	require.NoError(t, fullBoot(ctx, pool), "фикстура: первый досев старта отказал")
	requireBootTouchedEveryTable(t, ctx, pool)
	before := physicalRowsOfRole(t, ctx, pool, restartRoleID)
	projBefore := wholeProjection(t, ctx, pool)

	require.NoError(t, fullBoot(ctx, pool), "фикстура: второй досев старта отказал")
	require.Equal(t, projBefore, wholeProjection(t, ctx, pool), "фикстура: второй досев тем же посевом сменил состав проекции")

	after := physicalRowsOfRole(t, ctx, pool, restartRoleID)
	for pair, x := range before {
		require.Equalf(t, x, after[pair], "пара %s роли %s удалена и вставлена заново досевом с прежним "+
			"содержимым (xmin %s → %s): замена глаголов роли не разностная — перезапуск службы доступа "+
			"двигал бы версию прав строки и сужал аудиторию (NTF3-183)", pair, restartRoleID, x, after[pair])
	}
}

// TestNTF3183_RestartReseedMovesNoRightsVersion — второй досев тем же посевом не
// меняет `authz_rev` ни одной строки путевых таблиц (NTF3-183: перезапуск
// между `R1` и вопросом аудиторию не сужает).
func TestNTF3183_RestartReseedMovesNoRightsVersion(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)
	seedRestartWorld(t, ctx, pool)
	require.NoError(t, fullBoot(ctx, pool), "фикстура: первый досев старта отказал")
	requireBootTouchedEveryTable(t, ctx, pool)

	keysBefore := map[string][]string{}
	for _, rk := range revisionedKey {
		keysBefore[rk.table] = keysOf(t, ctx, pool, rk.table, rk.key)
	}
	versionsBefore := map[string]map[string]string{}
	for _, rk := range revisionedKey {
		versionsBefore[rk.table] = versionsOf(t, ctx, pool, rk.table, rk.key)
	}

	require.NoError(t, fullBoot(ctx, pool), "фикстура: второй досев старта отказал")
	for _, rk := range revisionedKey {
		require.Equalf(t, keysBefore[rk.table], keysOf(t, ctx, pool, rk.table, rk.key),
			"фикстура: второй досев тем же посевом сменил состав строк %s", rk.table)
	}

	var moved []string
	for _, rk := range revisionedKey {
		after := versionsOf(t, ctx, pool, rk.table, rk.key)
		for k, v := range versionsBefore[rk.table] {
			if after[k] != v {
				moved = append(moved, fmt.Sprintf("%s[%s]: %s → %s", rk.table, k, v, after[k]))
			}
		}
	}
	sort.Strings(moved)
	require.Emptyf(t, moved, "досев старта с прежним содержимым сдвинул версию прав %d строк — "+
		"перезапуск службы доступа сузил бы аудиторию ожидающих событий (NTF3-183):\n  %s",
		len(moved), strings.Join(moved, "\n  "))
}

// TestNTF3183_Twin_VerbDroppedBySeedMovesOnlyThatPair — близнец NTF3-183 по
// одному факту: посевом у системной роли снят глагол `get`. Снята ровно пара
// `get`; оставшаяся пара — та же физическая строка с прежней версией; версии
// строк прочих ролей не сдвинулись.
func TestNTF3183_Twin_VerbDroppedBySeedMovesOnlyThatPair(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)
	seedRestartWorld(t, ctx, pool)
	require.NoError(t, fullBoot(ctx, pool), "фикстура: первый досев старта отказал")
	requireBootTouchedEveryTable(t, ctx, pool)

	dropped := catalogfixture.Facts().RoleVerbsFromSelectors(mustRules(t, restartRulesBoth).MaterializingSelectors())
	kept := catalogfixture.Facts().RoleVerbsFromSelectors(mustRules(t, restartRulesOne).MaterializingSelectors())
	require.Len(t, kept, 1, "фикстура: посев близнеца раскрывается не в одну пару")
	keptKey := kept[0].ObjectType + "|" + kept[0].Verb
	var droppedKey string
	for _, p := range dropped {
		if k := p.ObjectType + "|" + p.Verb; k != keptKey {
			droppedKey = k
		}
	}
	require.NotEmpty(t, droppedKey, "фикстура: снимаемой пары не нашлось")

	physBefore := physicalRowsOfRole(t, ctx, pool, restartRoleID)
	require.Contains(t, physBefore, droppedKey, "фикстура: снимаемой пары нет до посева близнеца")
	verbVersionsBefore := versionsOf(t, ctx, pool, "kaname.role_verb", "role_id || '|' || object_type || '|' || verb")

	// Посев близнеца: правила роли — тем путём, каким их кладёт миграция посева.
	_, err := pool.Exec(ctx, `UPDATE kaname.roles SET rules = $2::jsonb WHERE id = $1`, restartRoleID, restartRulesOne)
	require.NoError(t, err, "фикстура: посев близнеца не записан")
	require.NoError(t, fullBoot(ctx, pool), "фикстура: досев близнеца отказал")

	physAfter := physicalRowsOfRole(t, ctx, pool, restartRoleID)
	require.NotContainsf(t, physAfter, droppedKey, "снятая посевом пара %s осталась в проекции", droppedKey)
	require.Equalf(t, physBefore[keptKey], physAfter[keptKey],
		"пара %s, не снятая посевом, удалена и вставлена заново (xmin %s → %s): замена не разностная",
		keptKey, physBefore[keptKey], physAfter[keptKey])

	verbVersionsAfter := versionsOf(t, ctx, pool, "kaname.role_verb", "role_id || '|' || object_type || '|' || verb")
	var moved []string
	for k, v := range verbVersionsBefore {
		if strings.HasSuffix(k, "|"+droppedKey) && strings.HasPrefix(k, restartRoleID+"|") {
			continue
		}
		if verbVersionsAfter[k] != v {
			moved = append(moved, fmt.Sprintf("%s: %s → %s", k, v, verbVersionsAfter[k]))
		}
	}
	sort.Strings(moved)
	require.Emptyf(t, moved, "снятие одной пары посевом сдвинуло версию %d несвязанных пар:\n  %s",
		len(moved), strings.Join(moved, "\n  "))
}

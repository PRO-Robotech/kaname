// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// verifies https://github.com/PRO-Robotech/kaname/issues/983
// Консервативный гейт установленной схемы для проверенного графа вызовов триггеров.
// Это детектор изменений, не общий парсер SQL и не песочница DDL администратора.

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/authoritycallbacks"
	"github.com/stretchr/testify/require"
)

func TestPermanentProjectCommand_InstalledTriggerGraphIsClosed(t *testing.T) {
	w := newPPWorld(t)
	authoritycallbacks.AssertReviewedGraph(t, w.ctx, w.pool)
	type fn struct{ name, body, language string }
	funcs := map[uint32]fn{}
	byName := map[string][]uint32{}
	rows, err := w.pool.Query(w.ctx, `SELECT p.oid,p.proname,p.prosrc,l.lanname FROM pg_proc p
        JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
        WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND p.prokind='f'`)
	require.NoError(t, err)
	for rows.Next() {
		var oid uint32
		var f fn
		require.NoError(t, rows.Scan(&oid, &f.name, &f.body, &f.language))
		funcs[oid] = f
		byName[f.name] = append(byName[f.name], oid)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	var roots []uint32
	rows, err = w.pool.Query(w.ctx, `SELECT DISTINCT tgfoid FROM pg_trigger WHERE NOT tgisinternal`)
	require.NoError(t, err)
	for rows.Next() {
		var oid uint32
		require.NoError(t, rows.Scan(&oid))
		roots = append(roots, oid)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	stripComments := regexp.MustCompile(`(?s)/\*.*?\*/|(?m)--[^\n]*`)
	calls := regexp.MustCompile(`(?i)\b([a-z_][a-z0-9_]*)\s*\(`)
	writes := regexp.MustCompile(`(?i)\b(?:insert\s+into|update|delete\s+from|merge\s+into)\s+(?:only\s+)?(?:kaname\.)?resource_(?:mirror|parent_edge)\b`)
	seen := map[uint32]bool{}
	for len(roots) > 0 {
		oid := roots[0]
		roots = roots[1:]
		if seen[oid] {
			continue
		}
		seen[oid] = true
		f, ok := funcs[oid]
		require.True(t, ok, "unreviewed trigger function oid %d", oid)
		body := stripComments.ReplaceAllString(f.body, "")
		require.Contains(t, []string{"plpgsql", "sql"}, f.language, "unreviewed callback language: "+f.name)
		require.NotEqual(t, "rename_cluster_anchor", f.name, "dynamic rename must never become trigger-reachable")
		if writes.MatchString(body) {
			require.Equal(t, "resource_registration_command_apply", f.name, "unchecked incoming physical writer")
		}
		unreviewed, lexicalErr := ppTriggerHasUnreviewedExecute(f.body)
		require.NoError(t, lexicalErr, "неразобранное тело callback "+f.name)
		require.False(t, unreviewed, "unreviewed dynamic callback in "+f.name)
		for _, call := range calls.FindAllStringSubmatch(body, -1) {
			roots = append(roots, byName[strings.ToLower(call[1])]...)
		}
	}
	var bad int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM pg_constraint WHERE contype='f'
        AND conrelid IN ('kaname.resource_mirror'::regclass,'kaname.resource_parent_edge'::regclass,'kaname.registration_catalog_fence'::regclass)`).Scan(&bad))
	require.Zero(t, bad, "incoming FK actions require a new graph proof")
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM pg_rewrite WHERE ev_class IN
        ('kaname.resource_mirror'::regclass,'kaname.resource_parent_edge'::regclass,'kaname.catalog_resource'::regclass,'kaname.registration_catalog_fence'::regclass)`).Scan(&bad))
	require.Zero(t, bad, "physical rewrite callbacks are not part of the approved graph")
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM pg_class WHERE oid IN
        ('kaname.resource_mirror'::regclass,'kaname.resource_parent_edge'::regclass,'kaname.resource_registration_command'::regclass,'kaname.catalog_resource'::regclass,'kaname.registration_catalog_fence'::regclass)
        AND (relrowsecurity OR relforcerowsecurity)`).Scan(&bad))
	require.Zero(t, bad, "RLS callbacks require a new graph proof")
	// Остаток графа — ровно 16 исторических AFTER STATEMENT epoch callbacks.
	// Закреплены функция, событие, режим и transition tables; новое имя,
	// BEFORE/ROW, условие, аргументы или иной transition alias не допускаются.
	// Тела и private callees уже проверены AssertReviewedGraph выше.
	var epochCallbacks []string
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT array_agg(
 c.relname||'|'||t.tgname||'|'||n.nspname||'.'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||')'||
 '|'||t.tgtype::text||'|'||t.tgenabled::text||'|'||coalesce(t.tgoldtable::text,'')||'|'||coalesce(t.tgnewtable::text,'')||
 '|'||t.tgnargs::text||'|'||(t.tgqual IS NOT NULL)::text||'|'||t.tgdeferrable::text||'|'||t.tginitdeferred::text
 ORDER BY c.relname COLLATE "C",t.tgname COLLATE "C")
 FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
 JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_class c ON c.oid=t.tgrelid
        WHERE t.tgrelid IN ('kaname.resource_mirror'::regclass,'kaname.resource_parent_edge'::regclass)
        AND NOT t.tgisinternal AND NOT (
 p.proname IN ('resource_mirror_keeps_the_bound_project','resource_parent_edge_keeps_the_bound_project','resource_registration_locks_writers') OR
 (t.tgname='authority_protocol_row' AND t.tgfoid='kaname.authority_protocol_row_guard()'::regprocedure AND t.tgtype=31 AND t.tgenabled='O') OR
 (t.tgname='authority_protocol_statement' AND t.tgfoid='kaname.authority_protocol_statement_guard()'::regprocedure AND t.tgtype=62 AND t.tgenabled='O') OR
 (t.tgname='authority_resource_effect_applied' AND t.tgfoid='kaname._authority_resource_effect_applied_v2()'::regprocedure AND t.tgtype=29 AND t.tgenabled='O'))`).Scan(&epochCallbacks))
	require.Equal(t, []string{
		"resource_mirror|binding_epoch_delete|kaname.authority_binding_epoch_changed()|8|O|old_epoch_rows||0|false|false|false",
		"resource_mirror|binding_epoch_insert|kaname.authority_binding_epoch_changed()|4|O||new_epoch_rows|0|false|false|false",
		"resource_mirror|binding_epoch_truncate|kaname.authority_binding_epoch_changed()|32|O|||0|false|false|false",
		"resource_mirror|binding_epoch_update|kaname.authority_binding_epoch_changed()|16|O|old_epoch_rows|new_epoch_rows|0|false|false|false",
		"resource_mirror|policy_epoch_delete|kaname.authority_policy_changed()|8|O|old_policy_rows||0|false|false|false",
		"resource_mirror|policy_epoch_insert|kaname.authority_policy_changed()|4|O||new_policy_rows|0|false|false|false",
		"resource_mirror|policy_epoch_truncate|kaname.authority_policy_changed()|32|O|||0|false|false|false",
		"resource_mirror|policy_epoch_update|kaname.authority_policy_changed()|16|O|old_policy_rows|new_policy_rows|0|false|false|false",
		"resource_parent_edge|binding_epoch_delete|kaname.authority_binding_epoch_changed()|8|O|old_epoch_rows||0|false|false|false",
		"resource_parent_edge|binding_epoch_insert|kaname.authority_binding_epoch_changed()|4|O||new_epoch_rows|0|false|false|false",
		"resource_parent_edge|binding_epoch_truncate|kaname.authority_binding_epoch_changed()|32|O|||0|false|false|false",
		"resource_parent_edge|binding_epoch_update|kaname.authority_binding_epoch_changed()|16|O|old_epoch_rows|new_epoch_rows|0|false|false|false",
		"resource_parent_edge|policy_epoch_delete|kaname.authority_policy_changed()|8|O|old_policy_rows||0|false|false|false",
		"resource_parent_edge|policy_epoch_insert|kaname.authority_policy_changed()|4|O||new_policy_rows|0|false|false|false",
		"resource_parent_edge|policy_epoch_truncate|kaname.authority_policy_changed()|32|O|||0|false|false|false",
		"resource_parent_edge|policy_epoch_update|kaname.authority_policy_changed()|16|O|old_policy_rows|new_policy_rows|0|false|false|false",
	}, epochCallbacks, "epoch callbacks должны точно совпадать с проверенным AFTER STATEMENT графом")
	// AFTER ROW обязан подтвердить каждый реально применённый эффект. Его
	// точное тело закреплено AssertReviewedGraph; BEFORE попытка не заменяет
	// required-consumption, а legacy без manifest остаётся no-op.
	var applied int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM pg_trigger t
 WHERE t.tgrelid IN ('kaname.resource_mirror'::regclass,'kaname.resource_parent_edge'::regclass)
 AND NOT t.tgisinternal AND t.tgname='authority_resource_effect_applied'
 AND t.tgfoid='kaname._authority_resource_effect_applied_v2()'::regprocedure
 AND t.tgtype=29 AND t.tgenabled='O'`).Scan(&applied))
	require.Equal(t, 2, applied, "обязательный AFTER-consumption установлен на обеих проекциях")
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM pg_constraint WHERE conrelid IN
        ('kaname.resource_mirror'::regclass,'kaname.resource_parent_edge'::regclass)
        AND pg_get_constraintdef(oid) LIKE '%kaname.%'`).Scan(&bad))
	require.Zero(t, bad, "physical checks must remain built-in expressions, without custom callbacks")
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM pg_proc WHERE pronamespace='kaname'::regnamespace
        AND proname IN ('registration_catalog_fence_mint','registration_catalog_fence_ensure','registration_catalog_fence_forget','registration_catalog_fence_refuses_truncate')
        AND (prosecdef OR provolatile<>'v')`).Scan(&bad))
	require.Zero(t, bad, "witness cannot introduce a definer privilege or cached snapshot")
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM pg_trigger t JOIN pg_proc p ON p.oid=t.tgfoid
        WHERE t.tgrelid='kaname.registration_catalog_fence'::regclass AND NOT t.tgisinternal
        AND p.proname NOT IN ('registration_catalog_fence_mint','registration_catalog_fence_refuses_truncate','resource_registration_locks_writers')`).Scan(&bad))
	require.Zero(t, bad, "witness mint graph has no unreviewed callbacks")
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM pg_constraint WHERE contype='c'
        AND conrelid IN ('kaname.catalog_resource'::regclass,'kaname.registration_catalog_fence'::regclass)
        AND pg_get_constraintdef(oid) LIKE '%kaname.%'`).Scan(&bad))
	require.Zero(t, bad, "catalog/witness checks cannot hide custom callbacks")
}

// ppTriggerExecuteTokens распознаёт только незаключённое в кавычки слово EXECUTE.
// Смещения относятся к исходному телу; комментарии заменяются пробелами, чтобы
// две прежние одобренные формы проверялись с настоящего начала оператора.
// Незакрытая строка либо комментарий — ошибка, а не доказательство отсутствия SQL.
func ppTriggerExecuteTokens(body string) (string, []int, error) {
	clean := []byte(body)
	var executes []int
	ident := func(c byte) bool {
		return c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '_' || c == '$' || c >= 0x80
	}
	blank := func(start, end int) {
		for j := start; j < end; j++ {
			if clean[j] != '\n' && clean[j] != '\r' {
				clean[j] = ' '
			}
		}
	}
	for i := 0; i < len(body); {
		start := i
		switch {
		case strings.HasPrefix(body[i:], "--"):
			for i < len(body) && body[i] != '\n' && body[i] != '\r' {
				i++
			}
			blank(start, i)
		case strings.HasPrefix(body[i:], "/*"):
			i += 2
			depth := 1
			for i < len(body) && depth > 0 {
				switch {
				case strings.HasPrefix(body[i:], "/*"):
					depth++
					i += 2
				case strings.HasPrefix(body[i:], "*/"):
					depth--
					i += 2
				default:
					i++
				}
			}
			if depth != 0 {
				return "", nil, fmt.Errorf("незакрытый SQL-комментарий на позиции %d", start)
			}
			blank(start, i)
		case body[i] == '\'' || body[i] == '"':
			quote := body[i]
			escaped := quote == '\'' && i > 0 && (body[i-1] == 'E' || body[i-1] == 'e') && (i < 2 || !ident(body[i-2]))
			i++
			closed := false
			for i < len(body) {
				if escaped && body[i] == '\\' {
					i += 2
					continue
				}
				if body[i] == quote {
					i++
					if i < len(body) && body[i] == quote {
						i++
						continue
					}
					closed = true
					break
				}
				i++
			}
			if !closed {
				return "", nil, fmt.Errorf("незакрытая SQL-кавычка на позиции %d", start)
			}
		case body[i] == '$':
			j := i + 1
			for j < len(body) && (body[j] == '_' || body[j] >= 'a' && body[j] <= 'z' || body[j] >= 'A' && body[j] <= 'Z' || body[j] >= 0x80 || j > i+1 && body[j] >= '0' && body[j] <= '9') {
				j++
			}
			if j < len(body) && body[j] == '$' {
				tag := body[i : j+1]
				end := strings.Index(body[j+1:], tag)
				if end < 0 {
					return "", nil, fmt.Errorf("незакрытая dollar-строка на позиции %d", start)
				}
				i = j + 1 + end + len(tag)
			} else {
				i++
			}
		case ident(body[i]):
			for i < len(body) && ident(body[i]) {
				i++
			}
			if strings.EqualFold(body[start:i], "execute") {
				executes = append(executes, start)
			}
		default:
			if strings.HasPrefix(body[i:], "*/") || body[i] == 0 {
				return "", nil, fmt.Errorf("неожиданный SQL-токен на позиции %d", start)
			}
			i++
		}
	}
	return string(clean), executes, nil
}

// Одобрение применяется только с начала настоящей executable-лексемы, а не
// с похожего текста внутри литерала. Неизвестный EXECUTE по-прежнему запрещён.
func ppTriggerHasUnreviewedExecute(body string) (bool, error) {
	// Единственный проверенный динамический SQL, достижимый из существующих триггеров: чтения
	// фиксированных отношений из аргументов триггера. Каждый новый EXECUTE требует явного ревью.
	dynamicReads := regexp.MustCompile(`(?is)^EXECUTE\s+format\(\s*'(?:SELECT to_jsonb\(t\) FROM kaname\.%I t WHERE t\.id = \$1|SELECT count\(\*\) FROM %I\.%I WHERE %I = \$1 AND id <> \$2)'[^;]*;`)
	dynamicBody, executes, err := ppTriggerExecuteTokens(body)
	if err != nil {
		return true, err
	}
	for _, at := range executes {
		if !dynamicReads.MatchString(dynamicBody[at:]) {
			return true, nil
		}
	}
	return false, nil
}

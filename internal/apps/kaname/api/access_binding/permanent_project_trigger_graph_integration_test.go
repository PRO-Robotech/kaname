// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// verifies https://github.com/PRO-Robotech/kaname/issues/983
// Консервативный гейт установленной схемы для проверенного графа вызовов триггеров.
// Это детектор изменений, не общий парсер SQL и не песочница DDL администратора.

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/authoritycallbacks"
	"github.com/stretchr/testify/require"
)

func TestPermanentProjectCommand_InstalledTriggerGraphIsClosed(t *testing.T) {
	w := newPPWorld(t)
	authoritycallbacks.AssertReviewedGraph(t, w.ctx, w.pool)
	funcs := map[uint32]ppTriggerFunction{}
	rows, err := w.pool.Query(w.ctx, `SELECT p.oid,p.proname,p.prosrc,l.lanname,n.nspname||'.'||p.proname||'('||pg_get_function_identity_arguments(p.oid)||')' FROM pg_proc p
        JOIN pg_namespace n ON n.oid=p.pronamespace JOIN pg_language l ON l.oid=p.prolang
        WHERE n.nspname NOT LIKE 'pg_%' AND n.nspname<>'information_schema' AND p.prokind='f'`)
	require.NoError(t, err)
	for rows.Next() {
		var oid uint32
		var f ppTriggerFunction
		require.NoError(t, rows.Scan(&oid, &f.name, &f.body, &f.language, &f.signature))
		funcs[oid] = f
	}
	require.NoError(t, rows.Err())
	rows.Close()
	var roots []ppTriggerRoot
	rows, err = w.pool.Query(w.ctx, `SELECT t.tgfoid,n.nspname||'.'||c.relname||'/'||t.tgname
 FROM pg_trigger t JOIN pg_class c ON c.oid=t.tgrelid JOIN pg_namespace n ON n.oid=c.relnamespace
 WHERE NOT t.tgisinternal`)
	require.NoError(t, err)
	for rows.Next() {
		var root ppTriggerRoot
		require.NoError(t, rows.Scan(&root.oid, &root.label))
		roots = append(roots, root)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	// Сначала собираем все отказы достижимого графа; первый EXECUTE не обрывает
	// перепись остальных функций и последующие физические schema guards.
	if census := ppTriggerGraphCensus(funcs, roots); len(census) != 0 {
		t.Errorf("непроверенный callback graph:\n%s", strings.Join(census, "\n"))
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

type ppTriggerFunction struct{ name, body, language, signature string }
type ppTriggerRoot struct {
	oid   uint32
	label string
}
type ppTriggerCall struct {
	name   string
	offset int
}

// Каждая функция проверяется один раз. Отсортированные roots и callees дают
// детерминированный первый путь; все EXECUTE offsets этой функции остаются в census.
// Разрешение имени консервативно: сохраняем все overloads/схемы с этим именем.
func ppTriggerGraphCensus(funcs map[uint32]ppTriggerFunction, roots []ppTriggerRoot) []string {
	byName := map[string][]uint32{}
	for oid, f := range funcs {
		byName[f.name] = append(byName[f.name], oid)
	}
	for name := range byName {
		sort.Slice(byName[name], func(i, j int) bool {
			a, b := byName[name][i], byName[name][j]
			if funcs[a].signature != funcs[b].signature {
				return funcs[a].signature < funcs[b].signature
			}
			return a < b
		})
	}
	roots = append([]ppTriggerRoot(nil), roots...)
	sort.Slice(roots, func(i, j int) bool {
		if roots[i].label != roots[j].label {
			return roots[i].label < roots[j].label
		}
		return roots[i].oid < roots[j].oid
	})
	type visit struct {
		oid        uint32
		root, path string
	}
	var queue []visit
	for _, root := range roots {
		queue = append(queue, visit{root.oid, root.label, funcs[root.oid].signature})
	}
	stripComments := regexp.MustCompile(`(?s)/\*.*?\*/|(?m)--[^\n]*`)
	writes := regexp.MustCompile(`(?i)\b(?:insert\s+into|update|delete\s+from|merge\s+into)\s+(?:only\s+)?(?:kaname\.)?resource_(?:mirror|parent_edge)\b`)
	seen := map[uint32]bool{}
	var census []string
	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		if seen[v.oid] {
			continue
		}
		seen[v.oid] = true
		f, ok := funcs[v.oid]
		reject := func(offset int, reason string) {
			census = append(census, fmt.Sprintf("root=%q path=%q function=%q offset=%d: %s", v.root, v.path, f.signature, offset, reason))
		}
		if !ok {
			reject(0, fmt.Sprintf("unreviewed trigger function oid %d", v.oid))
			continue
		}
		if f.language != "plpgsql" && f.language != "sql" {
			reject(0, "unreviewed callback language: "+f.language)
			continue
		}
		if f.name == "rename_cluster_anchor" {
			reject(0, "dynamic rename must never become trigger-reachable")
		}
		if writes.MatchString(stripComments.ReplaceAllString(f.body, "")) && f.name != "resource_registration_command_apply" {
			reject(0, "unchecked incoming physical writer")
		}
		clean, executes, calls, err := ppTriggerSQLTokens(f.body)
		if err != nil {
			reject(0, "неразобранное тело callback: "+err.Error())
		}
		for _, at := range ppTriggerUnreviewedExecuteOffsets(clean, executes) {
			reject(at, "unreviewed EXECUTE")
		}
		for _, call := range calls {
			for _, oid := range byName[call.name] {
				queue = append(queue, visit{oid, v.root, fmt.Sprintf("%s -> %s@%d", v.path, funcs[oid].signature, call.offset)})
			}
		}
	}
	sort.Strings(census)
	return census
}

// Один проход различает executable tokens, литералы и quoted identifiers.
// dynamic сохраняет строки только для прежней проверки EXECUTE, не для calls.
// Смещения относятся к исходному телу; комментарии заменяются пробелами, чтобы
// прежние одобренные формы проверялись с настоящего начала оператора.
// Незакрытая строка либо комментарий — ошибка, а не доказательство отсутствия SQL.
func ppTriggerSQLTokens(body string) (string, []int, []ppTriggerCall, error) {
	if at := strings.IndexByte(body, 0); at >= 0 {
		return body, nil, nil, fmt.Errorf("нулевой SQL-байт на позиции %d", at)
	}
	clean := []byte(body)
	var executes []int
	var calls []ppTriggerCall
	var previous ppTriggerCall
	var parens []int
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
				return string(clean), executes, calls, fmt.Errorf("незакрытый SQL-комментарий на позиции %d", start)
			}
			blank(start, i)
		case body[i] == '\'' || body[i] == '"':
			if start >= 2 && strings.EqualFold(body[start-2:start], "u&") && (start == 2 || !ident(body[start-3])) {
				return string(clean), executes, calls, fmt.Errorf("неподдерживаемая Unicode SQL-кавычка на позиции %d", start-2)
			}
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
				return string(clean), executes, calls, fmt.Errorf("незакрытая SQL-кавычка на позиции %d", start)
			}
			previous = ppTriggerCall{}
			if quote == '"' {
				if i == start+2 {
					return string(clean), executes, calls, fmt.Errorf("пустой SQL-идентификатор на позиции %d", start)
				}
				previous = ppTriggerCall{name: strings.ReplaceAll(body[start+1:i-1], `""`, `"`), offset: start}
			}
		case body[i] == '$':
			previous = ppTriggerCall{}
			j := i + 1
			for j < len(body) && (body[j] == '_' || body[j] >= 'a' && body[j] <= 'z' || body[j] >= 'A' && body[j] <= 'Z' || body[j] >= 0x80 || j > i+1 && body[j] >= '0' && body[j] <= '9') {
				j++
			}
			if j < len(body) && body[j] == '$' {
				tag := body[i : j+1]
				end := strings.Index(body[j+1:], tag)
				if end < 0 {
					return string(clean), executes, calls, fmt.Errorf("незакрытая dollar-строка на позиции %d", start)
				}
				i = j + 1 + end + len(tag)
			} else {
				i++
			}
		case ident(body[i]):
			for i < len(body) && ident(body[i]) {
				i++
			}
			// PostgreSQL складывает ASCII-регистр unquoted identifiers; UTF-8
			// байты сохраняются, quoted identifiers выше не складываются вообще.
			name := []byte(body[start:i])
			for j, c := range name {
				if c >= 'A' && c <= 'Z' {
					name[j] = c + ('a' - 'A')
				}
			}
			previous = ppTriggerCall{name: string(name), offset: start}
			if strings.EqualFold(body[start:i], "execute") {
				executes = append(executes, start)
			}
		case body[i] == ' ' || body[i] == '\t' || body[i] == '\n' || body[i] == '\r' || body[i] == '\f':
			i++
		default:
			if body[i] == '(' {
				if previous.name != "" {
					calls = append(calls, previous)
				}
				parens = append(parens, i)
			} else if body[i] == ')' {
				if len(parens) == 0 {
					return string(clean), executes, calls, fmt.Errorf("лишняя SQL-скобка на позиции %d", start)
				}
				parens = parens[:len(parens)-1]
			}
			previous = ppTriggerCall{}
			if strings.HasPrefix(body[i:], "*/") || body[i] == 0 {
				return string(clean), executes, calls, fmt.Errorf("неожиданный SQL-токен на позиции %d", start)
			}
			i++
		}
	}
	if len(parens) != 0 {
		return string(clean), executes, calls, fmt.Errorf("незакрытая SQL-скобка на позиции %d", parens[len(parens)-1])
	}
	return string(clean), executes, calls, nil
}

func ppTriggerExecuteTokens(body string) (string, []int, error) {
	clean, executes, _, err := ppTriggerSQLTokens(body)
	return clean, executes, err
}

// Одобрение применяется только с начала настоящей executable-лексемы, а не
// с похожего текста внутри литерала. Неизвестный EXECUTE по-прежнему запрещён.
func ppTriggerUnreviewedExecuteOffsets(dynamicBody string, executes []int) []int {
	// Прежние проверенные чтения фиксированных отношений из аргументов
	// триггера сохраняются без расширения. Каждый новый EXECUTE требует ревью.
	dynamicReads := regexp.MustCompile(`(?is)^EXECUTE\s+format\(\s*'(?:SELECT to_jsonb\(t\) FROM kaname\.%I t WHERE t\.id = \$1|SELECT count\(\*\) FROM %I\.%I WHERE %I = \$1 AND id <> \$2)'[^;]*;`)
	// Точное чтение наличия строки в TEMP владельца закреплено телом графа: перед
	// ним проверяются owner, relpersistence=t и relkind=r двух таблиц квитанций.
	// Полный оператор ограничивает format одним name и результат populated:
	// конкатенация либо дополнительные аргументы здесь не разрешаются.
	tempPresenceRead := regexp.MustCompile(`(?is)^EXECUTE\s+format\(\s*'SELECT EXISTS\(SELECT 1 FROM pg_temp\.%I\)'\s*,\s*name\s*\)\s+INTO\s+populated\s*;`)
	var unknown []int
	for _, at := range executes {
		if !dynamicReads.MatchString(dynamicBody[at:]) && !tempPresenceRead.MatchString(dynamicBody[at:]) {
			unknown = append(unknown, at)
		}
	}
	return unknown
}

func ppTriggerHasUnreviewedExecute(body string) (bool, error) {
	clean, executes, err := ppTriggerExecuteTokens(body)
	if err != nil {
		return true, err
	}
	return len(ppTriggerUnreviewedExecuteOffsets(clean, executes)) != 0, nil
}

// Twins проверяют реальные рёбра графа и полный отказ, не текст lexer implementation.
func TestPermanentProjectCommand_TriggerCallGraphLexicalCensus(t *testing.T) {
	for _, tc := range []struct {
		name, body string
		calls      []string
	}{
		{name: "signature_literal", body: `PERFORM '_authority_protocol_enter_contract_v3(text)';`},
		{name: "signature_call", body: `PERFORM _authority_protocol_enter_contract_v3('text');`, calls: []string{"_authority_protocol_enter_contract_v3"}},
		{name: "single_escape_literal", body: `PERFORM 'it''s callee()';`},
		{name: "escape_literal", body: `PERFORM E'it\'s callee()';`},
		{name: "dollar_literals", body: `PERFORM $$callee()$$, $tag_7$callee()$tag_7$;`},
		{name: "nested_comments", body: "/* callee() /* callee() */ */ -- callee()\nPERFORM 1;"},
		{name: "unquoted_case", body: `PERFORM KANAME.CaLlEe();`, calls: []string{"callee"}},
		{name: "quoted_case", body: `PERFORM "kaname"."CaLlEe"();`, calls: []string{"CaLlEe"}},
		{name: "quoted_escape", body: `PERFORM "odd""callee"();`, calls: []string{`odd"callee`}},
		{name: "comment_before_arguments", body: `PERFORM callee /* nested /* () */ */ ();`, calls: []string{"callee"}},
		{name: "literal_then_call", body: `PERFORM 'callee()', $$callee()$$; PERFORM callee();`, calls: []string{"callee"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			_, _, calls, err := ppTriggerSQLTokens(tc.body)
			require.NoError(t, err)
			var names []string
			for _, call := range calls {
				names = append(names, call.name)
				require.GreaterOrEqual(t, call.offset, 0)
				require.Less(t, call.offset, len(tc.body))
			}
			require.Equal(t, tc.calls, names)
		})
	}
	t.Run("literal_does_not_admit_entry_but_real_call_does", func(t *testing.T) {
		funcs := map[uint32]ppTriggerFunction{
			1: {name: "root", signature: "kaname.root()", language: "plpgsql", body: `PERFORM '_authority_protocol_enter_contract_v3(text)';`},
			2: {name: "_authority_protocol_enter_contract_v3", signature: "kaname._authority_protocol_enter_contract_v3(text)", language: "plpgsql", body: `EXECUTE 'REVOKE ALL ON x FROM PUBLIC';`},
		}
		roots := []ppTriggerRoot{{oid: 1, label: "kaname.t/trigger"}}
		require.Empty(t, ppTriggerGraphCensus(funcs, roots))
		root := funcs[1]
		root.body = `PERFORM "kaname"."_authority_protocol_enter_contract_v3"('text');`
		funcs[1] = root
		census := ppTriggerGraphCensus(funcs, roots)
		require.Len(t, census, 1)
		require.Contains(t, census[0], `function="kaname._authority_protocol_enter_contract_v3(text)" offset=0: unreviewed EXECUTE`)
	})
	t.Run("all_unknown_offsets_and_functions", func(t *testing.T) {
		body := `PERFORM 'EXECUTE hidden()', $q$EXECUTE ignored()$q$; EXECUTE 'SELECT 1'; EXECUTE 'SELECT 2';`
		funcs := map[uint32]ppTriggerFunction{
			1: {name: "root", signature: "kaname.root()", language: "plpgsql", body: `PERFORM child(); PERFORM sibling();`},
			2: {name: "child", signature: "kaname.child()", language: "plpgsql", body: body},
			3: {name: "sibling", signature: "kaname.sibling()", language: "plpgsql", body: `EXECUTE 'SELECT 3';`},
		}
		roots := []ppTriggerRoot{{oid: 1, label: "z/root"}, {oid: 1, label: "a/root"}}
		census := ppTriggerGraphCensus(funcs, roots)
		expected := []string{
			fmt.Sprintf(`root="a/root" path="kaname.root() -> kaname.child()@8" function="kaname.child()" offset=%d: unreviewed EXECUTE`, strings.Index(body, "EXECUTE 'SELECT 1'")),
			fmt.Sprintf(`root="a/root" path="kaname.root() -> kaname.child()@8" function="kaname.child()" offset=%d: unreviewed EXECUTE`, strings.Index(body, "EXECUTE 'SELECT 2'")),
			`root="a/root" path="kaname.root() -> kaname.sibling()@25" function="kaname.sibling()" offset=0: unreviewed EXECUTE`,
		}
		require.Equal(t, expected, census)
		require.Equal(t, census, ppTriggerGraphCensus(funcs, []ppTriggerRoot{roots[1], roots[0]}))
	})
	for _, tc := range []struct{ name, body string }{
		{"unterminated_single", `PERFORM 'callee()`},
		{"unterminated_escape", `PERFORM E'tail\`},
		{"unterminated_identifier", `PERFORM "callee`},
		{"unterminated_dollar", `PERFORM $q$callee()`},
		{"unterminated_comment", `/* outer /* inner */`},
		{"unclosed_parenthesis", `PERFORM callee(`},
		{"extra_parenthesis", `PERFORM callee())`},
		{"empty_identifier", `PERFORM ""()`},
		{"nul_literal", "PERFORM 'bad\x00literal';"},
		{"unsupported_unicode_identifier", `PERFORM U&"c\0061llee"()`},
	} {
		t.Run("malformed_"+tc.name, func(t *testing.T) {
			_, _, _, err := ppTriggerSQLTokens(tc.body)
			require.Error(t, err)
			census := ppTriggerGraphCensus(map[uint32]ppTriggerFunction{
				1: {name: "root", signature: "kaname.root()", language: "plpgsql", body: tc.body},
			}, []ppTriggerRoot{{oid: 1, label: "kaname.t/trigger"}})
			require.NotEmpty(t, census)
			require.Contains(t, strings.Join(census, "\n"), "неразобранное тело callback")
		})
	}
}

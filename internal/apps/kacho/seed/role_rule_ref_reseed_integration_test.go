// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed_test

// role_rule_ref_reseed_integration_test.go — досев проекции ОБЪЯВЛЕННЫХ
// СЕГМЕНТОВ правила на старте (kacho#1821), поведенческая половина.
//
// # Что утверждается
//
// После старта на чистой базе у КАЖДОЙ системной роли с непустыми правилами
// множество строк `kacho_iam.role_rule_ref` совпадает с `domain.RuleRefsOf` её
// правил — по всем ролям сразу, а не только по посеянной пробой. Роль,
// заведённая сырым SQL миграции, путём пользовательской роли не проходит
// никогда, поэтому «совпадает у моей роли» ничего не сказало бы о том, ради чего
// полоса заведена.
//
// # Чего эта проба НЕ утверждает
//
// Ни уровня журнала, ни счётчика исходов: они живут в композиционном корне, то
// есть в `package main`, куда проба Go не дотягивается by construction. Ту
// половину держит гейт дерева
// `services/iam/internal/check/seed_rule_ref_lane_test.go` — он же судит, что
// полосу вообще кто-то зовёт.
//
// # Якорь — это NULL в базе и пустая строка в домене
//
// Правило, не сузившее глаголы (`verbs: ["*"]`), даёт ОДНУ строку с пустым
// глаголом. В базе она лежит как `NULL`, в домене — как `""`. Сравнение обязано
// сводить обе формы к одной, иначе якорь читался бы как расхождение всегда, а
// проба краснела бы на исправном продукте.

import (
	"context"
	"sort"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	kachopg "github.com/PRO-Robotech/kacho-iam/internal/repo/kacho/pg"
)

// anchorRules — правило БЕЗ сужения глаголов: даёт ровно один сегмент-якорь.
// Ресурс взят из каталога платформы: правило вне каталога отвергается ключом, и
// проба краснела бы на исправном ключе.
const anchorRules = `[{"module":"iam","resources":["role"],"verbs":["*"]}]`

// ruleRefRow — строка проекции в форме, сравнимой с доменной.
type ruleRefRow struct {
	Module   string
	Resource string
	Verb     string
}

// declaredRuleRefsOf — что объявляет правило роли, в форме строк проекции.
func declaredRuleRefsOf(t *testing.T, raw []byte) []ruleRefRow {
	t.Helper()
	rules, err := domain.DecodeRules(raw)
	require.NoError(t, err, "разобрать правила роли")
	refs := domain.RuleRefsOf(rules)
	out := make([]ruleRefRow, 0, len(refs))
	for _, r := range refs {
		out = append(out, ruleRefRow{Module: r.Module, Resource: r.Resource, Verb: r.Verb})
	}
	sortRuleRefRows(out)
	return out
}

// storedRuleRefsOf — что лежит в проекции. `NULL` якоря сводится к пустой строке.
func storedRuleRefsOf(t *testing.T, ctx context.Context, pool *pgxpool.Pool, roleID string) []ruleRefRow {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT module, resource, COALESCE(verb, '')
		   FROM kacho_iam.role_rule_ref WHERE role_id = $1`, roleID)
	require.NoError(t, err, "прочитать проекцию сегментов роли %s", roleID)
	defer rows.Close()
	var out []ruleRefRow
	for rows.Next() {
		var r ruleRefRow
		require.NoError(t, rows.Scan(&r.Module, &r.Resource, &r.Verb))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	sortRuleRefRows(out)
	return out
}

func sortRuleRefRows(rows []ruleRefRow) {
	sort.Slice(rows, func(i, j int) bool {
		if rows[i].Module != rows[j].Module {
			return rows[i].Module < rows[j].Module
		}
		if rows[i].Resource != rows[j].Resource {
			return rows[i].Resource < rows[j].Resource
		}
		return rows[i].Verb < rows[j].Verb
	})
}

// systemRolesWithRules — те же роли, что берёт досев: системные, живые, с
// непустым массивом правил.
func systemRolesWithRules(t *testing.T, ctx context.Context, pool *pgxpool.Pool) map[string][]byte {
	t.Helper()
	rows, err := pool.Query(ctx,
		`SELECT id, rules FROM kacho_iam.roles
		  WHERE is_system = true AND live AND rules IS NOT NULL
		    AND jsonb_typeof(rules) = 'array' AND jsonb_array_length(rules) > 0`)
	require.NoError(t, err, "перечислить системные роли")
	defer rows.Close()
	out := make(map[string][]byte)
	for rows.Next() {
		var (
			id  string
			raw []byte
		)
		require.NoError(t, rows.Scan(&id, &raw))
		out[id] = raw
	}
	require.NoError(t, rows.Err())
	return out
}

// TestRuleRefReseedMatchesDeclaredSegmentsForEverySystemRole — несущее
// утверждение полосы.
func TestRuleRefReseedMatchesDeclaredSegmentsForEverySystemRole(t *testing.T) {
	ctx, pool := newReseedPool(t)

	// Две роли, заведённые СЫРЫМ SQL — тем путём, каким их заводит миграция и
	// каким они через путь пользовательской роли не проходят никогда. Вторая
	// несёт ЯКОРЬ: без неё проба не отличала бы «сегменты пишутся» от «пишутся
	// только названные глаголы».
	named := seedProbeSystemRole(t, ctx, pool,
		"role-1821-named", "role-1821-named", materializingRules)
	anchored := seedProbeSystemRole(t, ctx, pool,
		"role-1821-anchor", "role-1821-anchor", anchorRules)

	// Положительный контроль: ДО досева проекции у посеянных ролей нет. Без него
	// совпадение ниже могло бы означать, что строки положил кто-то другой, а
	// полоса не исполнялась вовсе.
	require.Empty(t, storedRuleRefsOf(t, ctx, pool, named),
		"до досева у роли уже есть строки проекции — совпадение после досева "+
			"ничего не докажет")
	require.Empty(t, storedRuleRefsOf(t, ctx, pool, anchored))

	census, err := seed.ReseedSystemRoleRuleRefs(ctx, kachopg.New(pool, nil), pool, nil)
	require.NoError(t, err, "досев проекции сегментов отказал: %+v", census)

	roles := systemRolesWithRules(t, ctx, pool)
	require.NotZero(t, len(roles),
		"системных ролей с непустыми правилами ноль — обход беспредметен, "+
			"и «совпало у всех» означало бы «не проверено ни одной»")
	require.Equal(t, len(roles), census.Examined,
		"досев осмотрел не тот набор ролей, что проба")
	require.Equal(t, len(roles), census.Reseeded,
		"часть ролей не пересеяна: перепись %+v", census)

	mismatched := 0
	for id, raw := range roles {
		want := declaredRuleRefsOf(t, raw)
		got := storedRuleRefsOf(t, ctx, pool, id)
		if !assertRuleRefsEqual(t, id, want, got) {
			mismatched++
		}
	}
	t.Logf("перепись: системных ролей с правилами %d · пересеяно %d · сегментов %d · расхождений %d",
		len(roles), census.Reseeded, census.Refs, mismatched)

	// Якорь дошёл до базы именно якорем, а не строкой с глаголом.
	require.Equal(t,
		[]ruleRefRow{{Module: "iam", Resource: "role", Verb: ""}},
		storedRuleRefsOf(t, ctx, pool, anchored),
		"правило без сужения глаголов обязано дать ОДИН сегмент-якорь")

	// Сироты выдач по этой полосе не заводятся: строка проекции, чей референт не
	// резолвится, отвергается ключом, а не оседает следом.
	var orphans int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kacho_iam.role_grant_orphan WHERE source = 'rule_ref'`).
		Scan(&orphans))
	require.Zero(t, orphans, "досев оставил следы нерезолвящихся сегментов")
}

// assertRuleRefsEqual — сравнение с ИМЕНЕМ роли в тексте отказа: без него
// расхождение называет «слайсы не равны» и не говорит, у кого. Роль, чьё имя не
// названо, ищется потом обходом всех системных ролей вручную.
func assertRuleRefsEqual(t *testing.T, roleID string, want, got []ruleRefRow) bool {
	t.Helper()
	if len(want) == len(got) {
		same := true
		for i := range want {
			if want[i] != got[i] {
				same = false
				break
			}
		}
		if same {
			return true
		}
	}
	t.Errorf("роль %s: проекция сегментов разошлась с объявленным правилом\n"+
		"  объявлено: %+v\n  в базе:    %+v", roleID, want, got)
	return false
}

// TestRuleRefReseedIsIdempotent — повторный старт не удваивает и не теряет.
//
// Замена «снять всё, положить текущее» обязана быть тождественной на повторе:
// иначе каждый перезапуск службы менял бы проекцию, и расхождение накапливалось
// бы там, где его никто не ищет.
func TestRuleRefReseedIsIdempotent(t *testing.T) {
	ctx, pool := newReseedPool(t)
	id := seedProbeSystemRole(t, ctx, pool,
		"role-1821-idem", "role-1821-idem", materializingRules)

	repo := kachopg.New(pool, nil)
	first, err := seed.ReseedSystemRoleRuleRefs(ctx, repo, pool, nil)
	require.NoError(t, err)
	after := storedRuleRefsOf(t, ctx, pool, id)
	require.NotEmpty(t, after, "первый прогон не написал ничего — повтор нечему сравнивать")

	second, err := seed.ReseedSystemRoleRuleRefs(ctx, repo, pool, nil)
	require.NoError(t, err)
	require.Equal(t, after, storedRuleRefsOf(t, ctx, pool, id),
		"повторный досев изменил проекцию — замена не тождественна")
	require.Equal(t, first.Refs, second.Refs, "перепись сегментов разошлась между прогонами")
	t.Logf("перепись: прогон 1 %+v · прогон 2 %+v", first, second)
}

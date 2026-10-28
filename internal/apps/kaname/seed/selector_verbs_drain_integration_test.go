// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package seed_test

// selector_verbs_drain_integration_test.go — ОЧЕРЕДЬ ПЕРЕСЧЁТА ГЛАГОЛОВ ПРАВИЛ
// ЗАКРЫВАЕТ ОКНО МИГРАЦИИ (kaname#878).
//
// Роль из очереди несёт на строках селекторов объединение глаголов по роли —
// прежнее поведение решения о доступе. Окно закрывается только тогда, когда
// очередь пуста: пересчёт повторяется, отказ одной роли не роняет проход, а
// длина очереди видна переписью каждого прохода.

import (
	"context"
	"encoding/json"
	"errors"
	"slices"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
)

// drainRules — два правила разных глаголов над одним типом: чтение всех реестров
// и удаление одного. Объединение по роли даёт удаление обоим правилам.
func drainRules() domain.Rules {
	return domain.Rules{
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"get"}},
		{Module: "registry", Resources: []string{"registries"}, Verbs: []string{"delete"},
			ResourceNames: []string{"reg00000000000000001"}},
	}
}

// stageStaleTenantRole — роль арендатора в состоянии «после миграции»: строки
// селекторов несут объединение глаголов по роли, роль — в очереди.
func stageStaleTenantRole(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id, accID string, rules domain.Rules) {
	t.Helper()
	raw, err := domain.EncodeRules(rules)
	require.NoError(t, err)
	_, err = pool.Exec(ctx,
		`INSERT INTO kaname.roles (id, account_id, name, permissions, rules)
		 VALUES ($1, $2, $3, '[]'::jsonb, $4::jsonb)`, id, accID, "probe_"+id[len(id)-4:], raw)
	require.NoErrorf(t, err, "роль %s", id)
	union := map[string][]string{}
	for _, p := range catalogfixture.Facts().RoleVerbsFromSelectors(rules.MaterializingSelectors(), domain.TenantPolicy()) {
		union[p.ObjectType] = append(union[p.ObjectType], p.Verb)
		_, err := pool.Exec(ctx, `INSERT INTO kaname.role_verb (role_id, object_type, verb) VALUES ($1, $2, $3)`,
			id, p.ObjectType, p.Verb)
		require.NoError(t, err)
	}
	unionJSON, err := json.Marshal(union)
	require.NoError(t, err)
	for _, s := range rules.MaterializingSelectors() {
		names := s.ResourceNames
		if names == nil {
			names = []string{}
		}
		_, err := pool.Exec(ctx,
			`INSERT INTO kaname.role_rule_selectors
			   (role_id, rule_fp, arm, object_types, resource_names, match_labels, verbs_by_type)
			 VALUES ($1, $2, $3, $4, $5, '{}'::jsonb, $6::jsonb)`,
			id, s.RuleFP, map[domain.Arm]string{domain.ArmAnchor: "anchor", domain.ArmNames: "names"}[s.Arm],
			s.ObjectTypes, names, unionJSON)
		require.NoError(t, err)
	}
	enqueueForRegrain(t, ctx, pool, id)
}

// exactMaps — карты, которые обязан записать пересчёт: по правилу.
func exactMaps(rules domain.Rules) map[string]map[string][]string {
	out := map[string]map[string][]string{}
	for _, s := range catalogfixture.Facts().GrantSelectors(rules.MaterializingSelectors(), domain.TenantPolicy()) {
		m := map[string][]string{}
		for k, v := range s.Grants {
			m[k] = slices.Sorted(slices.Values(v))
		}
		out[s.RuleFP] = m
	}
	return out
}

func storedMaps(t *testing.T, ctx context.Context, pool *pgxpool.Pool, id string) map[string]map[string][]string {
	t.Helper()
	rows, err := pool.Query(ctx, `SELECT rule_fp, verbs_by_type FROM kaname.role_rule_selectors WHERE role_id = $1`, id)
	require.NoError(t, err)
	defer rows.Close()
	out := map[string]map[string][]string{}
	for rows.Next() {
		var fp string
		var raw []byte
		require.NoError(t, rows.Scan(&fp, &raw))
		m := map[string][]string{}
		require.NoError(t, json.Unmarshal(raw, &m))
		for k := range m {
			slices.Sort(m[k])
		}
		out[fp] = m
	}
	require.NoError(t, rows.Err())
	return out
}

// clearQueue — очередь базы пробы до сцены пуста: миграция ставит в неё и
// системные роли посева, и без этого перепись прохода считала бы чужие роли.
func clearQueue(t *testing.T, ctx context.Context, pool *pgxpool.Pool) {
	t.Helper()
	c, err := seed.RegrainQueuedSelectorVerbs(ctx, kanamepg.New(pool, nil), pool, catalogfixture.Facts())
	require.NoError(t, err)
	require.Zero(t, c.Pending, "очередь базы пробы не опустела до сцены")
}

func queueLen(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.role_selector_verbs_pending`).Scan(&n))
	return n
}

// flakyRepo — настоящий репозиторий, у которого пересчёт глаголов правил роли
// `failFor` отказывает `left` раз. Всё прочее — настоящее.
type flakyRepo struct {
	kanamerepo.Repository
	failFor string
	left    *atomic.Int32
}

func (r flakyRepo) Writer(ctx context.Context) (kanamerepo.Writer, error) {
	w, err := r.Repository.Writer(ctx)
	if err != nil {
		return nil, err
	}
	return flakyWriter{Writer: w, r: r}, nil
}

type flakyWriter struct {
	kanamerepo.Writer
	r flakyRepo
}

func (w flakyWriter) RolesW() role.WriterIface {
	return flakyRoles{WriterIface: w.Writer.RolesW(), r: w.r}
}

type flakyRoles struct {
	role.WriterIface
	r flakyRepo
}

var errInjected = errors.New("инъекция: пересчёт роли отказал")

func (x flakyRoles) RegrainSelectorVerbs(ctx context.Context, id domain.RoleID, sels []domain.RuleSelector) error {
	if string(id) == x.r.failFor && x.r.left.Add(-1) >= 0 {
		return errInjected
	}
	return x.WriterIface.RegrainSelectorVerbs(ctx, id, sels)
}

// Отказ одной роли не роняет проход: соседняя роль пересчитана, отказавшая
// посчитана и осталась в очереди, длина очереди названа переписью.
func TestSelectorVerbsDrain_OneRoleFailureDoesNotStopThePass(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)
	_, accID := seedProbeAccountWithoutOwnerBinding(t, ctx, pool, "dr1")
	clearQueue(t, ctx, pool)
	stageStaleTenantRole(t, ctx, pool, "rol-dr1-fail", accID, drainRules())
	stageStaleTenantRole(t, ctx, pool, "rol-dr1-good", accID, drainRules())
	left := &atomic.Int32{}
	left.Store(1000)
	repo := flakyRepo{Repository: kanamepg.New(pool, nil), failFor: "rol-dr1-fail", left: left}

	c, err := seed.RegrainQueuedSelectorVerbs(ctx, repo, pool, catalogfixture.Facts())
	require.Error(t, err, "отказ роли обязан дойти до вызывающего")
	require.Equal(t, seed.SelectorVerbsCensus{Examined: 2, Regrained: 1, Failed: 1, Pending: 1}, c)
	require.Equal(t, exactMaps(drainRules()), storedMaps(t, ctx, pool, "rol-dr1-good"))
}

// (к) Сорванный пересчёт повторяется и закрывает окно: очередь пустеет, карты
// точные, переписи проходов называют и отказ, и длину очереди.
func TestSelectorVerbsDrain_AFailedRegrainIsRetriedUntilTheQueueIsEmpty(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)
	_, accID := seedProbeAccountWithoutOwnerBinding(t, ctx, pool, "dr2")
	clearQueue(t, ctx, pool)
	stageStaleTenantRole(t, ctx, pool, "rol-dr2-flak", accID, drainRules())
	left := &atomic.Int32{}
	left.Store(2)
	repo := flakyRepo{Repository: kanamepg.New(pool, nil), failFor: "rol-dr2-flak", left: left}

	var passes []seed.SelectorVerbsCensus
	dctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	// Разбор живёт, пока жив переходный механизм: здесь его останавливает проба,
	// как только проход назвал пустую очередь.
	_ = seed.DrainSelectorVerbsQueue(dctx, repo, pool, catalogfixture.Source(), 20*time.Millisecond,
		func(c seed.SelectorVerbsCensus, _ error) {
			passes = append(passes, c)
			if c.Pending == 0 {
				cancel()
			}
		})
	require.GreaterOrEqual(t, len(passes), 3, "ждали два сорванных прохода и третий, закрывший окно: %v", passes)
	require.Equal(t, 1, passes[0].Failed)
	require.Equal(t, 1, passes[0].Pending)
	require.Equal(t, 0, passes[2].Pending)
	require.Zero(t, queueLen(t, ctx, pool))
	require.Equal(t, exactMaps(drainRules()), storedMaps(t, ctx, pool, "rol-dr2-flak"))
}

// (и) Две реплики пересчитывают очередь одновременно, рядом идёт правка роли —
// стороны сходятся к точному набору правил ПОСЛЕ правки, очередь пуста.
func TestSelectorVerbsDrain_ReplicasAndARoleEditConverge(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)
	_, accID := seedProbeAccountWithoutOwnerBinding(t, ctx, pool, "dr3")
	clearQueue(t, ctx, pool)
	const id = "rol-dr3-race"
	stageStaleTenantRole(t, ctx, pool, id, accID, drainRules())
	edited := append(drainRules(), domain.Rule{Module: "registry", Resources: []string{"repositories"}, Verbs: []string{"list"}})

	var wg sync.WaitGroup
	errs := make(chan error, 3)
	for range 2 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			dctx, cancel := context.WithTimeout(ctx, 3*time.Second)
			defer cancel()
			err := seed.DrainSelectorVerbsQueue(dctx, kanamepg.New(pool, nil), pool, catalogfixture.Source(),
				10*time.Millisecond, nil)
			if errors.Is(err, context.DeadlineExceeded) {
				err = nil // разбор живёт до отмены — срок пробы и есть отмена
			}
			errs <- err
		}()
	}
	wg.Add(1)
	go func() {
		defer wg.Done()
		errs <- editRoleRules(ctx, pool, id, edited)
	}()
	wg.Wait()
	close(errs)
	for err := range errs {
		require.NoError(t, err)
	}
	require.Zero(t, queueLen(t, ctx, pool))
	require.Equal(t, exactMaps(edited), storedMaps(t, ctx, pool, id),
		"после гонки реплик и правки карты не равны точному набору правил после правки")
}

// editRoleRules — правка правил роли путём роли: строка роли, селекторы и
// проекция глаголов одной транзакцией писателя.
func editRoleRules(ctx context.Context, pool *pgxpool.Pool, id string, rules domain.Rules) error {
	repo := kanamepg.New(pool, nil)
	w, err := repo.Writer(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = w.Rollback(ctx) }()
	r, err := w.Roles().Get(ctx, domain.RoleID(id))
	if err != nil {
		return err
	}
	r.Rules = rules
	if _, err := w.RolesW().Update(ctx, r, []string{"rules"}); err != nil {
		return err
	}
	facts := catalogfixture.Facts()
	if err := w.RolesW().ReplaceRuleSelectors(ctx, r.ID, facts.GrantSelectors(rules.MaterializingSelectors(), domain.TenantPolicy())); err != nil {
		return err
	}
	if err := w.RolesW().ReplaceRoleVerbs(ctx, r.ID, facts.RoleVerbsFromSelectors(rules.MaterializingSelectors(), domain.TenantPolicy())); err != nil {
		return err
	}
	return w.Commit(ctx)
}

// Разбор не кончается на пустой очереди: строка, вставленная писателем прежней
// версии ПОСЛЕ того, как очередь опустела (переходный страж кладёт верхнюю
// границу и ставит роль в очередь), получает точную карту без перезапуска, и
// перепись печатается и на пустой очереди.
func TestSelectorVerbsDrain_KeepsServingAfterTheQueueEmpties(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)
	_, accID := seedProbeAccountWithoutOwnerBinding(t, ctx, pool, "dr4")
	clearQueue(t, ctx, pool)

	var (
		mu      sync.Mutex
		passes  []seed.SelectorVerbsCensus
		emptied = make(chan struct{})
		once    sync.Once
	)
	dctx, cancel := context.WithCancel(ctx)
	done := make(chan struct{})
	go func() {
		defer close(done)
		_ = seed.DrainSelectorVerbsQueue(dctx, kanamepg.New(pool, nil), pool, catalogfixture.Source(),
			20*time.Millisecond, func(c seed.SelectorVerbsCensus, _ error) {
				mu.Lock()
				passes = append(passes, c)
				mu.Unlock()
				if c.Pending == 0 {
					once.Do(func() { close(emptied) })
				}
			})
	}()
	t.Cleanup(func() { cancel(); <-done })

	select {
	case <-emptied:
	case <-time.After(10 * time.Second):
		t.Fatal("разбор не опустошил очередь за 10 с")
	}

	// Писатель прежней версии: роль и строки селекторов БЕЗ карты.
	const id = "rol-dr4-late"
	rules := drainRules()
	raw, err := domain.EncodeRules(rules)
	require.NoError(t, err)
	_, err = pool.Exec(ctx, `INSERT INTO kaname.roles (id, account_id, name, permissions, rules)
	                          VALUES ($1, $2, 'probe_dr4_late', '[]'::jsonb, $3::jsonb)`, id, accID, raw)
	require.NoError(t, err)
	for _, s := range rules.MaterializingSelectors() {
		arm, names := "anchor", []string{}
		if s.Arm == domain.ArmNames {
			arm, names = "names", s.ResourceNames
		}
		_, err := pool.Exec(ctx, `INSERT INTO kaname.role_rule_selectors
		                            (role_id, rule_fp, arm, object_types, resource_names, match_labels)
		                          VALUES ($1, $2, $3, $4, $5, '{}'::jsonb)`, id, s.RuleFP, arm, s.ObjectTypes, names)
		require.NoError(t, err)
	}
	require.Equal(t, 1, queueLen(t, ctx, pool), "КОНТРОЛЬ: переходный страж роль в очередь не поставил")
	mu.Lock()
	before := len(passes)
	mu.Unlock()

	require.Eventually(t, func() bool { return queueLen(t, ctx, pool) == 0 }, 10*time.Second, 50*time.Millisecond,
		"роль, поставленная после опустения очереди, не разобрана без перезапуска")
	require.Equal(t, exactMaps(rules), storedMaps(t, ctx, pool, id))

	// Перепись печатается и на пустой очереди: проходы идут после разбора.
	require.Eventually(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(passes) >= before+2 && passes[len(passes)-1].Pending == 0
	}, 10*time.Second, 50*time.Millisecond, "на пустой очереди проходы с переписью не продолжились")
}

// Паритет верхней границы: для каждого живого типа платформы (правило `*.*`,
// подстановка глаголов) точный набор глаголов правила — подмножество верхней
// границы, которую кладут досев системной роли и переходный страж. Иначе роль в
// очереди теряла бы доступ, а не держала прежний.
func TestSelectorVerbsUpperBound_CoversTheExactGrants(t *testing.T) {
	if testing.Short() {
		t.Skip("нужен Postgres")
	}
	ctx, pool := newReseedPool(t)
	rules := domain.Rules{{Module: "*", Resources: []string{"*"}, Verbs: []string{"*"}}}
	sels := catalogfixture.Facts().GrantSelectors(rules.MaterializingSelectors(), domain.TenantPolicy())
	checked := 0
	for _, s := range sels {
		var raw []byte
		require.NoError(t, pool.QueryRow(ctx, `SELECT kaname.role_selector_verbs_upper_bound($1)`, s.ObjectTypes).Scan(&raw))
		bound := map[string][]string{}
		require.NoError(t, json.Unmarshal(raw, &bound))
		for typ, verbs := range s.Grants {
			for _, v := range verbs {
				require.Containsf(t, bound[typ], v, "тип %s: глагол %s точного набора вне верхней границы %v", typ, v, bound[typ])
				checked++
			}
		}
	}
	require.Greater(t, checked, 50, "сверено пар «тип × глагол» %d — проба беспредметна", checked)
	t.Logf("сверено пар «тип × глагол»: %d", checked)
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// catalog_consequence_reaches_role_readers_integration_test.go — приёмка
// `docs/engineering/acceptance/catalog-consequence-reaches-role-readers.md`
// (kaname#76 и остаток kacho#1814 §6 п. 1), части I и II.
//
// Право, отобранное последствием каталога, (а) даёт роли ровно одно событие
// `iam_role UPDATED` на транзакцию и не даёт его, когда отбирать было нечего;
// (б) не обещается превью роли.
//
// # Мир М
//
// Строится домами дерева: база харнесса пакета, синтетический модуль `probemod`
// путём старта (три ресурса), снимок каталога поверх ценза стража паритета,
// арендатор с вычеканенным проектом, роли — use-case'ом создания. Журнал не
// чистится: события шага «Когда» отсчитываются от МЕТКИ — наибольшего номера
// строки журнала перед шагом. Так сценарий оболочки (`IAM-CCR-06`) видит строку
// `CREATED` той же роли, а прочие — только своё.

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"

	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/operationresolver"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
	_ "github.com/PRO-Robotech/kaname/internal/dto/toproto" // переводы реестра
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	reporole "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// ─────────────────────────────────────────────────────────────────────────────
// Мир М

// ccrRoleRules — правила ролей мира, по таблице приёмки §4.
func ccrRoleRules(name string) domain.Rules {
	r := func(verbs []string, res ...string) domain.Rule {
		return domain.Rule{Module: applierProbeModule, Resources: res, Verbs: verbs}
	}
	v := func(s ...string) []string { return s }
	switch name {
	case "a", "p":
		return domain.Rules{r(v("get"), "widgets"), r(v("list"), "gadgets")}
	case "b":
		return domain.Rules{r(v("get"), "widgets"), r(v("get", "list"), "gadgets")}
	case "c":
		return domain.Rules{r(v("get"), "widgets", "gadgets")}
	case "d":
		return domain.Rules{r(v("update"), "widgets"), r(v("get"), "gadgets")}
	case "e":
		return domain.Rules{r(v("list"), "gadgets")}
	case "f":
		return domain.Rules{r(v("update"), "gadgets")}
	case "w":
		return domain.Rules{r(v("*"), "widgets"), r(v("list"), "gadgets")}
	case "t":
		return domain.Rules{r(v("list", "create"), "gadgets")}
	case "u":
		return domain.Rules{r(v("create"), "gadgets")}
	case "v":
		return domain.Rules{r(v("*"), "widgets", "spare")}
	}
	panic("роль мира М не объявлена: " + name)
}

// Входы шага «Когда».
func ccrFull() *manifest.Manifest {
	return probeManifest(
		probeResource("widgets", "get", "list", "update", "delete"),
		probeResource("gadgets", "get", "list", "update", "delete"),
		probeResource("spare", "get", "list"))
}

func ccrOmegaWidgets() *manifest.Manifest {
	return probeManifest(
		probeResource("gadgets", "get", "list", "update", "delete"),
		probeResource("spare", "get", "list"))
}

func ccrOmegaSpare() *manifest.Manifest {
	return probeManifest(
		probeResource("widgets", "get", "list", "update", "delete"),
		probeResource("gadgets", "get", "list", "update", "delete"))
}

func ccrOmegaUpdate() *manifest.Manifest {
	return probeManifest(
		probeResource("widgets", "get", "list", "update", "delete"),
		probeResource("gadgets", "get", "list", "delete"),
		probeResource("spare", "get", "list"))
}

// ccrWorld — мир М одной пробы.
type ccrWorld struct {
	ctx     context.Context
	pool    *pgxpool.Pool
	repo    kanamerepo.Repository
	catRepo *kanamepg.CatalogRepo
	snap    *catalog.Snapshot
	account string
	user    string
	project string
	roles   map[string]domain.RoleID
}

// buildCCRWorld поднимает мир М с названными ролями.
func buildCCRWorld(t *testing.T, names ...string) *ccrWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool := catalogPool(t)
	w := &ccrWorld{ctx: ctx, pool: pool, repo: kanamepg.New(pool, nil),
		catRepo: kanamepg.NewCatalogRepo(pool), roles: map[string]domain.RoleID{}}

	census, err := seed.AssertCatalogParity(ctx, w.catRepo, seed.ImageAnchor())
	require.NoError(t, err, "ПРЕДПОСЫЛКА: страж паритета каталога")
	w.snap, err = catalog.NewSnapshot(census.Halves(), w.catRepo, nil, nil)
	require.NoError(t, err, "ПРЕДПОСЫЛКА: снимок каталога")

	rep, err := applierOver(t, pool).Apply(ctx, ccrFull())
	require.NoError(t, err, "ПРЕДПОСЫЛКА: модуль пробы не принят путём старта")
	require.Equalf(t, 13, rep.WrittenVerbs,
		"строк действий модуля пробы %d, а мир М объявляет тринадцать (десять плюс три "+
			"ярусные `create`): %s", rep.WrittenVerbs, rep)
	require.NoError(t, w.snap.Refresh(ctx), "ПРЕДПОСЫЛКА: обновление снимка")

	w.seedTenant(t)
	for _, n := range names {
		w.roles[n] = w.createRole(t, n)
	}
	return w
}

// seedTenant — аккаунт, пользователь и проект с ВЫЧЕКАНЕННЫМИ идентификаторами:
// путь создания роли судит форму идентификатора синхронно.
func (w *ccrWorld) seedTenant(t *testing.T) {
	t.Helper()
	w.account = ids.NewID(domain.PrefixAccount)
	w.user = ids.NewID(domain.PrefixUser)
	w.project = ids.NewID(domain.PrefixProject)
	tx, err := w.pool.Begin(w.ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(w.ctx) }()
	exec := func(sql string, args ...any) {
		t.Helper()
		_, eerr := tx.Exec(w.ctx, sql, args...)
		require.NoError(t, eerr, "посев арендатора: %s", sql)
	}
	exec(`INSERT INTO users (id, account_id, external_id, email, display_name, invite_status)
	      VALUES ($1, $2, $3, $4, 'CCR', 'ACTIVE')`, w.user, w.account, "ext-"+w.user, "ccr-"+w.user+"@example.com")
	exec(`INSERT INTO accounts (id, name, owner_user_id, labels) VALUES ($1, 'ccr-acc', $2, '{}'::jsonb)`,
		w.account, w.user)
	exec(`INSERT INTO projects (id, account_id, name, labels) VALUES ($1, $2, 'ccr-prj', '{}'::jsonb)`,
		w.project, w.account)
	activewayin.Seed(t, w.ctx, tx)
	require.NoError(t, tx.Commit(w.ctx))
}

func (w *ccrWorld) callerCtx() context.Context {
	return operations.WithPrincipal(w.ctx, operations.Principal{Type: "user", ID: w.user, DisplayName: "CCR"})
}

// createRole заводит роль мира use-case'ом создания и доводит операцию до
// терминального исхода с пустым `error`.
func (w *ccrWorld) createRole(t *testing.T, name string) domain.RoleID {
	t.Helper()
	r := domain.Role{Name: domain.RoleName("ccr_" + name), Description: "мир М", Rules: ccrRoleRules(name)}
	if name == "p" {
		r.ProjectID = domain.ProjectID(w.project)
	} else {
		r.AccountID = domain.AccountID(w.account)
	}
	ops := operations.NewRepo(w.pool, "kaname")
	op, err := roleapp.NewCreateRoleUseCase(w.repo, ops, w.snap).Execute(w.callerCtx(), r)
	require.NoErrorf(t, err, "ПРЕДПОСЫЛКА: роль %s отвергнута синхронно", name)
	done := awaitOperation(t, w.ctx, ops, op.ID)
	require.Nilf(t, done.Error, "ПРЕДПОСЫЛКА: операция создания роли %s отказала: %v", name, done.Error)
	var meta iamv1.CreateRoleMetadata
	require.NoError(t, done.Metadata.UnmarshalTo(&meta))
	return domain.RoleID(meta.GetRoleId())
}

// mark — наибольший номер строки журнала: события шага «Когда» — строго после.
func (w *ccrWorld) mark(t *testing.T) int64 {
	t.Helper()
	var m int64
	require.NoError(t, w.pool.QueryRow(w.ctx,
		`SELECT COALESCE(max(sequence_no), 0) FROM kaname.resource_journal`).Scan(&m))
	return m
}

// roleEvents — строки журнала вида `iam_role` после метки: по роли и всего.
func (w *ccrWorld) roleEvents(t *testing.T, after int64) (byRole map[domain.RoleID][]string, total int) {
	t.Helper()
	rows, err := w.pool.Query(w.ctx, `
		SELECT resource_id, event_type FROM kaname.resource_journal
		 WHERE resource_kind = 'iam_role' AND sequence_no > $1 ORDER BY sequence_no`, after)
	require.NoError(t, err)
	defer rows.Close()
	byRole = map[domain.RoleID][]string{}
	for rows.Next() {
		var id, ev string
		require.NoError(t, rows.Scan(&id, &ev))
		byRole[domain.RoleID(id)] = append(byRole[domain.RoleID(id)], ev)
		total++
	}
	require.NoError(t, rows.Err())
	return byRole, total
}

// eventCensus — перепись событий по ролям мира одной строкой.
func (w *ccrWorld) eventCensus(byRole map[domain.RoleID][]string) string {
	names := make([]string, 0, len(w.roles))
	for n := range w.roles {
		names = append(names, n)
	}
	sort.Strings(names)
	parts := make([]string, 0, len(names))
	for _, n := range names {
		parts = append(parts, fmt.Sprintf("%s=%d", strings.ToUpper(n), len(byRole[w.roles[n]])))
	}
	return strings.Join(parts, " ")
}

// ledgerCount — строк ведомости роли.
func (w *ccrWorld) ledgerCount(t *testing.T, sql string, id domain.RoleID) int {
	t.Helper()
	var n int
	require.NoError(t, w.pool.QueryRow(w.ctx, sql, string(id)).Scan(&n))
	return n
}

// grants — выдачи роли, `тип:глагол`, по порядку.
func (w *ccrWorld) grants(t *testing.T, id domain.RoleID) []string {
	t.Helper()
	rows, err := w.pool.Query(w.ctx,
		`SELECT object_type || ':' || verb FROM kaname.role_verb WHERE role_id = $1 ORDER BY 1`, string(id))
	require.NoError(t, err)
	defer rows.Close()
	out := []string{}
	for rows.Next() {
		var s string
		require.NoError(t, rows.Scan(&s))
		out = append(out, s)
	}
	require.NoError(t, rows.Err())
	return out
}

// ccrAllowAll — порт модели прав, допускающий всякую роль: решение о доступе
// предметом сценариев не является, а превью на отказном пути не считается.
type ccrAllowAll struct{}

func (ccrAllowAll) CheckWithContext(context.Context, string, string, string, map[string]any) (bool, error) {
	return true, nil
}

func (ccrAllowAll) BatchCheckWithContext(_ context.Context, _, _ string, objects []string, _ map[string]any) ([]bool, error) {
	out := make([]bool, len(objects))
	for i := range out {
		out[i] = true
	}
	return out, nil
}

func (ccrAllowAll) ListSubjects(context.Context, string, string, string, int, string) ([]string, string, error) {
	return nil, "", nil
}

var _ clients.RelationQueries = ccrAllowAll{}

// read — ответ одиночного чтения роли use-case'ом над снимком `snap`.
func (w *ccrWorld) read(t *testing.T, snap catalog.Source, id domain.RoleID) *iamv1.Role {
	t.Helper()
	got, err := roleapp.NewGetRoleUseCase(w.repo, snap).WithRelationStore(ccrAllowAll{}).Execute(w.callerCtx(), id)
	require.NoErrorf(t, err, "чтение роли %s", id)
	return toPbRole(t, got)
}

func toPbRole(t *testing.T, r domain.Role) *iamv1.Role {
	t.Helper()
	var dst *iamv1.Role
	require.NoErrorf(t, dto.Transfer(dto.FromTo(r, &dst)), "перевод роли %s в ответ", r.ID)
	return dst
}

// preview — превью одной строкой: authored | effective | ключи заметок.
func preview(r *iamv1.Role) string {
	notes := make([]string, 0, len(r.GetVerbNotes()))
	for k := range r.GetVerbNotes() {
		notes = append(notes, k)
	}
	sort.Strings(notes)
	return fmt.Sprintf("%v | %v | %v", r.GetAuthoredVerbs(), r.GetEffectiveVerbs(), notes)
}

// ─────────────────────────────────────────────────────────────────────────────
// Часть I — событие, и часть II на том же применении Ω-widgets

// TestCCR_OmegaWidgets — IAM-CCR-01, -03, -06, -12, -13, -14, -15, -17,
// -18, -19: одно применение Ω-widgets, все утверждения о его исходе.
func TestCCR_OmegaWidgets(t *testing.T) {
	w := buildCCRWorld(t, "a", "b", "c", "d", "e", "f", "w", "p")
	a := w.roles["a"]

	// D до применения: квалификатор редактора с основанием.
	require.Equal(t, "[get update] | [get update delete*] | [delete*]", preview(w.read(t, w.snap, w.roles["d"])),
		"ПРЕДПОСЫЛКА -15: у D до применения квалификатор редактора")
	require.Equal(t, "[get list update delete] | [get list update delete] | []", preview(w.read(t, w.snap, w.roles["w"])),
		"ПРЕДПОСЫЛКА -17: подстановка W до применения")

	mark := w.mark(t)
	rep, err := applierOver(t, w.pool).Apply(w.ctx, ccrOmegaWidgets())
	require.NoError(t, err)
	t.Logf("перепись применения Ω-widgets: %s", rep)
	require.NoError(t, w.snap.Refresh(w.ctx))

	// ── IAM-CCR-01 ──────────────────────────────────────────────────────────
	require.Positive(t, rep.Resettled.RuleRefs, "объявления не переселены: %s", rep)
	require.Positive(t, rep.Resettled.RoleVerbs, "выдачи не переселены: %s", rep)
	require.Positive(t, rep.PrunedSelectorTypes, "элементы отбора не вырезаны: %s", rep)
	require.Positive(t, w.ledgerCount(t, `SELECT count(*) FROM kaname.role_grant_orphan WHERE role_id = $1 AND source = 'rule_ref'`, a),
		"у A нет сироты объявления — тогда «ровно одно» выполнялось бы на роли, тронутой не всеми операторами")
	require.Positive(t, w.ledgerCount(t, `SELECT count(*) FROM kaname.role_grant_orphan WHERE role_id = $1 AND source = 'role_verb'`, a))
	require.Positive(t, w.ledgerCount(t, `SELECT count(*) FROM kaname.role_selector_prune WHERE role_id = $1`, a))

	byRole, total := w.roleEvents(t, mark)
	t.Logf("событий iam_role: %s · всего %d", w.eventCensus(byRole), total)
	require.Equal(t, []string{"UPDATED"}, byRole[a],
		"IAM-CCR-01: роль A, тронутая всеми тремя популяциями, обязана получить РОВНО одно событие UPDATED")

	// ── IAM-CCR-03 ──────────────────────────────────────────────────────────
	for _, n := range []string{"a", "b", "c", "d", "w", "p"} {
		require.Equalf(t, []string{"UPDATED"}, byRole[w.roles[n]], "IAM-CCR-03: роль %s", strings.ToUpper(n))
	}
	for _, n := range []string{"e", "f"} {
		require.Emptyf(t, byRole[w.roles[n]], "IAM-CCR-03: роль %s widgets не называет", strings.ToUpper(n))
	}
	require.Equal(t, 6, total, "IAM-CCR-03: строк iam_role всего")

	// ── IAM-CCR-06 ──────────────────────────────────────────────────────────
	for _, n := range []string{"a", "p"} {
		id := w.roles[n]
		rows, qerr := w.pool.Query(w.ctx, `
			SELECT event_type, project_id, scope::text, payload::text FROM kaname.resource_journal
			 WHERE resource_kind = 'iam_role' AND resource_id = $1 ORDER BY sequence_no`, string(id))
		require.NoError(t, qerr)
		type env struct{ ev, project, scope, payload string }
		var got []env
		for rows.Next() {
			var e env
			require.NoError(t, rows.Scan(&e.ev, &e.project, &e.scope, &e.payload))
			got = append(got, e)
		}
		rows.Close()
		require.Lenf(t, got, 2, "IAM-CCR-06: у %s две строки — CREATED и UPDATED: %+v", n, got)
		require.Equal(t, "CREATED", got[0].ev)
		require.Equal(t, "UPDATED", got[1].ev)
		require.Equalf(t, got[0].project, got[1].project, "IAM-CCR-06: project_id роли %s", n)
		require.Equalf(t, got[0].scope, got[1].scope, "IAM-CCR-06: scope роли %s", n)
		var payload map[string]string
		require.NoError(t, json.Unmarshal([]byte(got[1].payload), &payload))
		require.Equal(t, map[string]string{"id": string(id)}, payload, "IAM-CCR-06: нагрузка — ровно идентификатор")
		if n == "a" {
			require.Empty(t, got[1].project)
			require.JSONEq(t, fmt.Sprintf(`[{"type":"account","id":%q}]`, w.account), got[1].scope)
		} else {
			require.Equal(t, w.project, got[1].project, "IAM-CCR-06: ось проекта у P")
			require.JSONEq(t, fmt.Sprintf(`[{"type":"project","id":%q}]`, w.project), got[1].scope)
		}
	}

	// ── Часть II: превью через обновлённый снимок ──────────────────────────
	pa := w.read(t, w.snap, a)
	require.Equal(t, "[list] | [list] | []", preview(pa), "IAM-CCR-12")
	require.Equal(t, "[get list] | [get list] | []", preview(w.read(t, w.snap, w.roles["b"])), "IAM-CCR-13")
	pc := w.read(t, w.snap, w.roles["c"])
	require.Equal(t, "[get] | [get] | []", preview(pc), "IAM-CCR-14")
	require.Len(t, pc.GetRuleStates(), 1)
	require.Equal(t, iamv1.RuleLifecycle_RULE_LIFECYCLE_WITHDRAWN, pc.GetRuleStates()[0].GetState(), "IAM-CCR-14")
	require.Equal(t, "[get] | [get] | []", preview(w.read(t, w.snap, w.roles["d"])), "IAM-CCR-15")
	require.Equal(t, "[list] | [list] | []", preview(w.read(t, w.snap, w.roles["w"])), "IAM-CCR-17")

	// ── IAM-CCR-19 ──────────────────────────────────────────────────────────
	require.Len(t, pa.GetRules(), 2, "IAM-CCR-19: авторские правила")
	require.Equal(t, []string{"widgets"}, pa.GetRules()[0].GetResources())
	require.Equal(t, []string{"get"}, pa.GetRules()[0].GetVerbs())
	require.Equal(t, []string{"gadgets"}, pa.GetRules()[1].GetResources())
	states := []iamv1.RuleLifecycle{}
	for _, s := range pa.GetRuleStates() {
		states = append(states, s.GetState())
	}
	require.Equal(t, []iamv1.RuleLifecycle{iamv1.RuleLifecycle_RULE_LIFECYCLE_WITHDRAWN, iamv1.RuleLifecycle_RULE_LIFECYCLE_ACTIVE}, states)
	require.EqualValues(t, 2, pa.GetDeclaredSegments())
	require.EqualValues(t, 1, pa.GetUnresolvedSegments())
	require.Equal(t, iamv1.RoleHealth_ROLE_HEALTH_DEGRADED, pa.GetHealth())
	sources := []iamv1.WithdrawnGrantSource{}
	for _, g := range pa.GetWithdrawnGrants() {
		require.Equal(t, applierProbeModule+".widgets", g.GetObjectType())
		require.Equal(t, "get", g.GetVerb())
		sources = append(sources, g.GetSource())
	}
	require.ElementsMatch(t, []iamv1.WithdrawnGrantSource{
		iamv1.WithdrawnGrantSource_WITHDRAWN_GRANT_SOURCE_GRANT,
		iamv1.WithdrawnGrantSource_WITHDRAWN_GRANT_SOURCE_RULE_REFERENCE,
	}, sources, "IAM-CCR-19: ведомость отобранного A")

	// ── IAM-CCR-18: одно превью на четырёх ответах ───────────────────────────
	list := w.listPreview(t, a)
	desc := domain.Description("правка описания — IAM-CCR-18")
	ops := operations.NewRepo(w.pool, "kaname")
	op, err := roleapp.NewUpdateRoleUseCase(w.repo, ops, w.snap).Execute(w.callerCtx(),
		roleapp.UpdateRoleInput{ID: a, Description: &desc, UpdateMask: []string{"description"}})
	require.NoError(t, err)
	done := awaitOperation(t, w.ctx, ops, op.ID)
	require.Nil(t, done.Error, "IAM-CCR-18: правка описания отказала")
	var echo iamv1.Role
	require.NoError(t, done.Response.UnmarshalTo(&echo))
	meta, err := anypb.New(&iamv1.UpdateRoleMetadata{RoleId: string(a)})
	require.NoError(t, err)
	res, err := operationresolver.New(w.repo, w.snap, nil).Resolve(w.ctx, operations.Operation{ID: "opccr18", Metadata: meta})
	require.NoError(t, err)
	require.Equal(t, operations.OutcomeDone, res.Outcome)
	var resolved iamv1.Role
	require.NoError(t, res.Response.UnmarshalTo(&resolved))
	for name, got := range map[string]*iamv1.Role{"Get": pa, "List": list, "эхо правки": &echo, "резолвер": &resolved} {
		require.Equalf(t, []string{"list"}, got.GetAuthoredVerbs(), "IAM-CCR-18: %s authored", name)
		require.Equalf(t, []string{"list"}, got.GetEffectiveVerbs(), "IAM-CCR-18: %s effective", name)
	}
}

// TestCCR08_RoleRowIsNotWritten — IAM-CCR-08: применение строку роли не
// пишет — версия и `updated_at` прежние, правка ПРАВИЛ арендатора по версии,
// снятой до применения, принята.
func TestCCR08_RoleRowIsNotWritten(t *testing.T) {
	w := buildCCRWorld(t, "a")
	a := w.roles["a"]
	version := func() string {
		rd, err := w.repo.Reader(w.ctx)
		require.NoError(t, err)
		defer func() { _ = rd.Rollback(w.ctx) }()
		_, v, err := rd.Roles().GetWithVersion(w.ctx, a)
		require.NoError(t, err)
		return v
	}
	updatedAt := func() time.Time {
		var at time.Time
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT updated_at FROM kaname.roles WHERE id = $1`, string(a)).Scan(&at))
		return at
	}
	v0, at0 := version(), updatedAt()

	_, err := applierOver(t, w.pool).Apply(w.ctx, ccrOmegaWidgets())
	require.NoError(t, err)
	require.Positive(t, w.ledgerCount(t, `SELECT count(*) FROM kaname.role_grant_orphan WHERE role_id = $1`, a),
		"IAM-CCR-08: применение A не тронуло — «ничего не сдвинулось» было бы вакуумным")
	require.Equal(t, v0, version(), "IAM-CCR-08: версия роли A сдвинулась — строка роли переписана")
	require.True(t, at0.Equal(updatedAt()), "IAM-CCR-08: updated_at роли A сдвинулся")

	ops := operations.NewRepo(w.pool, "kaname")
	op, err := roleapp.NewUpdateRoleUseCase(w.repo, ops, w.snap).Execute(w.callerCtx(), roleapp.UpdateRoleInput{
		ID: a, Rules: domain.Rules{{Module: applierProbeModule, Resources: []string{"gadgets"}, Verbs: []string{"list"}}},
		UpdateMask: []string{"rules"}, ResourceVersion: v0})
	require.NoError(t, err, "IAM-CCR-08: правка правил по прежней версии отвергнута синхронно")
	require.Nil(t, awaitOperation(t, w.ctx, ops, op.ID).Error,
		"IAM-CCR-08: операция правки правил по прежней версии отказала")
}

// listPreview — роль из ответа списка (страницы до той, где она есть).
func (w *ccrWorld) listPreview(t *testing.T, id domain.RoleID) *iamv1.Role {
	t.Helper()
	uc := roleapp.NewListRolesUseCase(w.repo, w.snap).WithRelationStore(ccrAllowAll{})
	token := ""
	for page := 0; page < 50; page++ {
		got, next, err := uc.Execute(w.callerCtx(), reporole.ListFilter{
			AccountID: domain.AccountID(w.account), PageSize: 100, PageToken: token})
		require.NoError(t, err, "список ролей")
		for _, r := range got {
			if r.ID == id {
				return toPbRole(t, r)
			}
		}
		if next == "" {
			break
		}
		token = next
	}
	t.Fatalf("роли %s нет в списке аккаунта", id)
	return nil
}

// TestCCR02_RetiringAnUnnamedResourceEmitsNothing — IAM-CCR-02, близнец -03.
func TestCCR02_RetiringAnUnnamedResourceEmitsNothing(t *testing.T) {
	w := buildCCRWorld(t, "a", "b", "c", "d", "e", "f", "w", "p")
	mark := w.mark(t)
	rep, err := applierOver(t, w.pool).Apply(w.ctx, ccrOmegaSpare())
	require.NoError(t, err)
	t.Logf("перепись Ω-spare: %s", rep)
	require.Equal(t, 1, rep.RetiredResources, "снят ровно spare: %s", rep)
	require.Zero(t, rep.Resettled.RuleRefs)
	require.Zero(t, rep.Resettled.RoleVerbs)
	require.Zero(t, rep.PrunedSelectorTypes)
	_, total := w.roleEvents(t, mark)
	require.Zero(t, total, "IAM-CCR-02: снятие, не задевшее ролей, дало события")
}

// TestCCR04_RetiringOneActionOfALiveResource — IAM-CCR-04 и -16.
func TestCCR04_RetiringOneActionOfALiveResource(t *testing.T) {
	w := buildCCRWorld(t, "e", "f")
	mark := w.mark(t)
	rep, err := applierOver(t, w.pool).Apply(w.ctx, ccrOmegaUpdate())
	require.NoError(t, err)
	t.Logf("перепись Ω-update: %s", rep)
	require.NoError(t, w.snap.Refresh(w.ctx))
	require.Equal(t, 1, rep.Resettled.RuleRefs, "IAM-CCR-04: одно переселённое объявление: %s", rep)
	require.Zero(t, rep.Resettled.RoleVerbs, "IAM-CCR-04: выдачи действия не переселяются: %s", rep)

	byRole, total := w.roleEvents(t, mark)
	t.Logf("событий iam_role: %s · всего %d", w.eventCensus(byRole), total)
	require.Equal(t, []string{"UPDATED"}, byRole[w.roles["f"]], "IAM-CCR-04: у F ровно одно событие")
	require.Empty(t, byRole[w.roles["e"]], "IAM-CCR-04: у E событий нет")

	pf := w.read(t, w.snap, w.roles["f"])
	require.Len(t, pf.GetWithdrawnGrants(), 1, "IAM-CCR-04: ведомость F")
	g := pf.GetWithdrawnGrants()[0]
	require.Equal(t, applierProbeModule+".gadgets", g.GetObjectType())
	require.Equal(t, "update", g.GetVerb())
	require.Equal(t, iamv1.WithdrawnGrantSource_WITHDRAWN_GRANT_SOURCE_RULE_REFERENCE, g.GetSource())
	require.Equal(t, iamv1.WithdrawnGrantCause_WITHDRAWN_GRANT_CAUSE_CATALOG_RETIRED, g.GetCause())

	// IAM-CCR-16: превью F не сужено, выдачи целы, роль здорова.
	require.Equal(t, "[update] | [update delete*] | [delete*]", preview(pf), "IAM-CCR-16")
	require.Equal(t, []string{applierProbeModule + ".gadgets:delete", applierProbeModule + ".gadgets:update"},
		w.grants(t, w.roles["f"]), "IAM-CCR-16: выдачи F")
	require.Equal(t, iamv1.RoleHealth_ROLE_HEALTH_HEALTHY, pf.GetHealth(), "IAM-CCR-16")
}

// TestCCR05_RepeatedApplyEmitsNothing — IAM-CCR-05.
func TestCCR05_RepeatedApplyEmitsNothing(t *testing.T) {
	w := buildCCRWorld(t, "a")
	_, err := applierOver(t, w.pool).Apply(w.ctx, ccrOmegaWidgets())
	require.NoError(t, err)
	mark := w.mark(t)
	rep, err := applierOver(t, w.pool).Apply(w.ctx, ccrOmegaWidgets())
	require.NoError(t, err)
	require.False(t, rep.Changed(), "IAM-CCR-05: повтор изменил каталог: %s", rep)
	_, total := w.roleEvents(t, mark)
	require.Zero(t, total, "IAM-CCR-05: повтор применения дал события — шторм #73 вернулся")
}

// ccrVerbRequest — вход глагола: опора ДОСТАВКИ, подтверждение по текущему
// состоянию модуля и потолок переселённых выдач `verbs`.
func ccrVerbRequest(t *testing.T, w *ccrWorld, verbs int) modulecatalog.Request {
	t.Helper()
	m := ccrOmegaWidgets()
	anchor, err := modulecatalog.AnchorOfDelivery([]*manifest.Manifest{m})
	require.NoError(t, err)
	return modulecatalog.Request{
		Manifest:              m,
		ExpectedState:         moduleStateOf(t, w.ctx, w.pool, applierProbeModule),
		MaxResettledRuleRefs:  modulecatalog.Limit(generousCeiling),
		MaxResettledRoleVerbs: modulecatalog.Limit(verbs),
		Anchor:                anchor,
	}
}

// TestCCR07_RefusedAfterTheTakingLeavesNoEvent — IAM-CCR-07; близнец — -26.
func TestCCR07_RefusedAfterTheTakingLeavesNoEvent(t *testing.T) {
	w := buildCCRWorld(t, "a")
	a := w.roles["a"]
	before := stateFingerprint(t, w.ctx, w.pool)
	mark := w.mark(t)
	rep, err := verbApplierOver(t, w.pool).Apply(verbCallerCtx(w.ctx), ccrVerbRequest(t, w, 0))
	t.Logf("перепись (потолок выдач 0): %s · %v", rep, err)
	require.ErrorIs(t, err, modulecatalog.ErrResettleCeilingExceeded)
	require.Contains(t, err.Error(), "max_resettled_role_verbs")
	require.Positive(t, rep.Resettled.RoleVerbs, "отбор до отказа не прошёл — сценарий вакуумен")
	_, total := w.roleEvents(t, mark)
	require.Zero(t, total, "IAM-CCR-07: откаченное применение оставило событие")
	require.Equal(t, before, stateFingerprint(t, w.ctx, w.pool), "IAM-CCR-07: отпечаток состояния")
	require.Len(t, w.grants(t, a), 2, "IAM-CCR-07: выдачи A")
	require.Equal(t, 2, w.ledgerCount(t, `SELECT count(*) FROM kaname.role_rule_ref WHERE role_id = $1`, a))
	require.Equal(t, 2, w.ledgerCount(t, `SELECT count(*) FROM kaname.role_rule_selectors WHERE role_id = $1`, a))
}

// TestCCR26_VerbLaneCommitsAndEmits — IAM-CCR-26; близнец — -07.
func TestCCR26_VerbLaneCommitsAndEmits(t *testing.T) {
	w := buildCCRWorld(t, "a")
	a := w.roles["a"]
	before := stateFingerprint(t, w.ctx, w.pool)
	mark := w.mark(t)
	rep, err := verbApplierOver(t, w.pool).Apply(verbCallerCtx(w.ctx), ccrVerbRequest(t, w, generousCeiling))
	t.Logf("перепись (щедрый потолок): %s", rep)
	require.NoError(t, err, "IAM-CCR-26: полоса глагола со щедрым потолком обязана зафиксироваться")
	require.NotEqual(t, before, stateFingerprint(t, w.ctx, w.pool))
	require.Equal(t, []string{applierProbeModule + ".gadgets:list"}, w.grants(t, a))
	byRole, total := w.roleEvents(t, mark)
	t.Logf("событий iam_role всего %d", total)
	require.Equal(t, []string{"UPDATED"}, byRole[a], "IAM-CCR-26: у A на полосе глагола ровно одно событие")
}

// TestCCR11_RepeatedWithdrawalAfterRevivalEmitsAgain — IAM-CCR-11 и -23.
func TestCCR11_RepeatedWithdrawalAfterRevivalEmitsAgain(t *testing.T) {
	w := buildCCRWorld(t, "a")
	a := w.roles["a"]
	_, err := applierOver(t, w.pool).Apply(w.ctx, ccrOmegaWidgets())
	require.NoError(t, err)
	mark := w.mark(t)
	rev, err := applierOver(t, w.pool).Apply(w.ctx, ccrFull())
	require.NoError(t, err)
	require.Equal(t, 1, rev.WrittenResources, "widgets не ожил: %s", rev)
	require.NoError(t, w.snap.Refresh(w.ctx))

	// IAM-CCR-23: до переобъявления превью отобранного не обещает.
	pa := w.read(t, w.snap, a)
	require.Equal(t, "[list] | [list] | []", preview(pa), "IAM-CCR-23")
	require.Equal(t, iamv1.RuleLifecycle_RULE_LIFECYCLE_WITHDRAWN, pa.GetRuleStates()[0].GetState())
	require.Equal(t, []string{applierProbeModule + ".gadgets:list"}, w.grants(t, a))
	_, total := w.roleEvents(t, mark)
	require.Zero(t, total, "IAM-CCR-23: оживление дало событие")

	// Переобъявление теми же правилами.
	ops := operations.NewRepo(w.pool, "kaname")
	op, err := roleapp.NewUpdateRoleUseCase(w.repo, ops, w.snap).Execute(w.callerCtx(),
		roleapp.UpdateRoleInput{ID: a, Rules: ccrRoleRules("a"), UpdateMask: []string{"rules"}})
	require.NoError(t, err)
	require.Nil(t, awaitOperation(t, w.ctx, ops, op.ID).Error)
	require.Equal(t, "[get list] | [get list] | []", preview(w.read(t, w.snap, a)), "близнец -23: выдача вернулась")
	orphansBefore := w.ledgerCount(t, `SELECT count(*) FROM kaname.role_grant_orphan WHERE role_id = $1`, a)

	mark = w.mark(t)
	rep, err := applierOver(t, w.pool).Apply(w.ctx, ccrOmegaWidgets())
	require.NoError(t, err)
	t.Logf("перепись повторного отзыва: %s", rep)
	require.Equal(t, 1, rep.Resettled.RuleRefs)
	require.Equal(t, 1, rep.Resettled.RoleVerbs)
	require.Equal(t, orphansBefore, w.ledgerCount(t, `SELECT count(*) FROM kaname.role_grant_orphan WHERE role_id = $1`, a),
		"IAM-CCR-11: вставка на повторной паре обязана гаситься ключом ведомости")
	byRole, _ := w.roleEvents(t, mark)
	require.Equal(t, []string{"UPDATED"}, byRole[a], "IAM-CCR-11: повторный отзыв обязан дать событие снова")
}

// TestCCR21_JournalRefusalRollsTheApplyBack — IAM-CCR-21.
func TestCCR21_JournalRefusalRollsTheApplyBack(t *testing.T) {
	w := buildCCRWorld(t, "a")
	a := w.roles["a"]
	_, err := w.pool.Exec(w.ctx, `
		CREATE FUNCTION kaname.ccr21_refuse() RETURNS trigger LANGUAGE plpgsql AS $$
		BEGIN RAISE EXCEPTION 'ccr21: журнал отвергает событие роли'; END $$;
		CREATE TRIGGER ccr21_refuse_trg BEFORE INSERT ON kaname.resource_journal
		  FOR EACH ROW WHEN (NEW.resource_kind = 'iam_role') EXECUTE FUNCTION kaname.ccr21_refuse();`)
	require.NoError(t, err)
	t.Cleanup(func() {
		_, _ = w.pool.Exec(context.Background(), `
			DROP TRIGGER IF EXISTS ccr21_refuse_trg ON kaname.resource_journal;
			DROP FUNCTION IF EXISTS kaname.ccr21_refuse();`)
	})
	before := stateFingerprint(t, w.ctx, w.pool)
	_, err = applierOver(t, w.pool).Apply(w.ctx, ccrOmegaWidgets())
	require.Error(t, err, "IAM-CCR-21: применение прошло мимо отказа журнала")
	var pgErr *pgconn.PgError
	require.True(t, errors.As(err, &pgErr), "цепочка ошибки не доводит до отказа базы: %v", err)
	require.Equal(t, "P0001", pgErr.Code)
	require.Equal(t, before, stateFingerprint(t, w.ctx, w.pool), "IAM-CCR-21: отпечаток состояния")
	require.Equal(t, []string{applierProbeModule + ".gadgets:list", applierProbeModule + ".widgets:get"}, w.grants(t, a))
}

// TestCCR22_StaleSnapshotPromisesNothingTaken — IAM-CCR-22.
func TestCCR22_StaleSnapshotPromisesNothingTaken(t *testing.T) {
	w := buildCCRWorld(t, "a", "b", "v")
	halves, err := w.catRepo.ReadCatalogHalves(w.ctx)
	require.NoError(t, err)
	s0, err := catalog.NewSnapshot(halves, w.catRepo, nil, nil)
	require.NoError(t, err)
	_, err = applierOver(t, w.pool).Apply(w.ctx, ccrOmegaWidgets())
	require.NoError(t, err)

	require.Equal(t, "[list] | [list] | []", preview(w.read(t, s0, w.roles["a"])), "IAM-CCR-22: A через отставший снимок")
	require.Equal(t, "[get list] | [get list] | []", preview(w.read(t, s0, w.roles["b"])), "IAM-CCR-22: B")
	pv := w.read(t, s0, w.roles["v"])
	require.Equal(t, []string{"get", "list"}, pv.GetAuthoredVerbs(),
		"IAM-CCR-22: подстановка V развернулась набором ресурса с неудержанным якорем")
	require.Equal(t, []string{applierProbeModule + ".spare:get", applierProbeModule + ".spare:list"}, w.grants(t, w.roles["v"]))
	require.Equal(t, iamv1.RoleHealth_ROLE_HEALTH_DEGRADED, pv.GetHealth())
	require.EqualValues(t, 2, pv.GetDeclaredSegments())
	require.EqualValues(t, 1, pv.GetUnresolvedSegments())
}

// TestCCR25_TierVerbStaysOnALiveCatalog — IAM-CCR-25.
func TestCCR25_TierVerbStaysOnALiveCatalog(t *testing.T) {
	w := buildCCRWorld(t, "t", "u", "e")
	pt, pu, pe := w.read(t, w.snap, w.roles["t"]), w.read(t, w.snap, w.roles["u"]), w.read(t, w.snap, w.roles["e"])
	// Три утверждения превью — `assert`, а не `require`: форма, уносящая ярусный
	// глагол, обязана покраснеть у T И у U, и первое не вправе скрыть второе.
	assert.Equal(t, []string{"list", "create"}, pt.GetAuthoredVerbs(), "IAM-CCR-25: T")
	assert.Equal(t, []string{"create"}, pu.GetAuthoredVerbs(), "IAM-CCR-25: U")
	assert.Equal(t, []string{"list"}, pe.GetAuthoredVerbs(), "IAM-CCR-25: E")
	require.Equal(t, []string{applierProbeModule + ".gadgets:list"}, w.grants(t, w.roles["t"]))
	require.Empty(t, w.grants(t, w.roles["u"]))
	require.Equal(t, []string{applierProbeModule + ".gadgets:list"}, w.grants(t, w.roles["e"]))
	require.Equal(t, iamv1.RoleHealth_ROLE_HEALTH_DEGRADED, pt.GetHealth())
	require.Equal(t, iamv1.RoleHealth_ROLE_HEALTH_EMPTY, pu.GetHealth())
	require.Equal(t, iamv1.RoleHealth_ROLE_HEALTH_HEALTHY, pe.GetHealth())
}

// TestCCR09_RaceWithARulesEditDoesNotDeadlock — IAM-CCR-09.
func TestCCR09_RaceWithARulesEditDoesNotDeadlock(t *testing.T) {
	w := buildCCRWorld(t, "a")
	r := w.roles["a"]
	mark := w.mark(t)

	holder, err := w.pool.Begin(w.ctx)
	require.NoError(t, err)
	var once sync.Once
	release := func() { once.Do(func() { _ = holder.Rollback(context.Background()) }) }
	t.Cleanup(release)
	var held int
	require.NoError(t, holder.QueryRow(w.ctx, `
		SELECT count(*) FROM (SELECT 1 FROM kaname.catalog_verb
		 WHERE module = $1 AND resource = 'gadgets' AND verb = 'get' FOR UPDATE) s`, applierProbeModule).Scan(&held))
	require.Equal(t, 1, held, "ПРЕДПОСЫЛКА: строки действия gadgets.get нет")

	ares := make(chan error, 1)
	go func() {
		_, aerr := applierOver(t, w.pool).Apply(w.ctx, ccrOmegaWidgets())
		ares <- aerr
	}()
	w.awaitWaiters(t, 1, "применитель не встал на строке действия")

	bres := make(chan error, 1)
	go func() { bres <- w.tenantRulesEdit(r) }()
	w.awaitWaiters(t, 2, "сторона арендатора не встала на строке каталога")

	release()
	var aerr, berr error
	for i := 0; i < 2; i++ {
		select {
		case aerr = <-ares:
		case berr = <-bres:
		case <-time.After(60 * time.Second):
			t.Fatalf("сторона не завершилась: применитель=%v арендатор=%v", aerr, berr)
		}
	}
	require.Falsef(t, isDeadlock(aerr), "IAM-CCR-09: применитель отвергнут блокировкой: %v", aerr)
	require.Falsef(t, isDeadlock(berr), "IAM-CCR-09: правка роли отвергнута блокировкой: %v", berr)
	require.NoError(t, aerr)
	require.NoError(t, berr)
	byRole, _ := w.roleEvents(t, mark)
	require.Len(t, byRole[r], 2, "IAM-CCR-09: у R два события — правка арендатора и отбор применения: %v", byRole[r])
}

// awaitWaiters ждёт, пока НЕудовлетворённых замков станет n: взаимное
// ожидание утверждается состоянием базы, а не паузой.
func (w *ccrWorld) awaitWaiters(t *testing.T, n int, why string) {
	t.Helper()
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		var got int
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(DISTINCT pid) FROM pg_locks WHERE NOT granted`).Scan(&got))
		if got >= n {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("ПРЕДПОСЫЛКА: %s — ждущих сеансов меньше %d", why, n)
}

// tenantRulesEdit — правка правил роли в порядке исполнителя правки: запись
// строки роли под сторожем версии, затем проекция отбора.
func (w *ccrWorld) tenantRulesEdit(id domain.RoleID) error {
	ctx := w.ctx
	rd, err := w.repo.Reader(ctx)
	if err != nil {
		return err
	}
	role, ver, err := rd.Roles().GetWithVersion(ctx, id)
	_ = rd.Rollback(ctx)
	if err != nil {
		return err
	}
	wr, err := w.repo.Writer(ctx)
	if err != nil {
		return err
	}
	role.Rules = domain.Rules{{Module: applierProbeModule, Resources: []string{"gadgets"}, Verbs: []string{"get", "list"}}}
	upd, err := wr.RolesW().UpdateCAS(ctx, role, []string{"rules"}, ver)
	if err != nil {
		_ = wr.Rollback(ctx)
		return err
	}
	facts := w.snap.Facts()
	if err := wr.RolesW().ReplaceRuleSelectors(ctx, upd.ID,
		facts.GrantSelectors(upd.Rules.MaterializingSelectors(), domain.TenantPolicy())); err != nil {
		_ = wr.Rollback(ctx)
		return err
	}
	return wr.Commit(ctx)
}

// TestCCR_U1_RepeatMemoryLivesOneTransaction — условие У1 аудита поверхности:
// память о повторе живёт ровно одну транзакцию. Два применения подряд на пуле
// из ОДНОГО соединения, журнал между ними не чистится: у A — две строки.
// Законный близнец — повтор внутри одной транзакции: одна строка.
func TestCCR_U1_RepeatMemoryLivesOneTransaction(t *testing.T) {
	w := buildCCRWorld(t, "a")
	a := w.roles["a"]
	cfg, err := pgxpool.ParseConfig(w.pool.Config().ConnString())
	require.NoError(t, err)
	cfg.MaxConns = 1
	one, err := pgxpool.NewWithConfig(w.ctx, cfg)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, one)

	mark := w.mark(t)
	app := modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(one))
	_, err = app.Apply(w.ctx, ccrOmegaWidgets())
	require.NoError(t, err)
	_, err = app.Apply(w.ctx, probeManifest(probeResource("spare", "get", "list")))
	require.NoError(t, err)
	byRole, _ := w.roleEvents(t, mark)
	require.Equal(t, []string{"UPDATED", "UPDATED"}, byRole[a],
		"У1: второе применение на том же соединении осталось без события — память о повторе пережила транзакцию")

	// Близнец: повтор внутри ОДНОЙ транзакции.
	mark = w.mark(t)
	tx, err := one.Begin(w.ctx)
	require.NoError(t, err)
	for i := 0; i < 2; i++ {
		_, err = tx.Exec(w.ctx, `SELECT kaname.resource_journal_emit_role_composition($1::text[])`, []string{string(a), string(a)})
		require.NoError(t, err)
	}
	require.NoError(t, tx.Commit(w.ctx))
	byRole, _ = w.roleEvents(t, mark)
	require.Equal(t, []string{"UPDATED"}, byRole[a], "У1, близнец: повтор в одной транзакции обязан гаситься")
}

// TestCCR10_ModuleRoleRetirementEmitsOnce — IAM-CCR-10: снятие роли модулем
// строку роли уже пишет и событие уже даёт; производитель §3.1 второго не
// добавляет.
func TestCCR10_ModuleRoleRetirementEmitsOnce(t *testing.T) {
	if testing.Short() {
		t.Skip("integration: требует Postgres")
	}
	ctx, pool, applier := applierOnLiveBase(t)
	const goneID, stayID = "vpc.ccrgone.admin", "vpc.ccrstay.admin"
	gone := domain.SystemRoleID(domain.RoleName(goneID))
	_, err := applier.Apply(ctx, withdrawalManifest(t, "vpc", goneID, stayID), moduleroles.BootActorID)
	require.NoError(t, err)
	var mark int64
	require.NoError(t, pool.QueryRow(ctx, `SELECT COALESCE(max(sequence_no), 0) FROM kaname.resource_journal`).Scan(&mark))
	rep, err := applier.Apply(ctx, withdrawalManifest(t, "vpc", stayID), moduleroles.BootActorID)
	require.NoError(t, err)
	require.Equal(t, []string{goneID}, rep.RetiredNames)
	var orphans, events int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.role_grant_orphan WHERE role_id = $1 AND cause = 'role_retired'`, string(gone)).Scan(&orphans))
	require.NoError(t, pool.QueryRow(ctx, `
		SELECT count(*) FROM kaname.resource_journal
		 WHERE resource_kind = 'iam_role' AND resource_id = $1 AND sequence_no > $2`, string(gone), mark).Scan(&events))
	t.Logf("сирот причины role_retired %d · событий iam_role %d", orphans, events)
	require.Positive(t, orphans, "IAM-CCR-10: ведомость не несёт сироту снятия роли")
	require.Equal(t, 1, events, "IAM-CCR-10: у снятой роли ровно одно событие iam_role")
}

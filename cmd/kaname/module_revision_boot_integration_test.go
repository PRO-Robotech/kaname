// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// module_revision_boot_integration_test.go — ПОСЛЕДОВАТЕЛЬНОСТЬ СТАРТА над
// живой базой: редакция манифеста модуля только растёт (kaname#865, приёмка
// `docs/engineering/acceptance/module-manifest-revision-only-moves-forward.md`,
// сценарии 865-01 … 865-04, 865-07 … 865-09, 865-24).
//
// Держатель — корень старта, а не применитель: перепись, записи пропуска и
// отказа, перечень, поданный применителям ролей и посева, производит
// `applyDeliveredManifests`, и проба зовёт ровно его, а затем применитель
// ролей тем же перечнем, который корень подаёт ему в `serve.go` (что подаёт
// именно этот перечень — держит гейт `module_revision_filter_wiring_test.go`).
//
// Документы — фикстура P11 `probemod.public-read-fixture.yaml`, правленная
// фикстурами P14 (`publicreadfixture`), и собственный манифест службы с
// вписанной редакцией. Каждый документ разобран загрузчиком.

import (
	"bufio"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/pgtest"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/servicemanifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogstate"
	"github.com/PRO-Robotech/kaname/internal/testsupport/logbuf"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

const (
	bootRevisionModule   = "probemod"
	bootRevisionResource = "boxes"
	// bootCatalogCensusMsg / bootStaleMsg / bootConflictMsg / bootRolesCensusMsg —
	// записи журнала старта, которые проба читает (тексты Д7 и перепись P3).
	bootCatalogCensusMsg = "перепись применения каталога модуля"
	bootStaleMsg         = "применение каталога модуля: редакция старше применённой — модуль пропущен"
	bootConflictMsg      = "применение каталога модуля: редакция совпадает с применённой, содержимое другое — модуль не применён"
	bootRolesCensusMsg   = "перепись применения ролей модуля"
)

// bootDoc — документы общего «Дано» приёмки.
type bootDoc struct {
	t *testing.T
}

// r — R(n, open): фикстура P11 с редакцией n; n == 0 — без ключа `revision`.
func (d bootDoc) r(n int64, open bool) []byte {
	d.t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	require.NoError(d.t, err)
	if !open {
		doc, err = publicreadfixture.WithoutKey(doc)
		require.NoError(d.t, err)
	}
	if n > 0 {
		doc, err = publicreadfixture.WithRevision(doc, n)
		require.NoError(d.t, err)
	}
	return doc
}

// q — Q(n, open): R(n, open) с ролью `probemod.viewer`.
func (d bootDoc) q(n int64, open bool) []byte {
	d.t.Helper()
	doc, err := publicreadfixture.WithRoles(d.r(n, open), "viewer")
	require.NoError(d.t, err)
	return doc
}

// e — E(n, open): R(n, open) с объявленным пустым разделом `roles`.
func (d bootDoc) e(n int64, open bool) []byte {
	d.t.Helper()
	doc, err := publicreadfixture.WithEmptyRoles(d.r(n, open))
	require.NoError(d.t, err)
	return doc
}

// i — I(n): собственный манифест службы (модуль `iam`) с редакцией n.
func (d bootDoc) i(n int64) []byte {
	d.t.Helper()
	doc, err := publicreadfixture.WithRevision(servicemanifest.Raw(), n)
	require.NoError(d.t, err)
	return doc
}

// load — документ, разобранный загрузчиком.
func (d bootDoc) load(doc []byte) *manifest.Manifest {
	d.t.Helper()
	m, err := manifest.Load(doc)
	require.NoError(d.t, err)
	return m
}

// bootRevisionStand — база и журнал одной пробы.
type bootRevisionStand struct {
	t    *testing.T
	ctx  context.Context
	pool *pgxpool.Pool
	logs *logbuf.Buffer
	log  *slog.Logger
	doc  bootDoc
}

func newBootRevisionStand(t *testing.T) *bootRevisionStand {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, pgtest.WithSearchPath(pgtest.NewDB(t), "kaname,public"))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	buf := &logbuf.Buffer{}
	return &bootRevisionStand{
		t: t, ctx: ctx, pool: pool, logs: buf,
		log: slog.New(slog.NewJSONHandler(buf, &slog.HandlerOptions{Level: slog.LevelDebug})),
		doc: bootDoc{t: t},
	}
}

// start — один старт: каталог, затем роли тем перечнем, который вернул
// применитель каталога. Возвращает этот перечень (его же корень подаёт
// посеву) и исход применителя каталога.
func (s *bootRevisionStand) start(docs ...[]byte) ([]*manifest.Manifest, error) {
	s.t.Helper()
	delivered := make([]*manifest.Manifest, 0, len(docs))
	for _, d := range docs {
		delivered = append(delivered, s.doc.load(d))
	}
	applier := modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(s.pool))
	applied, err := applyDeliveredManifests(s.ctx, s.log, applier, delivered)
	if err != nil {
		return applied, err
	}

	live, lerr := kanamepg.NewCatalogRepo(s.pool).ReadLiveCatalog(s.ctx)
	require.NoError(s.t, lerr)
	reg, rerr := seed.LoadPermissionRegistry(s.ctx, s.log)
	require.NoError(s.t, rerr)
	rights, _, _, berr := buildModuleRoleRights(live, reg)
	require.NoError(s.t, berr)
	roles := moduleroles.NewApplier(moduleroles.NewRepoTxRunner(kanamepg.New(s.pool, nil)), rights)
	require.NoError(s.t, applyDeliveredModuleRoles(s.ctx, s.log, roles, applied),
		"применение ролей применённого перечня обязано пройти")
	return applied, nil
}

// records — записи журнала с текстом msg, в порядке появления.
func (s *bootRevisionStand) records(msg string) []map[string]any {
	s.t.Helper()
	var out []map[string]any
	sc := bufio.NewScanner(strings.NewReader(s.logs.String()))
	sc.Buffer(make([]byte, 0, 1<<16), 1<<22)
	for sc.Scan() {
		var rec map[string]any
		if json.Unmarshal(sc.Bytes(), &rec) != nil {
			continue
		}
		if rec["msg"] == msg {
			out = append(out, rec)
		}
	}
	return out
}

// last — последняя запись с текстом msg; её отсутствие — отказ пробы.
func (s *bootRevisionStand) last(msg string) map[string]any {
	s.t.Helper()
	recs := s.records(msg)
	require.NotEmpty(s.t, recs, "записи %q в журнале старта нет", msg)
	return recs[len(recs)-1]
}

// reset — журнал следующего старта читается с чистого листа.
func (s *bootRevisionStand) reset() { *s.logs = logbuf.Buffer{} }

func (s *bootRevisionStand) container() bool {
	return catalogstate.ContainerFlag(s.t, s.ctx, s.pool, bootRevisionModule, bootRevisionResource)
}

func (s *bootRevisionStand) appliedRevision(module string) *int64 {
	rev, _ := catalogstate.Applied(s.t, s.ctx, s.pool, module)
	return rev
}

func (s *bootRevisionStand) appliedDigest(module string) *string {
	_, d := catalogstate.Applied(s.t, s.ctx, s.pool, module)
	return d
}

func (s *bootRevisionStand) roleLive(name string) bool {
	s.t.Helper()
	var live bool
	require.NoError(s.t, s.pool.QueryRow(s.ctx,
		`SELECT live FROM kaname.roles WHERE name = $1 AND account_id IS NULL`, name).Scan(&live),
		"роль %s не найдена", name)
	return live
}

func modulesOf(ms []*manifest.Manifest) []string {
	out := make([]string, 0, len(ms))
	for _, m := range ms {
		out = append(out, m.Module)
	}
	return out
}

func num(t *testing.T, rec map[string]any, key string) int64 {
	t.Helper()
	v, ok := rec[key]
	require.True(t, ok, "поле %s в записи %v отсутствует", key, rec["msg"])
	f, ok := v.(float64)
	require.True(t, ok, "поле %s не число: %v", key, v)
	return int64(f)
}

func strs(t *testing.T, rec map[string]any, key string) []string {
	t.Helper()
	raw, ok := rec[key].([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(raw))
	for _, v := range raw {
		out = append(out, v.(string))
	}
	return out
}

func i64(n int64) *int64 { return &n }

// Test865_01_StaleRevisionIsSkippedAtBoot — обратный порядок на старте.
func Test865_01_StaleRevisionIsSkippedAtBoot(t *testing.T) {
	s := newBootRevisionStand(t)
	_, err := s.start(s.doc.r(5, true))
	require.NoError(t, err)
	s.reset()

	_, err = s.start(s.doc.r(3, false))
	require.NoError(t, err, "младшая редакция — не отказ применителя: applyDeliveredManifests возвращает nil")

	require.True(t, s.container(), "признак контейнера обязан остаться значением старшей редакции")
	require.Equal(t, i64(5), s.appliedRevision(bootRevisionModule))

	census := s.last(bootCatalogCensusMsg)
	require.EqualValues(t, 1, num(t, census, "delivered"))
	require.EqualValues(t, 0, num(t, census, "applied"))
	require.EqualValues(t, 1, num(t, census, "skipped_stale"))

	warn := s.last(bootStaleMsg)
	require.Equal(t, "WARN", warn["level"])
	require.Equal(t, bootRevisionModule, warn["module"])
	require.EqualValues(t, 3, num(t, warn, "delivered_revision"))
	require.EqualValues(t, 5, num(t, warn, "applied_revision"))
}

// Test865_02_NewerRevisionAppliesAtBoot — прямой порядок, близнец 865-01.
func Test865_02_NewerRevisionAppliesAtBoot(t *testing.T) {
	s := newBootRevisionStand(t)
	_, err := s.start(s.doc.r(3, false))
	require.NoError(t, err)
	s.reset()

	_, err = s.start(s.doc.r(5, true))
	require.NoError(t, err)
	require.True(t, s.container())
	require.Equal(t, i64(5), s.appliedRevision(bootRevisionModule))
	census := s.last(bootCatalogCensusMsg)
	require.EqualValues(t, 1, num(t, census, "applied"))
	require.EqualValues(t, 0, num(t, census, "skipped_stale"))
	require.Equal(t, true, census["changed"])
	require.Empty(t, s.records(bootStaleMsg))
}

// Test865_03_SameRevisionIsIdempotentAtBoot — та же редакция повторно.
func Test865_03_SameRevisionIsIdempotentAtBoot(t *testing.T) {
	s := newBootRevisionStand(t)
	_, err := s.start(s.doc.r(5, true))
	require.NoError(t, err)
	before := catalogstate.Fingerprint(t, s.ctx, s.pool)
	s.reset()

	_, err = s.start(s.doc.r(5, true))
	require.NoError(t, err)
	require.Equal(t, before, catalogstate.Fingerprint(t, s.ctx, s.pool))
	require.Equal(t, i64(5), s.appliedRevision(bootRevisionModule))
	census := s.last(bootCatalogCensusMsg)
	require.EqualValues(t, 1, num(t, census, "applied"))
	require.Equal(t, false, census["changed"])
	require.EqualValues(t, 0, num(t, census, "skipped_stale"))
}

// Test865_04_RollbackIsANewerRevision — откат новой редакцией, близнец 865-01
// по номеру.
func Test865_04_RollbackIsANewerRevision(t *testing.T) {
	s := newBootRevisionStand(t)
	_, err := s.start(s.doc.r(5, true))
	require.NoError(t, err)
	s.reset()

	_, err = s.start(s.doc.r(6, false))
	require.NoError(t, err)
	require.False(t, s.container())
	require.Equal(t, i64(6), s.appliedRevision(bootRevisionModule))
	census := s.last(bootCatalogCensusMsg)
	require.EqualValues(t, 1, num(t, census, "applied"))
	require.EqualValues(t, 0, num(t, census, "skipped_stale"))
	require.Equal(t, true, census["changed"])
}

// Test865_07_RolesAndSeedDoNotGetTheSkippedModule — пропущенный модуль не
// получают ни роли, ни посев; младшая первой в доставке не останавливает
// второй модуль.
func Test865_07_RolesAndSeedDoNotGetTheSkippedModule(t *testing.T) {
	s := newBootRevisionStand(t)
	_, err := s.start(s.doc.q(5, true))
	require.NoError(t, err)
	require.True(t, s.roleLive(publicreadfixture.ViewerRoleID), "Дано: роль живая после применения Q(5, true)")
	s.reset()

	applied, err := s.start(s.doc.e(3, false), s.doc.i(1))
	require.NoError(t, err)

	require.True(t, s.roleLive(publicreadfixture.ViewerRoleID), "пропущенный модуль не снимает своих ролей")
	roles := s.last(bootRolesCensusMsg)
	require.EqualValues(t, 1, num(t, roles, "delivered"))
	require.NotContains(t, strs(t, roles, "modules"), bootRevisionModule)
	require.Equal(t, []string{"iam"}, modulesOf(applied), "перечень, поданный корнем посеву")

	census := s.last(bootCatalogCensusMsg)
	require.EqualValues(t, 2, num(t, census, "delivered"))
	require.EqualValues(t, 1, num(t, census, "applied"))
	require.EqualValues(t, 1, num(t, census, "skipped_stale"))
	require.EqualValues(t, 0, num(t, census, "refused_conflict"))
	require.Equal(t, []string{"iam"}, strs(t, census, "modules"))
}

// Test865_08_CensusAddsUp — близнец 865-07 по номеру: перепись складывается.
func Test865_08_CensusAddsUp(t *testing.T) {
	s := newBootRevisionStand(t)
	_, err := s.start(s.doc.q(5, true))
	require.NoError(t, err)
	require.True(t, s.roleLive(publicreadfixture.ViewerRoleID))
	s.reset()

	applied, err := s.start(s.doc.e(6, false), s.doc.i(1))
	require.NoError(t, err)

	require.False(t, s.roleLive(publicreadfixture.ViewerRoleID),
		"раздел roles объявлен и пуст — применитель ролей снимает роль")
	census := s.last(bootCatalogCensusMsg)
	require.EqualValues(t, 2, num(t, census, "delivered"))
	require.EqualValues(t, 2, num(t, census, "applied"))
	require.EqualValues(t, 0, num(t, census, "skipped_stale"))
	require.EqualValues(t, 0, num(t, census, "refused_conflict"))
	require.Equal(t, []string{bootRevisionModule, "iam"}, strs(t, census, "modules"))
	require.Equal(t, []string{bootRevisionModule, "iam"}, modulesOf(applied))
	_, hasElapsed := census["elapsed"]
	require.True(t, hasElapsed, "перепись несёт длительность применения (Д8)")
	t.Logf("длительность применения каталога (Д8): %v нс", census["elapsed"])
	require.Equal(t,
		num(t, census, "delivered"),
		num(t, census, "applied")+num(t, census, "skipped_stale")+num(t, census, "refused_conflict"))
}

// Test865_09_UndeclaredRevisionIsOlderThanAny — ключ не объявлен (только S1).
func Test865_09_UndeclaredRevisionIsOlderThanAny(t *testing.T) {
	s := newBootRevisionStand(t)
	_, err := s.start(s.doc.r(5, true))
	require.NoError(t, err)
	s.reset()

	_, err = s.start(s.doc.r(0, false))
	require.NoError(t, err)
	require.True(t, s.container())
	require.Equal(t, i64(5), s.appliedRevision(bootRevisionModule))
	warn := s.last(bootStaleMsg)
	_, has := warn["delivered_revision"]
	require.False(t, has, "номера нет — поле опускается, а не пишется нулём (CE-12)")
	require.EqualValues(t, 5, num(t, warn, "applied_revision"))

	t.Run("близнец: модуль без применённой редакции", func(t *testing.T) {
		s := newBootRevisionStand(t)
		_, err := s.start(s.doc.r(0, false))
		require.NoError(t, err)
		require.False(t, s.container())
		require.Nil(t, s.appliedRevision(bootRevisionModule))
		require.EqualValues(t, 0, num(t, s.last(bootCatalogCensusMsg), "skipped_stale"))
	})
}

// Test865_24_EqualRevisionOtherContentIsRefusedAtBoot — равный номер, иное
// содержимое на старте.
func Test865_24_EqualRevisionOtherContentIsRefusedAtBoot(t *testing.T) {
	s := newBootRevisionStand(t)
	q5 := s.doc.q(5, true)
	_, err := s.start(q5)
	require.NoError(t, err)
	require.True(t, s.roleLive(publicreadfixture.ViewerRoleID))
	traces := catalogstate.AppliedTraces(t, s.ctx, s.pool, modulecatalog.AppliedEventType, bootRevisionModule)
	s.reset()

	e5 := s.doc.e(5, false)
	applied, err := s.start(e5, s.doc.i(1))
	require.NoError(t, err, "конфликт содержимого — не отказ применителя: applyDeliveredManifests возвращает nil")

	dQ, dE := s.doc.load(q5).Digest(), s.doc.load(e5).Digest()
	require.True(t, s.container())
	require.Equal(t, i64(5), s.appliedRevision(bootRevisionModule))
	require.Equal(t, &dQ, s.appliedDigest(bootRevisionModule))
	require.True(t, s.roleLive(publicreadfixture.ViewerRoleID))
	require.Equal(t, []string{"iam"}, modulesOf(applied))

	census := s.last(bootCatalogCensusMsg)
	require.EqualValues(t, 2, num(t, census, "delivered"))
	require.EqualValues(t, 1, num(t, census, "applied"))
	require.EqualValues(t, 0, num(t, census, "skipped_stale"))
	require.EqualValues(t, 1, num(t, census, "refused_conflict"))
	require.Equal(t, []string{"iam"}, strs(t, census, "modules"))

	rec := s.last(bootConflictMsg)
	require.Equal(t, "ERROR", rec["level"])
	require.Equal(t, bootRevisionModule, rec["module"])
	require.EqualValues(t, 5, num(t, rec, "delivered_revision"))
	require.Equal(t, dE, rec["delivered_digest"])
	require.EqualValues(t, 5, num(t, rec, "applied_revision"))
	require.Equal(t, dQ, rec["applied_digest"])
	require.Equal(t, traces,
		catalogstate.AppliedTraces(t, s.ctx, s.pool, modulecatalog.AppliedEventType, bootRevisionModule),
		"отвергнутое применение следа не оставляет")

	t.Run("близнец: побайтово тот же документ", func(t *testing.T) {
		s.reset()
		applied, err := s.start(q5, s.doc.i(1))
		require.NoError(t, err)
		census := s.last(bootCatalogCensusMsg)
		require.EqualValues(t, 2, num(t, census, "applied"))
		require.EqualValues(t, 0, num(t, census, "refused_conflict"))
		require.Equal(t, false, census["changed"])
		require.True(t, s.roleLive(publicreadfixture.ViewerRoleID))
		require.Equal(t, []string{bootRevisionModule, "iam"}, modulesOf(applied))
		require.Empty(t, s.records(bootConflictMsg))
	})
}

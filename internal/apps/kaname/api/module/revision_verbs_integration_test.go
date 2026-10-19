// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package module_test

// revision_verbs_integration_test.go — глаголы `InternalModuleService` над
// живой Postgres: редакция манифеста модуля только растёт (kaname#865, приёмка
// `docs/engineering/acceptance/module-manifest-revision-only-moves-forward.md`,
// сценарии 865-11 … 865-16, 865-19, 865-27 … 865-29, 865-32).
//
// Держатель — use-case глагола с гейтом права, как у существующих глаголов
// (вызывающий держит `system_admin` на `cluster`), над адаптерами базы, которые
// провязывает композиционный корень. Пробы утверждают gRPC-код, значение и
// присутствие поля (§2 п.8 приёмки): присутствие — указатель порождённого поля
// не `nil`.

import (
	"context"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	moduleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/module"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogstate"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

const (
	verbRevModule   = "probemod"
	verbRevResource = "boxes"
)

// fixedDelivery — доставка, которую глаголы перечитывают: ровно поданные
// документы.
type fixedDelivery struct{ manifests []*manifest.Manifest }

func (d *fixedDelivery) Read(context.Context) (moduleapp.Delivery, error) {
	return moduleapp.Delivery{Declared: true, ManifestsRead: len(d.manifests), Manifests: d.manifests}, nil
}

// verbStand — база, адаптеры и глаголы одной пробы.
type verbStand struct {
	t        *testing.T
	ctx      context.Context
	pool     *pgxpool.Pool
	delivery *fixedDelivery
	ops      operations.FullRepo
	plan     *moduleapp.PlanUseCase
	apply    *moduleapp.ApplyUseCase
	get      *moduleapp.GetUseCase
}

func newVerbStand(t *testing.T) *verbStand {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := ctxAsUser(probeUser)
	pool, err := coredb.NewPool(context.Background(), pgtest.WithSearchPath(pgtest.NewDB(t), "kaname,public"))
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)

	allow := &fakeRelationChecker{allow: true}
	delivery := &fixedDelivery{}
	rows := kanamepg.NewCatalogRepo(pool)
	ops := shared.NewTerminalRefusalRepo(operations.NewRepo(pool, "kaname"))
	return &verbStand{
		t: t, ctx: ctx, pool: pool, delivery: delivery, ops: ops,
		plan: moduleapp.NewPlanUseCase(delivery, rows, kanamepg.NewCatalogPlanRepo(pool)).
			WithAdminChecker(allow),
		apply: moduleapp.NewApplyUseCase(delivery,
			modulecatalog.NewVerbApplier(kanamepg.NewCatalogWriteRepo(pool)), ops, nil).
			WithAdminChecker(allow),
		get: moduleapp.NewGetUseCase(rows, rows).WithAdminChecker(allow),
	}
}

// r — R(n, open); n == 0 — без ключа `revision`.
func (s *verbStand) r(n int64, open bool) []byte {
	s.t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	require.NoError(s.t, err)
	if !open {
		doc, err = publicreadfixture.WithoutKey(doc)
		require.NoError(s.t, err)
	}
	if n > 0 {
		doc, err = publicreadfixture.WithRevision(doc, n)
		require.NoError(s.t, err)
	}
	return doc
}

// q — Q(n, open, t): R(n, open) с ролью, описание которой — текст t как есть.
func (s *verbStand) q(n int64, open bool, desc string) []byte {
	s.t.Helper()
	doc, err := publicreadfixture.WithRoles(s.r(n, open), desc)
	require.NoError(s.t, err)
	return doc
}

func (s *verbStand) load(doc []byte) *manifest.Manifest {
	s.t.Helper()
	m, err := manifest.Load(doc)
	require.NoError(s.t, err)
	return m
}

// applied — «Дано применён x»: путь старта, как его применяет корень.
func (s *verbStand) applied(doc []byte) *manifest.Manifest {
	s.t.Helper()
	m := s.load(doc)
	_, err := modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(s.pool)).Apply(context.Background(), m)
	require.NoError(s.t, err)
	return m
}

// deliver — доставка несёт ровно этот документ.
func (s *verbStand) deliver(doc []byte) *manifest.Manifest {
	s.t.Helper()
	m := s.load(doc)
	s.delivery.manifests = []*manifest.Manifest{m}
	return m
}

func (s *verbStand) planOf() *iamv1.PlanModuleResponse {
	s.t.Helper()
	resp, err := s.plan.Execute(s.ctx, verbRevModule)
	require.NoError(s.t, err)
	return resp
}

func (s *verbStand) applyWith(expected string) (*iamv1.ApplyModuleResponse, error) {
	s.t.Helper()
	zero := int32(0)
	op, err := s.apply.Execute(s.ctx, verbRevModule, expected, &zero, &zero)
	if err != nil {
		return nil, err
	}
	require.True(s.t, op.GetDone())
	require.Nil(s.t, op.GetError())
	var resp iamv1.ApplyModuleResponse
	require.NoError(s.t, op.GetResponse().UnmarshalTo(&resp))
	return &resp, nil
}

// lastOperationError — строка операции последнего `Apply` и её ошибка.
func (s *verbStand) lastOperationError() *status.Status {
	s.t.Helper()
	var id string
	require.NoError(s.t, s.pool.QueryRow(context.Background(), `
		SELECT id FROM kaname.operations
		 WHERE description = 'Apply permission-module catalog of probemod'
		 ORDER BY created_at DESC LIMIT 1`).Scan(&id), "строка операции Apply не найдена")
	op, err := s.ops.Get(context.Background(), id)
	require.NoError(s.t, err)
	require.True(s.t, op.Done)
	require.NotNil(s.t, op.Error, "операция не помечена ошибкой")
	return status.FromProto(op.Error)
}

func (s *verbStand) fingerprint() string {
	return catalogstate.Fingerprint(s.t, context.Background(), s.pool)
}

func (s *verbStand) traces() int {
	return catalogstate.AppliedTraces(s.t, context.Background(), s.pool, modulecatalog.AppliedEventType, verbRevModule)
}

func (s *verbStand) container() bool {
	return catalogstate.ContainerFlag(s.t, context.Background(), s.pool, verbRevModule, verbRevResource)
}

func (s *verbStand) appliedPair() (*int64, *string) {
	return catalogstate.Applied(s.t, context.Background(), s.pool, verbRevModule)
}

func p64(n int64) *int64 { return &n }

func pstr(v string) *string { return &v }

// Test865_11_PlanOfAStaleRevision — `Plan` младшей редакции.
func Test865_11_PlanOfAStaleRevision(t *testing.T) {
	s := newVerbStand(t)
	s.applied(s.r(5, true))
	s.deliver(s.r(3, false))
	before, traces := s.fingerprint(), s.traces()

	resp := s.planOf()
	require.Equal(t, iamv1.ModulePlanVerdict_MODULE_PLAN_VERDICT_WOULD_BE_REFUSED_STALE_REVISION, resp.GetVerdict())
	require.Equal(t, p64(3), resp.ManifestRevision)
	require.Equal(t, p64(5), resp.AppliedRevision)
	require.Equal(t, before, s.fingerprint())
	require.Equal(t, traces, s.traces())
}

// Test865_12_PlanOfANewerRevision — близнец 865-11.
func Test865_12_PlanOfANewerRevision(t *testing.T) {
	s := newVerbStand(t)
	s.applied(s.r(5, true))
	s.deliver(s.r(6, false))
	resp := s.planOf()
	require.Equal(t, iamv1.ModulePlanVerdict_MODULE_PLAN_VERDICT_WOULD_APPLY, resp.GetVerdict())
	require.Equal(t, p64(6), resp.ManifestRevision)
	require.Equal(t, p64(5), resp.AppliedRevision)
}

// Test865_13_ApplyOfAStaleRevisionIsRefused — `Apply` младшей редакции.
func Test865_13_ApplyOfAStaleRevisionIsRefused(t *testing.T) {
	s := newVerbStand(t)
	s.applied(s.r(5, true))
	s.deliver(s.r(3, false))
	expected := s.planOf().GetExpectedState()
	before, traces := s.fingerprint(), s.traces()

	_, err := s.applyWith(expected)
	st, _ := status.FromError(err)
	require.Equal(t, codes.FailedPrecondition, st.Code(), "%v", err)
	const want = "модуль probemod: редакция манифеста 3 старше применённой 5; откат выражается новой редакцией больше 5"
	require.Equal(t, want, st.Message())
	require.True(t, s.container())
	rev, _ := s.appliedPair()
	require.Equal(t, p64(5), rev)
	require.Equal(t, before, s.fingerprint())
	require.Equal(t, traces, s.traces())
	opErr := s.lastOperationError()
	require.Equal(t, codes.FailedPrecondition, opErr.Code())
	require.Equal(t, want, opErr.Message())
}

// Test865_14_ApplyOfANewerRevision — близнец 865-13.
func Test865_14_ApplyOfANewerRevision(t *testing.T) {
	s := newVerbStand(t)
	s.applied(s.r(5, true))
	s.deliver(s.r(6, false))
	resp, err := s.applyWith(s.planOf().GetExpectedState())
	require.NoError(t, err)
	require.Equal(t, p64(6), resp.AppliedRevision)
	require.Equal(t, p64(5), resp.PreviousAppliedRevision)
	require.True(t, resp.GetChanged())
	require.False(t, s.container())
}

// Test865_15_ApplyOfTheSameRevision — равная редакция.
func Test865_15_ApplyOfTheSameRevision(t *testing.T) {
	s := newVerbStand(t)
	m := s.applied(s.r(5, true))
	s.deliver(s.r(5, true))
	resp, err := s.applyWith(s.planOf().GetExpectedState())
	require.NoError(t, err)
	require.Equal(t, p64(5), resp.AppliedRevision)
	require.Equal(t, p64(5), resp.PreviousAppliedRevision)
	require.False(t, resp.GetChanged())
	require.Equal(t, pstr(m.Digest()), resp.AppliedDigest)
}

// Test865_16_GetShowsTheAppliedRevision — `Get` показывает применённую
// редакцию; близнец — модуль без применённой редакции, поля нет.
func Test865_16_GetShowsTheAppliedRevision(t *testing.T) {
	s := newVerbStand(t)
	got, err := s.get.Execute(s.ctx, "iam")
	require.NoError(t, err)
	require.Nil(t, got.AppliedRevision, "близнец: применений не было — поля нет")

	s.applied(s.r(5, true))
	got, err = s.get.Execute(s.ctx, verbRevModule)
	require.NoError(t, err)
	require.Equal(t, p64(5), got.AppliedRevision)
}

// Test865_19_ApplyWithoutRevisionOverAnAppliedOne — ключ не объявлен (S1).
func Test865_19_ApplyWithoutRevisionOverAnAppliedOne(t *testing.T) {
	s := newVerbStand(t)
	s.applied(s.r(5, true))
	s.deliver(s.r(0, true))
	plan := s.planOf()
	require.Equal(t, iamv1.ModulePlanVerdict_MODULE_PLAN_VERDICT_WOULD_BE_REFUSED_STALE_REVISION, plan.GetVerdict())
	require.Nil(t, plan.ManifestRevision)
	require.Equal(t, p64(5), plan.AppliedRevision)
	before := s.fingerprint()

	_, err := s.applyWith(plan.GetExpectedState())
	st, _ := status.FromError(err)
	require.Equal(t, codes.FailedPrecondition, st.Code(), "%v", err)
	require.Equal(t,
		"модуль probemod: манифест не объявляет редакцию, а применена редакция 5; применяется только редакция не меньше 5",
		st.Message())
	require.Equal(t, before, s.fingerprint())

	t.Run("близнец: модуль без применённой редакции", func(t *testing.T) {
		s := newVerbStand(t)
		s.deliver(s.r(0, true))
		resp, err := s.applyWith(s.planOf().GetExpectedState())
		require.NoError(t, err)
		require.Nil(t, resp.AppliedRevision)
	})
}

// Test865_27_PlanOfAContentConflict — `Plan` при конфликте содержимого.
func Test865_27_PlanOfAContentConflict(t *testing.T) {
	s := newVerbStand(t)
	open := s.applied(s.r(5, true))
	closed := s.deliver(s.r(5, false))
	before, traces := s.fingerprint(), s.traces()

	resp := s.planOf()
	require.Equal(t, iamv1.ModulePlanVerdict_MODULE_PLAN_VERDICT_WOULD_BE_REFUSED_REVISION_CONFLICT, resp.GetVerdict())
	require.Equal(t, p64(5), resp.ManifestRevision)
	require.Equal(t, p64(5), resp.AppliedRevision)
	require.Equal(t, pstr(closed.Digest()), resp.ManifestDigest)
	require.Equal(t, pstr(open.Digest()), resp.AppliedDigest)
	require.Equal(t, before, s.fingerprint())
	require.Equal(t, traces, s.traces())

	t.Run("близнец: доставка несёт тот же документ", func(t *testing.T) {
		s.deliver(s.r(5, true))
		resp := s.planOf()
		require.Equal(t, iamv1.ModulePlanVerdict_MODULE_PLAN_VERDICT_WOULD_APPLY, resp.GetVerdict())
		require.Equal(t, pstr(open.Digest()), resp.ManifestDigest)
		require.Equal(t, pstr(open.Digest()), resp.AppliedDigest)
	})
}

// Test865_28_ApplyOfAContentConflictIsRefused — `Apply` при конфликте
// содержимого.
func Test865_28_ApplyOfAContentConflictIsRefused(t *testing.T) {
	s := newVerbStand(t)
	open := s.applied(s.r(5, true))
	closed := s.deliver(s.r(5, false))
	expected := s.planOf().GetExpectedState()
	before, traces := s.fingerprint(), s.traces()

	_, err := s.applyWith(expected)
	st, _ := status.FromError(err)
	require.Equal(t, codes.FailedPrecondition, st.Code(), "%v", err)
	want := "модуль probemod: редакция манифеста 5 уже применена с другим содержимым (отпечаток манифеста " +
		closed.Digest() + ", применённый " + open.Digest() + "); изменение содержимого выражается новой редакцией больше 5"
	require.Equal(t, want, st.Message())
	require.True(t, s.container())
	rev, digest := s.appliedPair()
	require.Equal(t, p64(5), rev)
	require.Equal(t, pstr(open.Digest()), digest)
	require.Equal(t, before, s.fingerprint())
	require.Equal(t, traces, s.traces())
	opErr := s.lastOperationError()
	require.Equal(t, codes.FailedPrecondition, opErr.Code())
	require.Equal(t, want, opErr.Message())
}

// Test865_29_DigestIsWrittenWithTheRevision — отпечаток пишется вместе с
// номером и не меняется на пропуске.
func Test865_29_DigestIsWrittenWithTheRevision(t *testing.T) {
	s := newVerbStand(t)
	var seededEmpty int
	require.NoError(t, s.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM kaname.catalog_module
		 WHERE module IN ('iam', 'vpc', 'compute', 'loadbalancer', 'registry', 'storage')
		   AND applied_revision IS NULL AND applied_digest IS NULL`).Scan(&seededEmpty))
	require.Equal(t, 6, seededEmpty)
	got, err := s.get.Execute(s.ctx, "iam")
	require.NoError(t, err)
	require.Nil(t, got.AppliedRevision, "близнец присутствия: полей нет")
	require.Nil(t, got.AppliedDigest, "близнец присутствия: полей нет")

	r5 := s.applied(s.r(5, true))
	_, digest := s.appliedPair()
	require.Equal(t, pstr(r5.Digest()), digest)
	got, err = s.get.Execute(s.ctx, verbRevModule)
	require.NoError(t, err)
	require.Equal(t, p64(5), got.AppliedRevision)
	require.Equal(t, pstr(r5.Digest()), got.AppliedDigest)

	s.applied(s.r(3, false))
	_, digest = s.appliedPair()
	require.Equal(t, pstr(r5.Digest()), digest, "младшая редакция отпечатка не трогает")

	r6 := s.deliver(s.r(6, false))
	resp, err := s.applyWith(s.planOf().GetExpectedState())
	require.NoError(t, err)
	require.Equal(t, p64(6), resp.AppliedRevision)
	require.Equal(t, pstr(r6.Digest()), resp.AppliedDigest)
	_, digest = s.appliedPair()
	require.Equal(t, pstr(r6.Digest()), digest)

	t.Run("близнец: документ без ключа над модулем без пары", func(t *testing.T) {
		s := newVerbStand(t)
		s.applied(s.r(0, true))
		rev, digest := s.appliedPair()
		require.Nil(t, rev)
		require.Nil(t, digest)
	})
}

// Test865_32_OtherTextOfANumericScalarIsAConflict — та же редакция, иной текст
// числового скаляра в строковом поле — конфликт; иная запись — повтор.
func Test865_32_OtherTextOfANumericScalarIsAConflict(t *testing.T) {
	s := newVerbStand(t)
	q16 := s.applied(s.q(5, true, "16"))
	q0x := s.deliver(s.q(5, true, "0x10"))
	require.Equal(t, "16", q16.Roles[0].Description)
	require.Equal(t, "0x10", q0x.Roles[0].Description)

	plan := s.planOf()
	require.Equal(t, iamv1.ModulePlanVerdict_MODULE_PLAN_VERDICT_WOULD_BE_REFUSED_REVISION_CONFLICT, plan.GetVerdict())
	require.Equal(t, pstr(q0x.Digest()), plan.ManifestDigest)
	require.Equal(t, pstr(q16.Digest()), plan.AppliedDigest)
	require.NotEqual(t, q16.Digest(), q0x.Digest())
	before := s.fingerprint()

	_, err := s.applyWith(plan.GetExpectedState())
	st, _ := status.FromError(err)
	require.Equal(t, codes.FailedPrecondition, st.Code(), "%v", err)
	require.Equal(t, "модуль probemod: редакция манифеста 5 уже применена с другим содержимым (отпечаток манифеста "+
		q0x.Digest()+", применённый "+q16.Digest()+"); изменение содержимого выражается новой редакцией больше 5",
		st.Message())
	_, digest := s.appliedPair()
	require.Equal(t, pstr(q16.Digest()), digest)
	require.Equal(t, before, s.fingerprint())

	t.Run("близнец: иная запись того же документа", func(t *testing.T) {
		ref, err := publicreadfixture.Reformatted(s.q(5, true, "16"))
		require.NoError(t, err)
		s.deliver(ref)
		plan := s.planOf()
		require.Equal(t, iamv1.ModulePlanVerdict_MODULE_PLAN_VERDICT_WOULD_APPLY, plan.GetVerdict())
		require.Equal(t, pstr(q16.Digest()), plan.ManifestDigest)
		require.Equal(t, pstr(q16.Digest()), plan.AppliedDigest)
		resp, err := s.applyWith(plan.GetExpectedState())
		require.NoError(t, err)
		require.False(t, resp.GetChanged())
	})
}

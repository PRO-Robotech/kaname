// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// reconcile_ledger_revoke_edges_integration_test.go — края снятия по реестру выдачи
// (kaname#933): набор снятия берётся из реестра, а не из снимка каталога процесса.
// Здесь три края того же предмета, которых проба reconcile_expiry_from_ledger не судит.
//
//  1. МНОГОСУБЪЕКТНАЯ выдача: истечение на реплике без типа снимает кортежи КАЖДОГО
//     субъекта, а не только первого.
//  2. ОШИБКА ЧТЕНИЯ реестра откатывает проход целиком: выдача остаётся действующей,
//     члены, реестр и прямые факты — на месте; проход повторим.
//  3. СОВПАДЕНИЕ СУФФИКСА `:<id>` у объектов разных типов одной выдачи: снятие члена
//     типа, которого нет в снимке реплики (объект ушёл из зеркала — kaname#937), не
//     снимает кортежей объекта ДРУГОГО типа с тем же идентификатором.
//
// У каждой пробы — законный близнец, отличный ровно одним фактом.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/timestamppb"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// insertThinBindingSubjects — insertThinBinding с перечнем субъектов: выдача
// all_in_scope на проект, субъекты — пользователи в порядке перечня.
func insertThinBindingSubjects(t *testing.T, ctx context.Context, repo *kanamepg.Repository, subjects []domain.UserID, roleID domain.RoleID, prj domain.ProjectID) domain.AccessBindingID {
	t.Helper()
	require.NotEmpty(t, subjects, "ПРЕДПОСЫЛКА: перечень субъектов не пуст")
	subs := make([]domain.Subject, 0, len(subjects))
	for _, u := range subjects {
		subs = append(subs, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(u)})
	}
	bid := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = w.Rollback(ctx) }()
	_, err = bindingset.Insert(ctx, w.AccessBindingsW(), domain.AccessBinding{
		ID: bid, SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(subjects[0]),
		Subjects: subs, RoleID: roleID, ResourceType: "project", ResourceID: string(prj),
		Scope: domain.ScopeProject, Status: domain.AccessBindingStatusActive,
	})
	require.NoError(t, err)
	require.NoError(t, w.Commit(ctx))
	return bid
}

// registerUnderProject — цепь предков объекта тем же входом, каким её пишет продукт.
func registerUnderProject(t *testing.T, ctx context.Context, pool *pgxpool.Pool, fx gammaFixture, fgaObject string) {
	t.Helper()
	require.NoError(t, newRegisterUCWired(pool).Register(ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:" + string(fx.prj), Relation: "parent", Object: fgaObject,
		ParentProjectId: string(fx.prj), ParentAccountId: string(fx.accID),
		SourceVersion: timestamppb.New(time.Now().Add(time.Minute)),
	}))
}

func ledgerRowsOn(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bid domain.AccessBindingID, object string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1 AND object = $2`,
		string(bid), object).Scan(&n))
	return n
}

func factsOn(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subj, objType, objID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.relation_fact WHERE object_type = $1 AND object_id = $2 AND subject = $3`,
		objType, objID, subj).Scan(&n))
	return n
}

func memberStatusOn(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bid domain.AccessBindingID, objType, objID string) (string, bool) {
	t.Helper()
	var st string
	err := pool.QueryRow(ctx,
		`SELECT verification_status FROM kaname.access_binding_target_members
		  WHERE binding_id = $1 AND object_type = $2 AND object_id = $3`,
		string(bid), objType, objID).Scan(&st)
	if err != nil {
		return "", false
	}
	return st, true
}

func distinctLedgerSubjects(t *testing.T, ctx context.Context, pool *pgxpool.Pool, bid domain.AccessBindingID) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(DISTINCT fga_user) FROM kaname.access_binding_emitted_tuples WHERE binding_id = $1`,
		string(bid)).Scan(&n))
	return n
}

// ── 1. Многосубъектное истечение ────────────────────────────────────────────

type multiSubjectProbe struct {
	pool  *pgxpool.Pool
	bid   domain.AccessBindingID
	subjs []string
	a, b  *reconcile.Reconciler
}

// newMultiSubjectProbe — выдача ДВУМ пользователям материализована репликой A: у
// каждого субъекта прямой факт на объекте и свои строки реестра.
func newMultiSubjectProbe(t *testing.T, suffix string) *multiSubjectProbe {
	t.Helper()
	skipShort(t)
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	fx := setupGamma(t, ctx, pool, suffix)
	second := mustSeedUser(t, ctx, pool, "gsecond"+suffix)
	a, adapter := newReconciler(pool)
	b := reconcile.New(adapter, nil, catalogWithout(t, ledgerProbeType, false))
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, suffix+"role", domain.Rules{forwardAnchorRule()})
	bid := insertThinBindingSubjects(t, ctx, fx.repo, []domain.UserID{fx.member, second}, roleID, fx.prj)
	seedMirrorRow(t, ctx, pool, "compute.instance", "iRace", string(fx.prj), string(fx.accID), nil, time.Now())
	registerUnderProject(t, ctx, pool, fx, "compute_instance:iRace")

	require.NoError(t, a.ReconcileBinding(ctx, bid))
	subjs := []string{"user:" + string(fx.member), "user:" + string(second)}
	require.Equal(t, 2, distinctLedgerSubjects(t, ctx, pool, bid),
		"БЛИЗНЕЦ: реестр несёт строки ОБОИХ субъектов")
	for _, s := range subjs {
		require.Positive(t, factsOn(t, ctx, pool, s, "compute_instance", "iRace"),
			"БЛИЗНЕЦ: прямой факт субъекта %s есть до снятия", s)
		require.Equal(t, relverdict.Allow, ledgerVerdict(t, ctx, pool, s),
			"БЛИЗНЕЦ: до снятия вердикт субъекта %s — разрешение", s)
	}
	return &multiSubjectProbe{pool: pool, bid: bid, subjs: subjs, a: a, b: b}
}

func (p *multiSubjectProbe) expireAndAssertNothingLeft(t *testing.T, r *reconcile.Reconciler, why string) {
	t.Helper()
	ctx := context.Background()
	(&ledgerProbe{pool: p.pool, bid: p.bid}).expireInPast(t)
	require.NoError(t, r.ExpireBinding(ctx, p.bid))
	assert.Equal(t, string(domain.AccessBindingStatusRevoked), bindingStatus(t, ctx, p.pool, p.bid))
	for _, s := range p.subjs {
		members, ledger, facts := bindingResidue(t, ctx, p.pool, p.bid, s, "compute_instance", "iRace")
		assert.Zero(t, members, "%s: остались члены", why)
		assert.Zero(t, ledger, "%s: остались записи реестра", why)
		assert.Zero(t, facts, "%s: у субъекта %s остался прямой факт — доступ без выдачи", why, s)
		assert.Equal(t, relverdict.Deny, ledgerVerdict(t, ctx, p.pool, s),
			"%s: вердикт субъекта %s обязан быть отказом", why, s)
	}
}

func TestExpireFromLedger_MultiSubject_TwinSameReplica(t *testing.T) {
	p := newMultiSubjectProbe(t, "e933mt")
	p.expireAndAssertNothingLeft(t, p.a, "многосубъектное истечение на реплике, знающей тип")
}

func TestExpireFromLedger_MultiSubject_ReplicaWithoutTheTypeRevokesEverySubject(t *testing.T) {
	p := newMultiSubjectProbe(t, "e933ms")
	p.expireAndAssertNothingLeft(t, p.b, "многосубъектное истечение на реплике без типа")
}

// ── 2. Ошибка чтения реестра откатывает проход ──────────────────────────────

var errLedgerProbe = errors.New("ledger read refused by probe")

// failingLedgerTx — настоящий исполнитель транзакций, чьё хранилище отказывает в
// чтении реестра: целиком (whole) либо по координате члена (perObject).
type failingLedgerTx struct {
	inner     *kanamepg.ReconcileAdapter
	whole     bool
	perObject bool
}

func (f *failingLedgerTx) WithTx(ctx context.Context, fn func(ctx context.Context, s reconcile.ReconcileStore) error) error {
	return f.inner.WithTx(ctx, func(ctx context.Context, s reconcile.ReconcileStore) error {
		return fn(ctx, &failingLedgerStore{ReconcileStore: s, f: f})
	})
}

type failingLedgerStore struct {
	reconcile.ReconcileStore
	f *failingLedgerTx
}

func (s *failingLedgerStore) LedgerTuples(ctx context.Context, bid domain.AccessBindingID) ([]reconcile.LedgerRow, error) {
	if s.f.whole {
		return nil, errLedgerProbe
	}
	return s.ReconcileStore.LedgerTuples(ctx, bid)
}

func (s *failingLedgerStore) LedgerTuplesForMember(ctx context.Context, bid domain.AccessBindingID, member reconcile.MemberCoord) ([]domain.MembershipTuple, error) {
	if s.f.perObject {
		return nil, errLedgerProbe
	}
	return s.ReconcileStore.LedgerTuplesForMember(ctx, bid, member)
}

// assertUntouched — проход откатился: выдача действующая, член ACTIVE, реестр и факт
// на месте, вердикт — разрешение.
func (p *ledgerProbe) assertUntouched(t *testing.T, why string) {
	t.Helper()
	ctx := context.Background()
	assert.Equal(t, string(domain.AccessBindingStatusActive), bindingStatus(t, ctx, p.pool, p.bid), "%s: выдача обязана остаться действующей", why)
	st, ok := memberStatusOn(t, ctx, p.pool, p.bid, "compute.instance", "iRace")
	assert.True(t, ok, "%s: член удалён, хотя проход откатился", why)
	assert.Equal(t, string(domain.VerificationActive), st, "%s: статус члена", why)
	assert.Positive(t, ledgerRowsOn(t, ctx, p.pool, p.bid, "compute_instance:iRace"), "%s: реестр выдачи пропал", why)
	assert.Positive(t, factsOn(t, ctx, p.pool, p.subj, "compute_instance", "iRace"), "%s: прямой факт пропал", why)
}

func TestLedgerReadError_ExpiryRollsBack(t *testing.T) {
	p := newLedgerProbe(t, "e933ex", false)
	p.expireInPast(t)
	adapter := kanamepg.NewReconcileAdapter(p.pool, catalogfixture.Source())
	r := reconcile.New(&failingLedgerTx{inner: adapter, whole: true}, nil, catalogWithout(t, ledgerProbeType, false))
	err := r.ExpireBinding(context.Background(), p.bid)
	require.ErrorIs(t, err, errLedgerProbe, "истечение обязано вернуть ошибку чтения реестра, а не проглотить её")
	p.assertUntouched(t, "истечение с отказом чтения реестра")
	// Близнец: тот же проход без отказа доходит до конца — откат оставил его повторимым.
	require.NoError(t, p.b.ExpireBinding(context.Background(), p.bid))
	p.assertNothingLeft(t, "повтор истечения после отката")
}

func TestLedgerReadError_FellOutOnReplicaWithoutTheTypeRollsBack(t *testing.T) {
	p := newLedgerProbe(t, "e933fe", false)
	// Член выпадает по-настоящему — объект ушёл из зеркала; одно незнание типа
	// репликой его не снимает (kaname#937).
	removeLedgerProbeObject(t, p.pool)
	adapter := kanamepg.NewReconcileAdapter(p.pool, catalogfixture.Source())
	// Отказывают ОБА чтения реестра: член снимается чтением своей координаты, и проба
	// не вправе зависеть от того, каким из двух чтений путь берёт набор снятия.
	r := reconcile.New(&failingLedgerTx{inner: adapter, whole: true, perObject: true}, nil, catalogWithout(t, ledgerProbeType, false))
	err := r.ReconcileBinding(context.Background(), p.bid)
	require.ErrorIs(t, err, errLedgerProbe, "выпадение члена обязано вернуть ошибку чтения реестра")
	p.assertUntouched(t, "выпадение члена с отказом чтения реестра")
	require.NoError(t, p.b.ReconcileBinding(context.Background(), p.bid))
	p.assertNothingLeft(t, "повтор выпадения после отката")
}

func TestLedgerReadError_FellOutOnKnownTypeRollsBack(t *testing.T) {
	p := newLedgerProbe(t, "e933fk", false)
	ctx := context.Background()
	// Объект ушёл из зеркала — член выпадает из желаемого на реплике, знающей тип.
	_, err := p.pool.Exec(ctx,
		`DELETE FROM kaname.resource_mirror WHERE object_type = 'compute.instance' AND object_id = 'iRace'`)
	require.NoError(t, err)
	st, ok := memberStatusOn(t, ctx, p.pool, p.bid, "compute.instance", "iRace")
	require.True(t, ok, "ПРЕДПОСЫЛКА: снятие строки зеркала члена не удаляет")
	require.Equal(t, string(domain.VerificationActive), st)
	adapter := kanamepg.NewReconcileAdapter(p.pool, catalogfixture.Source())
	r := reconcile.New(&failingLedgerTx{inner: adapter, perObject: true}, nil, catalogfixture.Source())
	err = r.ReconcileBinding(ctx, p.bid)
	require.ErrorIs(t, err, errLedgerProbe, "чтение реестра по объекту не гасится")
	p.assertUntouched(t, "выпадение члена знакомого типа с отказом чтения реестра")
	require.NoError(t, p.a.ReconcileBinding(ctx, p.bid))
	members, ledger, facts := bindingResidue(t, ctx, p.pool, p.bid, p.subj, "compute_instance", "iRace")
	assert.Zero(t, members, "повтор: остались члены")
	assert.Zero(t, ledger, "повтор: остались записи реестра")
	assert.Zero(t, facts, "повтор: остался прямой факт")
}

// ── 3. Совпадение суффикса `:<id>` у объектов разных типов ──────────────────

func vpcNetworkRule() domain.Rule {
	return domain.Rule{Module: "vpc", Resources: []string{"network"}, Verbs: []string{"get", "update"}}
}

type suffixProbe struct {
	pool  *pgxpool.Pool
	bid   domain.AccessBindingID
	subj  string
	netID string
	b     *reconcile.Reconciler
}

// newSuffixProbe — одна выдача, два члена: compute.instance «iRace» (типа нет в снимке
// реплики B) и vpc.network netID (тип B знает). Материализует реплика A.
func newSuffixProbe(t *testing.T, suffix, netID string) *suffixProbe {
	t.Helper()
	skipShort(t)
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, setupTestDB(t))
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	fx := setupGamma(t, ctx, pool, suffix)
	a, adapter := newReconciler(pool)
	b := reconcile.New(adapter, nil, catalogWithout(t, ledgerProbeType, false))
	roleID := seedRulesRole(t, ctx, pool, fx.repo, fx.prj, suffix+"role", domain.Rules{forwardAnchorRule(), vpcNetworkRule()})
	bid := insertThinBinding(t, ctx, fx.repo, fx.member, roleID, fx.prj)
	seedMirrorRow(t, ctx, pool, "compute.instance", "iRace", string(fx.prj), string(fx.accID), nil, time.Now())
	seedMirrorRow(t, ctx, pool, "vpc.network", netID, string(fx.prj), string(fx.accID), nil, time.Now())
	registerUnderProject(t, ctx, pool, fx, "compute_instance:iRace")
	registerUnderProject(t, ctx, pool, fx, "vpc_network:"+netID)

	require.NoError(t, a.ReconcileBinding(ctx, bid))
	subj := "user:" + string(fx.member)
	require.Positive(t, ledgerRowsOn(t, ctx, pool, bid, "compute_instance:iRace"), "БЛИЗНЕЦ: реестр инстанса есть")
	require.Positive(t, ledgerRowsOn(t, ctx, pool, bid, "vpc_network:"+netID), "БЛИЗНЕЦ: реестр сети есть")
	require.Positive(t, factsOn(t, ctx, pool, subj, "compute_instance", "iRace"), "БЛИЗНЕЦ: факт инстанса есть")
	require.Positive(t, factsOn(t, ctx, pool, subj, "vpc_network", netID), "БЛИЗНЕЦ: факт сети есть")
	// Инстанс уходит из зеркала: его член выпадает по-настоящему. Реплика B его типа
	// не знает, но одно это члена не снимает (kaname#937) — снимает выпадение.
	removeLedgerProbeObject(t, pool)
	return &suffixProbe{pool: pool, bid: bid, subj: subj, netID: netID, b: b}
}

// assertOnlyInstanceRevoked — кортежи инстанса сняты (kaname#933), сеть нетронута:
// её член ACTIVE, реестр и прямой факт на месте.
func (p *suffixProbe) assertOnlyInstanceRevoked(t *testing.T, netLedgerBefore int, why string) {
	t.Helper()
	ctx := context.Background()
	assert.Zero(t, ledgerRowsOn(t, ctx, p.pool, p.bid, "compute_instance:iRace"), "%s: реестр инстанса не снят", why)
	assert.Zero(t, factsOn(t, ctx, p.pool, p.subj, "compute_instance", "iRace"), "%s: факт инстанса не снят", why)
	st, ok := memberStatusOn(t, ctx, p.pool, p.bid, "vpc.network", p.netID)
	assert.True(t, ok, "%s: член сети удалён", why)
	assert.Equal(t, string(domain.VerificationActive), st, "%s: статус члена сети", why)
	assert.Equal(t, netLedgerBefore, ledgerRowsOn(t, ctx, p.pool, p.bid, "vpc_network:"+p.netID),
		"%s: снят реестр ЧУЖОГО объекта (сеть с тем же id)", why)
	assert.Positive(t, factsOn(t, ctx, p.pool, p.subj, "vpc_network", p.netID),
		"%s: снят прямой факт ЧУЖОГО объекта (сеть с тем же id) — член ACTIVE без доступа", why)
}

func (p *suffixProbe) netLedger(t *testing.T) int {
	return ledgerRowsOn(t, context.Background(), p.pool, p.bid, "vpc_network:"+p.netID)
}

// Проход по объекту (ReconcileObject) на реплике без типа инстанса: желаемое — только
// этот объект, поэтому вычитание «ещё заявлено» сеть не видит.
func TestSuffixCollision_ObjectPass_TwinDistinctID(t *testing.T) {
	p := newSuffixProbe(t, "e933sd", "nRace")
	before := p.netLedger(t)
	require.NoError(t, p.b.ReconcileObject(context.Background(), "compute.instance", "iRace"))
	p.assertOnlyInstanceRevoked(t, before, "проход по объекту, у сети другой id")
}

func TestSuffixCollision_ObjectPass_SameIDOfAnotherTypeIsNotRevoked(t *testing.T) {
	p := newSuffixProbe(t, "e933ss", "iRace")
	before := p.netLedger(t)
	require.NoError(t, p.b.ReconcileObject(context.Background(), "compute.instance", "iRace"))
	p.assertOnlyInstanceRevoked(t, before, "проход по объекту, у сети тот же id")
}

// Полный проход на той же фикстуре: желаемое несёт сеть целиком.
func TestSuffixCollision_FullPass_SameIDOfAnotherTypeIsNotRevoked(t *testing.T) {
	p := newSuffixProbe(t, "e933sf", "iRace")
	before := p.netLedger(t)
	require.NoError(t, p.b.ReconcileBinding(context.Background(), p.bid))
	p.assertOnlyInstanceRevoked(t, before, "полный проход, у сети тот же id")
}

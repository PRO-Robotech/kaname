// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package cluster_test

// public_twin_integration_test.go — публичный близнец `ClusterService`
// (приёмка ADM-CA, `docs/engineering/acceptance/cluster-admins-on-the-public-surface.md`,
// §5 S1 п.7): сценарии CAP-03…06, 10…20, 23 через близнеца, testcontainers.
//
// Близнец собирается так же, как в композиционном корне: над ТЕМИ ЖЕ
// экземплярами сценариев, что и внутренний обработчик (Р3), — `buildTwins`
// строит один набор сценариев и отдаёт оба транспорта над ним. CAP-20 судит
// именно это: назначено одним путём — видно другим, и наоборот.
//
// Аудит с публичной поверхности не наблюдаем, поэтому утверждения об аудите
// (CAP-04, 05, 06, 17, 19) живут здесь, а не в наборе newman.

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	clusterapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/cluster"
	clusterpublicapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/clusterpublic"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// twinOpts — что меняется между сборками близнеца.
type twinOpts struct {
	// checker — нил: разрешающий и безопасный для конкурентных вызовов.
	checker relationChecker
	// audit — нил: настоящий писатель аудита.
	audit interface {
		EmitTx(ctx context.Context, tx service.Tx, ev service.AuditEvent) error
	}
}

// relationChecker — порт проверки права сценариев мутаций.
type relationChecker interface {
	Check(ctx context.Context, subject, relation, object string) (bool, error)
}

// allowAll — разрешающий проверяющий без состояния: годен конкурентным пробам
// (запоминающий fakeAdminChecker пишет поля и гоняется сам с собой).
type allowAll struct{}

func (allowAll) Check(context.Context, string, string, string) (bool, error) { return true, nil }

// twins — оба транспорта над одним набором сценариев и доступ к базе.
type twins struct {
	internal *clusterapp.Handler
	public   *clusterpublicapp.Handler
	pool     *pgxpool.Pool
	ops      operations.Repo
}

// buildTwins собирает сценарии ОДИН раз и оба транспорта над ними — как
// композиционный корень (`cmd/kaname/wiring.go`).
func buildTwins(t *testing.T, dsn string, o twinOpts) twins {
	t.Helper()
	ctx := context.Background()
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	t.Cleanup(pool.Close)

	opsRepo := operations.NewRepo(pool, "kaname")
	grantWriter := kanamepg.NewClusterAdminGrantWriter(pool)
	grantReader := kanamepg.NewClusterAdminGrantReader(pool)
	fgaEmitter := kanamepg.NewFGAOutboxEmitter()
	txb := kanamepg.NewPoolTxBeginner(pool)

	var checker relationChecker = allowAll{}
	if o.checker != nil {
		checker = o.checker
	}
	var audit interface {
		EmitTx(ctx context.Context, tx service.Tx, ev service.AuditEvent) error
	} = kanamepg.NewAuditOutboxEmitter(pool)
	if o.audit != nil {
		audit = o.audit
	}

	getUC := clusterapp.NewGetClusterUseCase(kanamepg.NewClusterReader(pool))
	grantUC := clusterapp.NewGrantAdminUseCase(grantWriter, grantReader, fgaEmitter, txb, opsRepo).
		WithSubjectStateReader(kanamepg.NewSubjectStateReader(pool)).
		WithAdminChecker(checker).
		WithAuditEmitter(audit)
	revokeUC := clusterapp.NewRevokeAdminUseCase(grantWriter, fgaEmitter, txb, opsRepo).
		WithAdminChecker(checker).
		WithAuditEmitter(audit)
	listUC := clusterapp.NewListAdminsUseCase(grantReader)

	internal := clusterapp.NewHandler(getUC, grantUC, revokeUC, listUC)
	return twins{
		internal: internal,
		public:   clusterpublicapp.NewHandler(internal),
		pool:     pool,
		ops:      opsRepo,
	}
}

// seedNamedUser — активный человек с заданным непустым отображаемым именем и
// адресом. Возвращает id и адрес.
func seedNamedUser(t *testing.T, ctx context.Context, pool *pgxpool.Pool, suffix, displayName string) (domain.UserID, string) {
	t.Helper()
	uid := mustSeedUser(t, ctx, pool, suffix)
	email := fmt.Sprintf("u-%s@example.com", suffix)
	_, err := pool.Exec(ctx, `UPDATE kaname.users SET display_name = $2 WHERE id = $1`, string(uid), displayName)
	require.NoError(t, err)
	return uid, email
}

func grantReq(typ iamv1.ClusterGrantSubjectType, id string) *iamv1.GrantClusterAdminRequest {
	return &iamv1.GrantClusterAdminRequest{SubjectType: typ, SubjectId: id}
}

func revokeReq(typ iamv1.ClusterGrantSubjectType, id string) *iamv1.RevokeClusterAdminRequest {
	return &iamv1.RevokeClusterAdminRequest{SubjectType: typ, SubjectId: id}
}

func revokeMeta(t *testing.T, op *operationpb.Operation) *iamv1.RevokeClusterAdminMetadata {
	t.Helper()
	m := &iamv1.RevokeClusterAdminMetadata{}
	require.NoError(t, op.GetMetadata().UnmarshalTo(m))
	return m
}

func opResponseGrant(t *testing.T, op *operationpb.Operation) *iamv1.ClusterAdminGrant {
	t.Helper()
	g := &iamv1.ClusterAdminGrant{}
	require.NoError(t, op.GetResponse().UnmarshalTo(g))
	return g
}

// entriesFor — записи перечня для субъекта.
func entriesFor(resp *iamv1.ListClusterAdminsResponse, subjectID string) []*iamv1.ClusterAdminEntry {
	var out []*iamv1.ClusterAdminEntry
	for _, e := range resp.GetAdmins() {
		if e.GetSubjectId() == subjectID {
			out = append(out, e)
		}
	}
	return out
}

func activeGrantCount(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.cluster_admin_grants WHERE granted_until IS NULL`).Scan(&n))
	return n
}

func fgaOutboxRowsFor(t *testing.T, ctx context.Context, pool *pgxpool.Pool, subjectID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.fga_outbox WHERE payload::text LIKE '%' || $1 || '%'`,
		subjectID).Scan(&n))
	return n
}

func operationRows(t *testing.T, ctx context.Context, pool *pgxpool.Pool) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx, `SELECT count(*) FROM kaname.operations`).Scan(&n))
	return n
}

func fieldViolation(t *testing.T, err error) *errdetails.BadRequest_FieldViolation {
	t.Helper()
	for _, d := range status.Convert(err).Details() {
		if br, ok := d.(*errdetails.BadRequest); ok && len(br.GetFieldViolations()) > 0 {
			return br.GetFieldViolations()[0]
		}
	}
	t.Fatalf("no field violation in %v", err)
	return nil
}

func skipShort(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("skipping integration test (requires Docker)")
	}
}

// ── класс A ─────────────────────────────────────────────────────────────────

// TestClusterPublic_CAP03_GrantHumanThroughTheTwin — CAP-03.
func TestClusterPublic_CAP03_GrantHumanThroughTheTwin(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	tw := buildTwins(t, setupTestDB(t), twinOpts{})
	admin, adminEmail := seedNamedUser(t, ctx, tw.pool, "cap03adm", "CAP admin")
	const targetName = "CAP target cap03"
	target, targetEmail := seedNamedUser(t, ctx, tw.pool, "cap03tgt", targetName)

	op, err := tw.public.GrantAdmin(withPrincipal(ctx, string(admin)), grantReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
	require.Regexp(t, `^iop`, op.GetId())
	require.True(t, op.GetDone())
	require.Nil(t, op.GetError())
	meta := extractGrantMeta(t, op)
	require.Equal(t, string(target), meta.GetSubjectId())
	require.NotEmpty(t, meta.GetClusterAdminGrantId())
	g := opResponseGrant(t, op)
	require.Equal(t, meta.GetClusterAdminGrantId(), g.GetId())
	require.Equal(t, iamv1.ClusterGrantSubjectType_USER, g.GetSubjectType())
	require.Equal(t, string(admin), g.GetGrantedByUserId())

	polled, err := tw.ops.Get(ctx, op.GetId())
	require.NoError(t, err)
	require.True(t, polled.Done)
	require.Nil(t, polled.Error)

	list, err := tw.public.ListAdmins(ctx, &iamv1.ListClusterAdminsRequest{})
	require.NoError(t, err)
	es := entriesFor(list, string(target))
	require.Len(t, es, 1)
	require.Equal(t, targetEmail, es[0].GetSubjectEmail())
	require.NotEmpty(t, es[0].GetSubjectDisplayName())
	require.Equal(t, targetName, es[0].GetSubjectDisplayName())
	require.Equal(t, adminEmail, es[0].GetGrantedByEmail())
}

// TestClusterPublic_CAP04_RegrantIsIdempotent — CAP-04.
func TestClusterPublic_CAP04_RegrantIsIdempotent(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	tw := buildTwins(t, setupTestDB(t), twinOpts{})
	admin := mustSeedUser(t, ctx, tw.pool, "cap04adm")
	target := mustSeedUser(t, ctx, tw.pool, "cap04tgt")
	pctx := withPrincipal(ctx, string(admin))

	first, err := tw.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
	second, err := tw.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
	require.True(t, second.GetDone())
	require.Nil(t, second.GetError())
	require.Equal(t, extractGrantMeta(t, first).GetClusterAdminGrantId(), extractGrantMeta(t, second).GetClusterAdminGrantId())

	list, err := tw.public.ListAdmins(ctx, &iamv1.ListClusterAdminsRequest{})
	require.NoError(t, err)
	require.Len(t, entriesFor(list, string(target)), 1)
	require.Len(t, clusterAuditRows(ctx, t, tw.pool, string(target), "iam.cluster_admin.granted"), 1)
}

// TestClusterPublic_CAP05_RevokeThroughTheTwin — CAP-05.
func TestClusterPublic_CAP05_RevokeThroughTheTwin(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	tw := buildTwins(t, setupTestDB(t), twinOpts{})
	admin := mustSeedUser(t, ctx, tw.pool, "cap05adm")
	target := mustSeedUser(t, ctx, tw.pool, "cap05tgt")
	pctx := withPrincipal(ctx, string(admin))

	granted, err := tw.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
	op, err := tw.public.RevokeAdmin(pctx, revokeReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
	require.True(t, op.GetDone())
	require.Nil(t, op.GetError())
	m := revokeMeta(t, op)
	require.Equal(t, extractGrantMeta(t, granted).GetClusterAdminGrantId(), m.GetClusterAdminGrantId())
	require.Equal(t, string(target), m.GetSubjectId())

	list, err := tw.public.ListAdmins(ctx, &iamv1.ListClusterAdminsRequest{})
	require.NoError(t, err)
	require.Empty(t, entriesFor(list, string(target)))
	rows := clusterAuditRows(ctx, t, tw.pool, string(target), "iam.cluster_admin.revoked")
	require.Len(t, rows, 1)
	require.Equal(t, string(admin), rows[0].payload["actor"])
}

// TestClusterPublic_CAP06_RegrantAfterRevokeReactivates — CAP-06.
func TestClusterPublic_CAP06_RegrantAfterRevokeReactivates(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	tw := buildTwins(t, setupTestDB(t), twinOpts{})
	admin := mustSeedUser(t, ctx, tw.pool, "cap06adm")
	target := mustSeedUser(t, ctx, tw.pool, "cap06tgt")
	pctx := withPrincipal(ctx, string(admin))

	first, err := tw.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
	_, err = tw.public.RevokeAdmin(pctx, revokeReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
	again, err := tw.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
	require.True(t, again.GetDone())
	require.Nil(t, again.GetError())
	require.Equal(t, extractGrantMeta(t, first).GetClusterAdminGrantId(), extractGrantMeta(t, again).GetClusterAdminGrantId())

	list, err := tw.public.ListAdmins(ctx, &iamv1.ListClusterAdminsRequest{})
	require.NoError(t, err)
	require.Len(t, entriesFor(list, string(target)), 1, "the grant is active again")
	require.Len(t, clusterAuditRows(ctx, t, tw.pool, string(target), "iam.cluster_admin.granted"), 2)
}

// ── класс B ─────────────────────────────────────────────────────────────────

// TestClusterPublic_CAP10_MalformedGrantInput — CAP-10.
func TestClusterPublic_CAP10_MalformedGrantInput(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	tw := buildTwins(t, setupTestDB(t), twinOpts{})
	admin := mustSeedUser(t, ctx, tw.pool, "cap10adm")
	target := mustSeedUser(t, ctx, tw.pool, "cap10tgt")
	pctx := withPrincipal(ctx, string(admin))
	before := operationRows(t, ctx, tw.pool)

	cases := []struct {
		name string
		req  *iamv1.GrantClusterAdminRequest
		desc string
	}{
		{"kind and id form disagree", grantReq(iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, string(target)), ""},
		{"id missing", grantReq(iamv1.ClusterGrantSubjectType_USER, ""), "required"},
		{"underscore in id", grantReq(iamv1.ClusterGrantSubjectType_USER, "usr_aaaaaaaaaaaaaaaaa"), ""},
	}
	for _, c := range cases {
		_, err := tw.public.GrantAdmin(pctx, c.req)
		require.Equal(t, codes.InvalidArgument, status.Code(err), c.name)
		fv := fieldViolation(t, err)
		require.Equal(t, "subject_id", fv.GetField(), c.name)
		if c.desc != "" {
			require.Equal(t, c.desc, fv.GetDescription(), c.name)
		}
	}
	require.Zero(t, countGrantRows(t, ctx, tw.pool, string(target)))
	require.Empty(t, clusterAuditRows(ctx, t, tw.pool, string(target), "iam.cluster_admin.granted"))
	require.Equal(t, before, operationRows(t, ctx, tw.pool), "a refused input creates no operation")

	op, err := tw.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
	require.Nil(t, op.GetError())
}

// TestClusterPublic_CAP11_GrantAbsentHuman — CAP-11.
func TestClusterPublic_CAP11_GrantAbsentHuman(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	tw := buildTwins(t, setupTestDB(t), twinOpts{})
	admin := mustSeedUser(t, ctx, tw.pool, "cap11adm")
	target := mustSeedUser(t, ctx, tw.pool, "cap11tgt")
	pctx := withPrincipal(ctx, string(admin))

	const ghost = "usrzzzzzzzzzzzzzzzzz"
	_, err := tw.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, ghost))
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Equal(t, "User "+ghost+" not found", status.Convert(err).Message())
	require.Zero(t, countGrantRows(t, ctx, tw.pool, ghost))

	_, err = tw.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
}

// TestClusterPublic_CAP12_SubjectBarredFromSignIn — CAP-12.
func TestClusterPublic_CAP12_SubjectBarredFromSignIn(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	tw := buildTwins(t, setupTestDB(t), twinOpts{})
	admin := mustSeedUser(t, ctx, tw.pool, "cap12adm")
	pctx := withPrincipal(ctx, string(admin))

	blocked := mustSeedBlockedUser(t, ctx, tw.pool, "cap12blk")
	host := mustSeedUser(t, ctx, tw.pool, "cap12host")
	var accID string
	require.NoError(t, tw.pool.QueryRow(ctx, `SELECT account_id FROM kaname.users WHERE id = $1`, string(host)).Scan(&accID))
	pending := ids.NewID(domain.PrefixUser)
	_, err := tw.pool.Exec(ctx, `
		INSERT INTO kaname.users (id, account_id, external_id, email, display_name, invite_status)
		VALUES ($1, $2, '', $3, 'Invitee', 'PENDING')`, pending, accID, "pending-cap12@example.com")
	require.NoError(t, err)
	svaOff := mustSeedServiceAccount(t, ctx, tw.pool, "cap12off", false)

	refusals := []struct {
		req  *iamv1.GrantClusterAdminRequest
		text string
		id   string
	}{
		{grantReq(iamv1.ClusterGrantSubjectType_USER, string(blocked)), fmt.Sprintf("User %s is blocked", blocked), string(blocked)},
		{grantReq(iamv1.ClusterGrantSubjectType_USER, pending), fmt.Sprintf("User %s is not active", pending), pending},
		{grantReq(iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, string(svaOff)), fmt.Sprintf("ServiceAccount %s is disabled", svaOff), string(svaOff)},
	}
	for _, r := range refusals {
		_, err := tw.public.GrantAdmin(pctx, r.req)
		require.Equal(t, codes.FailedPrecondition, status.Code(err), r.text)
		require.Equal(t, r.text, status.Convert(err).Message())
		require.Zero(t, countGrantRows(t, ctx, tw.pool, r.id))
	}

	target := mustSeedUser(t, ctx, tw.pool, "cap12tgt")
	svaOn := mustSeedServiceAccount(t, ctx, tw.pool, "cap12on", true)
	_, err = tw.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
	_, err = tw.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, string(svaOn)))
	require.NoError(t, err)
}

// TestClusterPublic_CAP13_RevokeNonAdmin — CAP-13.
func TestClusterPublic_CAP13_RevokeNonAdmin(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	tw := buildTwins(t, setupTestDB(t), twinOpts{})
	admin := mustSeedUser(t, ctx, tw.pool, "cap13adm")
	target := mustSeedUser(t, ctx, tw.pool, "cap13tgt")
	pctx := withPrincipal(ctx, string(admin))

	_, err := tw.public.RevokeAdmin(pctx, revokeReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.Equal(t, codes.NotFound, status.Code(err))
	require.Equal(t, fmt.Sprintf("User %s is not an active cluster admin", target), status.Convert(err).Message())

	_, err = tw.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
	_, err = tw.public.RevokeAdmin(pctx, revokeReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
}

// TestClusterPublic_CAP14_SelfRevokeRefused — CAP-14.
func TestClusterPublic_CAP14_SelfRevokeRefused(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	tw := buildTwins(t, setupTestDB(t), twinOpts{})
	admin := mustSeedUser(t, ctx, tw.pool, "cap14adm")
	seedClusterAdmin(t, ctx, tw.pool, admin)
	target := mustSeedUser(t, ctx, tw.pool, "cap14tgt")
	pctx := withPrincipal(ctx, string(admin))

	_, err := tw.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)

	_, err = tw.public.RevokeAdmin(pctx, revokeReq(iamv1.ClusterGrantSubjectType_USER, string(admin)))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, "cannot revoke own cluster admin grant", status.Convert(err).Message())

	op, err := tw.public.RevokeAdmin(pctx, revokeReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
	require.True(t, op.GetDone())
	list, err := tw.public.ListAdmins(ctx, &iamv1.ListClusterAdminsRequest{})
	require.NoError(t, err)
	require.Empty(t, entriesFor(list, string(target)))
	require.Len(t, entriesFor(list, string(admin)), 1, "the caller's own grant stays active")
}

// TestClusterPublic_CAP15_LastAdminWhileModelStillSaysYes — CAP-15: проверка
// права у Y ещё отвечает «да» (снятие кортежа асинхронно), но последнего
// администратора не снять — инвариант держит база, а не проверка права.
func TestClusterPublic_CAP15_LastAdminWhileModelStillSaysYes(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	tw := buildTwins(t, setupTestDB(t), twinOpts{})
	decommissionBootstrapSeedGrant(t, ctx, tw.pool)
	x := mustSeedUser(t, ctx, tw.pool, "cap15x")
	y := mustSeedUser(t, ctx, tw.pool, "cap15y")
	seedClusterAdmin(t, ctx, tw.pool, x)
	seedClusterAdmin(t, ctx, tw.pool, y)
	require.Equal(t, 2, activeGrantCount(t, ctx, tw.pool))

	_, err := tw.public.RevokeAdmin(withPrincipal(ctx, string(x)), revokeReq(iamv1.ClusterGrantSubjectType_USER, string(y)))
	require.NoError(t, err)

	_, err = tw.public.RevokeAdmin(withPrincipal(ctx, string(y)), revokeReq(iamv1.ClusterGrantSubjectType_USER, string(x)))
	require.Equal(t, codes.FailedPrecondition, status.Code(err))
	require.Equal(t, "cannot revoke last active cluster admin", status.Convert(err).Message())
	require.Equal(t, 1, activeGrantCount(t, ctx, tw.pool))
	require.Empty(t, clusterAuditRows(ctx, t, tw.pool, string(x), "iam.cluster_admin.revoked"))

	// Близнец: при третьей активной выдаче тот же запрос Y проходит.
	z := mustSeedUser(t, ctx, tw.pool, "cap15z")
	seedClusterAdmin(t, ctx, tw.pool, z)
	_, err = tw.public.RevokeAdmin(withPrincipal(ctx, string(y)), revokeReq(iamv1.ClusterGrantSubjectType_USER, string(x)))
	require.NoError(t, err)
}

// TestClusterPublic_CAP16_CrossRevokeExactlyOneWins — CAP-16: два встречных
// снятия на паре последних администраторов, 20 повторов на свежей паре.
func TestClusterPublic_CAP16_CrossRevokeExactlyOneWins(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	tw := buildTwins(t, setupTestDB(t), twinOpts{})
	decommissionBootstrapSeedGrant(t, ctx, tw.pool)

	for round := 0; round < 20; round++ {
		_, err := tw.pool.Exec(ctx, `UPDATE kaname.cluster_admin_grants SET granted_until = now() WHERE granted_until IS NULL`)
		require.NoError(t, err)
		x := mustSeedUser(t, ctx, tw.pool, fmt.Sprintf("cap16x%d", round))
		y := mustSeedUser(t, ctx, tw.pool, fmt.Sprintf("cap16y%d", round))
		seedClusterAdmin(t, ctx, tw.pool, x)
		seedClusterAdmin(t, ctx, tw.pool, y)
		require.Equal(t, 2, activeGrantCount(t, ctx, tw.pool))

		var (
			wg   sync.WaitGroup
			errs [2]error
		)
		start := make(chan struct{})
		pairs := [2][2]domain.UserID{{x, y}, {y, x}}
		for i, p := range pairs {
			wg.Add(1)
			go func(i int, caller, subject domain.UserID) {
				defer wg.Done()
				<-start
				_, errs[i] = tw.public.RevokeAdmin(withPrincipal(ctx, string(caller)),
					revokeReq(iamv1.ClusterGrantSubjectType_USER, string(subject)))
			}(i, p[0], p[1])
		}
		close(start)
		wg.Wait()

		ok, refused := 0, 0
		for _, e := range errs {
			switch {
			case e == nil:
				ok++
			case status.Code(e) == codes.FailedPrecondition &&
				status.Convert(e).Message() == "cannot revoke last active cluster admin":
				refused++
			default:
				t.Fatalf("round %d: unexpected outcome %v", round, e)
			}
		}
		require.Equal(t, 1, ok, "round %d: exactly one revoke wins", round)
		require.Equal(t, 1, refused, "round %d", round)
		require.Equal(t, 1, activeGrantCount(t, ctx, tw.pool), "round %d: one admin remains", round)
	}
}

// TestClusterPublic_CAP17_MachineSubjectGrantAndRevoke — CAP-17.
func TestClusterPublic_CAP17_MachineSubjectGrantAndRevoke(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	tw := buildTwins(t, setupTestDB(t), twinOpts{})
	admin := mustSeedUser(t, ctx, tw.pool, "cap17adm")
	sva := mustSeedServiceAccount(t, ctx, tw.pool, "cap17sva", true)
	pctx := withPrincipal(ctx, string(admin))

	op, err := tw.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, string(sva)))
	require.NoError(t, err)
	require.Nil(t, op.GetError())
	list, err := tw.public.ListAdmins(ctx, &iamv1.ListClusterAdminsRequest{})
	require.NoError(t, err)
	es := entriesFor(list, string(sva))
	require.Len(t, es, 1)
	require.Equal(t, iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, es[0].GetSubjectType())

	// Без рода снятие трактуется как USER, и `sva…` не проходит форму человека.
	_, err = tw.public.RevokeAdmin(pctx, revokeReq(iamv1.ClusterGrantSubjectType_CLUSTER_GRANT_SUBJECT_TYPE_UNSPECIFIED, string(sva)))
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Equal(t, "subject_id", fieldViolation(t, err).GetField())

	op, err = tw.public.RevokeAdmin(pctx, revokeReq(iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, string(sva)))
	require.NoError(t, err)
	require.Nil(t, op.GetError())
	list, err = tw.public.ListAdmins(ctx, &iamv1.ListClusterAdminsRequest{})
	require.NoError(t, err)
	require.Empty(t, entriesFor(list, string(sva)))

	for _, ev := range []string{"iam.cluster_admin.granted", "iam.cluster_admin.revoked"} {
		rows := clusterAuditRows(ctx, t, tw.pool, string(sva), ev)
		require.Len(t, rows, 1, ev)
		require.Equal(t, "service_account", rows[0].payload["subject_type"], ev)
	}

	ghost := ids.NewID(domain.PrefixServiceAccount)
	_, err = tw.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_SERVICE_ACCOUNT, ghost))
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Equal(t, "ServiceAccount "+ghost+" not found", status.Convert(err).Message())
}

// TestClusterPublic_CAP18_ModelUnavailableRefuses — CAP-18.
func TestClusterPublic_CAP18_ModelUnavailableRefuses(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	dsn := setupTestDB(t)
	broken := buildTwins(t, dsn, twinOpts{checker: &fakeAdminChecker{err: errors.New("relation store unreachable")}})
	admin := mustSeedUser(t, ctx, broken.pool, "cap18adm")
	target := mustSeedUser(t, ctx, broken.pool, "cap18tgt")
	seedClusterAdmin(t, ctx, broken.pool, target)
	pctx := withPrincipal(ctx, string(admin))
	before := operationRows(t, ctx, broken.pool)
	grantsBefore := countGrantRows(t, ctx, broken.pool, string(target))

	other := mustSeedUser(t, ctx, broken.pool, "cap18oth")
	_, err := broken.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, string(other)))
	require.Equal(t, codes.Unavailable, status.Code(err))
	_, err = broken.public.RevokeAdmin(pctx, revokeReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.Equal(t, codes.Unavailable, status.Code(err))

	require.Zero(t, countGrantRows(t, ctx, broken.pool, string(other)))
	require.Equal(t, grantsBefore, countGrantRows(t, ctx, broken.pool, string(target)))
	require.Len(t, entriesFor(mustList(t, ctx, broken.public), string(target)), 1, "the grant was not revoked")
	require.Empty(t, clusterAuditRows(ctx, t, broken.pool, string(other), "iam.cluster_admin.granted"))
	require.Empty(t, clusterAuditRows(ctx, t, broken.pool, string(target), "iam.cluster_admin.revoked"))
	require.Equal(t, before, operationRows(t, ctx, broken.pool), "no operation is created, let alone a done one")

	healthy := buildTwins(t, dsn, twinOpts{})
	_, err = healthy.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, string(other)))
	require.NoError(t, err)
	_, err = healthy.public.RevokeAdmin(pctx, revokeReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
}

func mustList(t *testing.T, ctx context.Context, h *clusterpublicapp.Handler) *iamv1.ListClusterAdminsResponse {
	t.Helper()
	resp, err := h.ListAdmins(ctx, &iamv1.ListClusterAdminsRequest{})
	require.NoError(t, err)
	return resp
}

// failingAudit — сбой в той же транзакции ПОСЛЕ записи выдачи и строки очереди
// кортежей.
type failingAudit struct{}

func (failingAudit) EmitTx(context.Context, service.Tx, service.AuditEvent) error {
	return errors.New("injected audit failure")
}

// ── класс C ─────────────────────────────────────────────────────────────────

// TestClusterPublic_CAP19_GrantAuditIsAtomic — CAP-19.
func TestClusterPublic_CAP19_GrantAuditIsAtomic(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	dsn := setupTestDB(t)
	injected := buildTwins(t, dsn, twinOpts{audit: failingAudit{}})
	admin := mustSeedUser(t, ctx, injected.pool, "cap19adm")
	target := mustSeedUser(t, ctx, injected.pool, "cap19tgt")
	pctx := withPrincipal(ctx, string(admin))

	_, err := injected.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.Equal(t, codes.Internal, status.Code(err))
	require.NotContains(t, status.Convert(err).Message(), "injected", "driver/internal text must not leak")
	require.Zero(t, countGrantRows(t, ctx, injected.pool, string(target)))
	require.Empty(t, clusterAuditRows(ctx, t, injected.pool, string(target), "iam.cluster_admin.granted"))
	require.Zero(t, fgaOutboxRowsFor(t, ctx, injected.pool, string(target)))

	real := buildTwins(t, dsn, twinOpts{})
	_, err = real.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
	require.Equal(t, 1, countGrantRows(t, ctx, real.pool, string(target)))
	rows := clusterAuditRows(ctx, t, real.pool, string(target), "iam.cluster_admin.granted")
	require.Len(t, rows, 1)
	require.Equal(t, string(admin), rows[0].payload["actor"])
	require.Equal(t, 1, fgaOutboxRowsFor(t, ctx, real.pool, string(target)))
}

// TestClusterPublic_CAP20_OneWritePathBothTransports — CAP-20.
func TestClusterPublic_CAP20_OneWritePathBothTransports(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	tw := buildTwins(t, setupTestDB(t), twinOpts{})
	admin := mustSeedUser(t, ctx, tw.pool, "cap20adm")
	target, _ := seedNamedUser(t, ctx, tw.pool, "cap20tgt", "CAP target cap20")
	pctx := withPrincipal(ctx, string(admin))

	first, err := tw.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)

	pub := entriesFor(mustList(t, ctx, tw.public), string(target))
	in, err := tw.internal.ListAdmins(ctx, &iamv1.ListClusterAdminsRequest{})
	require.NoError(t, err)
	internalEntries := entriesFor(in, string(target))
	require.Len(t, pub, 1)
	require.Len(t, internalEntries, 1)
	require.True(t, proto.Equal(pub[0], internalEntries[0]), "both transports report the same entry")

	_, err = tw.internal.RevokeAdmin(pctx, revokeReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
	require.Empty(t, entriesFor(mustList(t, ctx, tw.public), string(target)))

	again, err := tw.public.GrantAdmin(pctx, grantReq(iamv1.ClusterGrantSubjectType_USER, string(target)))
	require.NoError(t, err)
	require.Equal(t, extractGrantMeta(t, first).GetClusterAdminGrantId(), extractGrantMeta(t, again).GetClusterAdminGrantId())

	// Чтение кластера — тот же ответ обоими путями.
	pc, err := tw.public.Get(ctx, &iamv1.GetClusterRequest{})
	require.NoError(t, err)
	ic, err := tw.internal.Get(ctx, &iamv1.GetClusterRequest{})
	require.NoError(t, err)
	require.True(t, proto.Equal(pc, ic))
	require.Equal(t, domain.ClusterSingletonID, pc.GetId())
}

// TestClusterPublic_CAP23_RosterOrderThroughTheTwin — CAP-23.
func TestClusterPublic_CAP23_RosterOrderThroughTheTwin(t *testing.T) {
	skipShort(t)
	ctx := context.Background()
	dsn := setupTestDB(t)
	want := tiedGrants(t, ctx, dsn)
	tw := buildTwins(t, dsn, twinOpts{})

	for i := 0; i < 10; i++ {
		pub := mustList(t, ctx, tw.public)
		in, err := tw.internal.ListAdmins(ctx, &iamv1.ListClusterAdminsRequest{})
		require.NoError(t, err)
		require.Equal(t, want, rosterOrder(pub, want), "read %d", i)
		require.Equal(t, rosterOrder(in, want), rosterOrder(pub, want), "read %d: the twin orders as the internal roster", i)
	}
}

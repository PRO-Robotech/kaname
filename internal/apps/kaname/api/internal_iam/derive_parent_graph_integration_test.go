// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam_test

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/corelib/pgtest"
	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/iampgtest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationscene"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Это пробы вывода и записи канонической регистрации, не доказательство mTLS
// либо full-bind. Дублёр gate изолирует личность; все parent/catalog/owning rows,
// записи фактов, зеркала, цепи и отказ API — настоящие адаптеры одной базы.
type parentGraphAPIWorld struct {
	t       *testing.T
	ctx     context.Context
	pool    *pgxpool.Pool
	handler *internaliam.Handler
	scene   registrationscene.Scene
	version time.Time
}

func newParentGraphAPIWorld(t *testing.T) *parentGraphAPIWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("requires PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Minute)
	t.Cleanup(cancel)
	cfg, err := pgxpool.ParseConfig(iampgtest.NewTestPostgres(t))
	require.NoError(t, err)
	cfg.MaxConns = 1
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	pgtest.ClosePoolAtEnd(t, pool)
	doc, err := os.ReadFile("../../../../manifest/testdata/probemod.children-fixture.yaml")
	require.NoError(t, err)
	m, err := manifest.Load(doc)
	require.NoError(t, err)
	// Буквальный canonical документ, включая project parent и public-read key.
	// Допуск задаётся значением; модель процесса не подменяется после старта.
	composed, report, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	require.NoError(t, err)
	admission, err := authzmodel.Admit(composed, report.KeyTerms...)
	require.NoError(t, err)
	require.True(t, admission.Admitted(), admission.Census())
	_, err = authzmodel.New(composed)
	require.NoError(t, err)
	_, err = modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(pool)).ApplyAll(ctx, []*manifest.Manifest{m})
	require.NoError(t, err)
	halves, err := kanamepg.NewCatalogRepo(pool).ReadCatalogHalves(ctx)
	require.NoError(t, err)
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	authority := registrationwriterfixture.Authority{Module: "probemod"}
	uc := internaliam.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(), kanamepg.NewResourceMirrorEmitter(), kanamepg.NewRegistrationTxBeginner(pool), kanamepg.NewCatalogTypeReader(), kanamepg.NewPublicReadPublisher(),
		accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), catalog.Fixed{F: facts}), kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader(),
	).WithRegistrationAuthority(authority).WithReconcile(kanamepg.NewReconcileEventEmitter())
	w := &parentGraphAPIWorld{t: t, ctx: ctx, pool: pool, handler: internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).WithResourceRegistrar(uc, authority), scene: registrationscene.Seed(t, ctx, pool)}
	require.NoError(t, pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&w.version))
	return w
}
func (w *parentGraphAPIWorld) request(subject, relation, object string, chain []string, scoped bool) *iamv1.RegisterResourceRequest {
	w.version = w.version.Add(time.Microsecond)
	r := &iamv1.RegisterResourceRequest{SubjectId: subject, Relation: relation, Object: object, ParentChain: append([]string(nil), chain...), SourceVersion: timestamppb.New(w.version)}
	if scoped {
		r.ParentProjectId = w.scene.Project
		r.ParentAccountId = w.scene.Account
	}
	return r
}
func (w *parentGraphAPIWorld) register(r *iamv1.RegisterResourceRequest) {
	w.t.Helper()
	_, err := w.handler.RegisterResource(w.ctx, r)
	require.NoError(w.t, err, "actual RegisterResource %s", r.Object)
}
func (w *parentGraphAPIWorld) box(id string) {
	w.t.Helper()
	w.register(w.request("project:"+w.scene.Project, "project", "probemod_box:"+id, w.scene.ProjectChain(), true))
}
func (w *parentGraphAPIWorld) item(id, box string, scoped bool) {
	w.t.Helper()
	chain := []string{"probemod_box:" + box}
	if scoped {
		chain = append(chain, w.scene.ProjectChain()...)
	}
	w.register(w.request("probemod_box:"+box, "box", "probemod_item:"+id, chain, scoped))
}
func (w *parentGraphAPIWorld) snapshot() map[string]string {
	w.t.Helper()
	out := map[string]string{}
	for _, table := range []string{"resource_mirror", "resource_parent_edge", "relation_fact", "fga_outbox", "resource_reconcile_outbox", "resource_registration_scope", "resource_registration_pointer", "resource_registration_retirement", "producer_source_receipt", "object_project_binding", "audit_outbox"} {
		var rows string
		require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT coalesce(jsonb_agg(to_jsonb(s) ORDER BY to_jsonb(s)::text),'[]'::jsonb)::text FROM `+pgx.Identifier{"kaname", table}.Sanitize()+` s`).Scan(&rows))
		out[table] = rows
	}
	return out
}
func (w *parentGraphAPIWorld) refused(r *iamv1.RegisterResourceRequest) {
	w.t.Helper()
	before := w.snapshot()
	response, err := w.handler.RegisterResource(w.ctx, r)
	require.Nil(w.t, response)
	require.Equal(w.t, codes.FailedPrecondition, status.Code(err), "actual hierarchy refusal: %v", err)
	require.Contains(w.t, status.Convert(err).Message(), r.Object+" parent scope does not match")
	require.Equal(w.t, before, w.snapshot(), "отказ не меняет бизнес/факты/цепи/журналы")
}
func (w *parentGraphAPIWorld) stored(typ, dotted, id string, want []string, scoped bool) {
	w.t.Helper()
	var project, account string
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT parent_project_id,parent_account_id FROM kaname.resource_mirror WHERE object_type=$1 AND object_id=$2`, dotted, id).Scan(&project, &account))
	if scoped {
		require.Equal(w.t, w.scene.Project, project)
		require.Equal(w.t, w.scene.Account, account)
	} else {
		require.Empty(w.t, project)
		require.Empty(w.t, account)
	}
	rows, err := w.pool.Query(w.ctx, `SELECT parent_type||':'||parent_id FROM kaname.resource_parent_edge WHERE object_type=$1 AND object_id=$2 ORDER BY depth`, typ, id)
	require.NoError(w.t, err)
	chain, err := pgx.CollectRows(rows, pgx.RowTo[string])
	require.NoError(w.t, err)
	require.Equal(w.t, want, chain)
}

func TestRegisterResourceCanonicalChildrenKeepsFullServerPath(t *testing.T) {
	w := newParentGraphAPIWorld(t)
	w.box("b1")
	w.box("b2")
	w.item("i1", "b1", true)
	chain := append([]string{"probemod_item:i1", "probemod_box:b1"}, w.scene.ProjectChain()...)
	request := w.request("probemod_item:i1", "item", "probemod_tag:t1", chain, true)
	for _, name := range []string{"forged_registered_box", "reordered", "fifth_link"} {
		t.Run(name, func(t *testing.T) {
			bad := proto.Clone(request).(*iamv1.RegisterResourceRequest)
			switch name {
			case "forged_registered_box":
				bad.ParentChain[1] = "probemod_box:b2"
			case "reordered":
				bad.ParentChain[0], bad.ParentChain[1] = bad.ParentChain[1], bad.ParentChain[0]
			case "fifth_link":
				bad.ParentChain = append(bad.ParentChain, "cluster:cluster_root")
			}
			// Тот же object, scope, version и tuple; меняется лишь утверждение о цепи.
			nested := *w
			nested.t = t
			nested.refused(bad)
		})
	}
	w.register(request)
	w.stored("probemod_tag", "probemod.tags", "t1", chain, true)
	var stands bool
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.relation_fact WHERE object_type='probemod_tag' AND object_id='t1' AND relation='item' AND subject='probemod_item:i1')`).Scan(&stands))
	require.True(t, stands)
	// После записи полная цепь остаётся допустимой при реальной повторной доставке.
	w.register(request)
}

func TestRegisterResourceCanonicalChildrenPreservesDP14Ceiling(t *testing.T) {
	w := newParentGraphAPIWorld(t)
	w.box("b1")
	w.item("i1", "b1", false)
	w.stored("probemod_item", "probemod.items", "i1", []string{"probemod_box:b1"}, false)
	request := w.request("probemod_item:i1", "item", "probemod_tag:t1", []string{"probemod_item:i1"}, false)
	bad := proto.Clone(request).(*iamv1.RegisterResourceRequest)
	bad.ParentChain = append(bad.ParentChain, "project:"+w.scene.Project)
	w.refused(bad)
	w.register(request)
	w.stored("probemod_tag", "probemod.tags", "t1", []string{"probemod_item:i1"}, false)
}

// Пять standing pointers законно накоплены последовательными регистрациями:
// каждая доказывает своего родителя, а старый tuple хранится до снятия. Новое
// admission дочернего tag обязано проверить весь граф и отвергнуть overflow;
// исторические refusal audit и cleanup этого item обязаны остаться доступны.
func TestRegisterResourceFiveStandingParentsKeepCleanupAndRefusalAudit(t *testing.T) {
	w := newParentGraphAPIWorld(t)
	for i := 1; i <= 5; i++ {
		box := fmt.Sprintf("cleanup-b%d", i)
		w.box(box)
		w.item("cleanup-item", box, true)
	}
	var facts, owned int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.relation_fact WHERE object_type='probemod_item' AND object_id='cleanup-item' AND relation='box'`).Scan(&facts))
	require.Equal(t, 5, facts, "Given: все пять настоящих Register оставили standing факты")
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.resource_registration_pointer WHERE module='probemod' AND object_type='probemod_item' AND object_id='cleanup-item' AND active`).Scan(&owned))
	require.Equal(t, 5, owned)

	// Область и каждый отдельный box законны. Отказ tag вызван именно полнотой
	// непосредственного fanout item, а не неизвестным объектом либо чужим проектом.
	chain := append([]string{"probemod_item:cleanup-item", "probemod_box:cleanup-b5"}, w.scene.ProjectChain()...)
	w.refused(w.request("probemod_item:cleanup-item", "item", "probemod_tag:cleanup-tag", chain, true))

	// Проверенная личность только для запуска настоящего refusal audit; fixture
	// gate продолжает изолировать авторизацию модуля и не доказывает mTLS.
	verified := grpcsrv.WithCertIdentityIn(w.ctx, grpcsrv.NewTrustDomain("kaname.test"), "spiffe://kaname.test/ns/modules/sa/kacho-probemod", true)
	actor, module, ok := authzguard.ModuleActor(verified)
	require.True(t, ok)
	require.Equal(t, "probemod", module)
	bad := w.request("user:cleanup-forbidden-owner", "owner", "probemod_item:cleanup-item", append([]string{"probemod_box:cleanup-b5"}, w.scene.ProjectChain()...), true)
	before := w.snapshot()
	response, err := w.handler.RegisterResource(verified, bad)
	require.Nil(t, response)
	require.Equal(t, codes.PermissionDenied, status.Code(err), "refusal audit не заменяет исходный отказ на Internal: %v", err)
	require.Equal(t, "permission denied", status.Convert(err).Message())
	after := w.snapshot()
	require.NotEqual(t, before["audit_outbox"], after["audit_outbox"], "отказ действительно записан отдельной TX")
	delete(before, "audit_outbox")
	delete(after, "audit_outbox")
	require.Equal(t, before, after, "отказ меняет только ожидаемый аудит")
	checkAudit := func(event, outcome string, wantTenant *string) {
		t.Helper()
		var count int
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type=$1 AND event_payload->'object'->>'id'='cleanup-item' AND event_payload->>'outcome'=$2`, event, outcome).Scan(&count))
		require.Equal(t, 1, count)
		var payload []byte
		var tenant *string
		require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT event_payload,tenant_account_id FROM kaname.audit_outbox WHERE event_type=$1 AND event_payload->'object'->>'id'='cleanup-item' AND event_payload->>'outcome'=$2`, event, outcome).Scan(&payload, &tenant))
		var recorded struct {
			Actor       string   `json:"actor"`
			Module      string   `json:"module"`
			ParentChain []string `json:"parent_chain"`
		}
		require.NoError(t, json.Unmarshal(payload, &recorded))
		require.Equal(t, actor, recorded.Actor)
		require.Equal(t, module, recorded.Module)
		require.Equal(t, wantTenant, tenant)
		require.Equal(t, append([]string{"probemod_box:cleanup-b1"}, w.scene.ProjectChain()...), recorded.ParentChain, "прежний детерминированный audit выбирает первый standing parent")
	}
	checkAudit(internaliam.AuditEventResourceRegistered, "permission_denied", &w.scene.Account)

	w.version = w.version.Add(time.Microsecond)
	unregistered, err := w.handler.UnregisterResource(verified, &iamv1.UnregisterResourceRequest{SubjectId: "probemod_box:cleanup-b5", Relation: "box", Object: "probemod_item:cleanup-item", SourceVersion: timestamppb.New(w.version)})
	require.NoError(t, err)
	require.NotNil(t, unregistered)
	for _, query := range []string{
		`SELECT count(*) FROM kaname.resource_mirror WHERE object_type='probemod.items' AND object_id='cleanup-item'`,
		`SELECT count(*) FROM kaname.resource_parent_edge WHERE object_type='probemod_item' AND object_id='cleanup-item'`,
		`SELECT count(*) FROM kaname.relation_fact WHERE object_type='probemod_item' AND object_id='cleanup-item'`,
		`SELECT count(*) FROM kaname.resource_registration_pointer WHERE object_type='probemod_item' AND object_id='cleanup-item' AND active`,
	} {
		var remaining int
		require.NoError(t, w.pool.QueryRow(w.ctx, query).Scan(&remaining))
		require.Zero(t, remaining, query)
	}
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.resource_registration_pointer WHERE module='probemod' AND object_type='probemod_item' AND object_id='cleanup-item' AND NOT active`).Scan(&owned))
	require.Equal(t, 5, owned, "все owned pointers сняты, история сохранена")
	// Исторический Unregister не заполняет tenant: здесь проверяется NULL,
	// а не добавляется новая семантика аудита ради oracle.
	checkAudit(internaliam.AuditEventResourceUnregistered, "unregistered", nil)
	var boxes int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.resource_mirror WHERE object_type='probemod.boxes'`).Scan(&boxes))
	require.Equal(t, 5, boxes, "cleanup ребёнка не снимает его родителей")
}

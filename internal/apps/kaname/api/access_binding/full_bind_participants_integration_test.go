// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"log/slog"
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Фабрика наблюдает настоящий материализатор только у выбранной тестовой пробы.
// Без фабрики все прежние вызовы получают прежний указатель напрямую.
type fullBindSelectorObserverFactory func(*reconcile.Reconciler) accessbindingapp.SelectorReconciler

type fullBindSetupAwaiter interface {
	awaitSetup(context.Context, string, string) error
}

// installFullBindParticipants меняет только отдельный FB world. Bootstrap
// завершается ДО lifecycle; исследуемые роли и выдачи затем идут через API
// и реальные configured factories обычного LOGIN.
func (w *fullBindWorld) installFullBindParticipants(observers ...fullBindSelectorObserverFactory) {
	w.t.Helper()
	ownerPool, ownerRepo := w.pool, w.repo
	require.LessOrEqual(w.t, len(observers), 1)
	var bootstrapAwaiter fullBindSetupAwaiter
	if len(observers) == 1 {
		require.NotNil(w.t, observers[0])
		// Авто-выдача владельца тоже создаётся публичным Create до activation.
		// Сохраняем его исходные зависимости, но наблюдаем и этот ранний хвост.
		selector := observers[0](w.rec)
		require.NotNil(w.t, selector)
		var ok bool
		bootstrapAwaiter, ok = selector.(fullBindSetupAwaiter)
		require.True(w.t, ok, "наблюдатель настройки должен ожидать настоящий callback")
		bootstrapCreate := accessbindingapp.NewCreateAccessBindingUseCase(ownerRepo, w.ops, catalog.Fixed{F: w.facts}).
			WithRelationStore(w.door, nil).WithReconciler(selector)
		w.ab = accessbindingapp.NewHandler(bootstrapCreate, nil, nil, nil, nil, nil, nil)
	}
	// Указатель, создаваемый прежним ownerMayRemove, подтверждён owning rows;
	// auto-binding принадлежит только usrA и никогда не добавляется actor usrD.
	var actualOwner, actualAccount string
	require.NoError(w.t, ownerPool.QueryRow(w.ctx, `SELECT a.owner_user_id,p.account_id FROM kaname.projects p JOIN kaname.accounts a ON a.id=p.account_id WHERE p.id=$1`, string(w.prjA)).Scan(&actualOwner, &actualAccount))
	require.Equal(w.t, string(w.usrA), actualOwner)
	require.Equal(w.t, string(w.accA), actualAccount)
	w.ownerMayRemove("FB: структурная auto-binding владельца до activation")
	require.NoError(w.t, ownerPool.QueryRow(w.ctx, `SELECT id FROM kaname.access_bindings WHERE role_id=$1 AND subject_type='user' AND subject_id=$2 AND resource_type='account' AND resource_id=$3 AND status='ACTIVE' AND revoked_at IS NULL`, domain.OwnerRoleID, string(w.usrA), string(w.accA)).Scan(&w.ownerBinding))
	if bootstrapAwaiter != nil {
		require.NoError(w.t, bootstrapAwaiter.awaitSetup(w.ctx, "iam.accessBinding", string(w.ownerBinding)))
	}
	require.NoError(w.t, w.rec.ReconcileBinding(w.ctx, w.ownerBinding))

	// Та же композиция, что installATCModel в TestMain, и обе половины
	// настоящего DB-каталога. Bundle не строится из усечённой cached Facts.
	composed, report, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{w.manifest(false)})
	require.NoError(w.t, err)
	halves, err := kanamepg.NewCatalogRepo(ownerPool).ReadCatalogHalves(w.ctx)
	require.NoError(w.t, err)
	bundle, err := granteffect.NewBundle(w.ctx, composed, halves, granteffect.ProjectorVersion, report.KeyTerms...)
	require.NoError(w.t, err)
	require.NoError(w.t, ownerRepo.PrepareAuthorityBundle(w.ctx, bundle))
	facts, err := catalog.NewFacts(halves)
	require.NoError(w.t, err)
	source := catalog.Fixed{F: facts}

	// Отдельная LOGIN connection: SET ROLE поверх migration owner не годится.
	login := "full_bind_runtime_" + strings.ReplaceAll(ids.NewID("rol"), "-", "_")
	quoted := pgx.Identifier{login}.Sanitize()
	password := ids.NewID("pwd")
	_, err = ownerPool.Exec(w.ctx, "CREATE ROLE "+quoted+" LOGIN PASSWORD '"+strings.ReplaceAll(password, "'", "''")+"' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT")
	require.NoError(w.t, err)
	w.t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = ownerPool.Exec(ctx, "DROP OWNED BY "+quoted)
		_, _ = ownerPool.Exec(ctx, "DROP ROLE "+quoted)
	})
	_, err = ownerPool.Exec(w.ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, login)
	require.NoError(w.t, err)
	cfg := ownerPool.Config()
	cfg.ConnConfig.User, cfg.ConnConfig.Password = login, password
	cfg.AfterConnect = nil
	runtime, err := pgxpool.NewWithConfig(w.ctx, cfg)
	require.NoError(w.t, err)
	w.t.Cleanup(runtime.Close)
	var current, session string
	require.NoError(w.t, runtime.QueryRow(w.ctx, `SELECT current_user,session_user`).Scan(&current, &session))
	require.Equal(w.t, login, current)
	require.Equal(w.t, login, session)
	repo := kanamepg.New(runtime, nil)
	require.NoError(w.t, repo.ValidateAuthorityRuntime(w.ctx))
	handed, err := repo.LoadAuthorityBundle(w.ctx, composed, report.KeyTerms...)
	require.NoError(w.t, err)
	require.Equal(w.t, bundle.Identity(), handed.Identity())
	writers, err := kanamepg.NewGrantPolicyWriters(w.ctx, repo, handed)
	require.NoError(w.t, err)
	participant, err := kanamepg.NewGroupMembershipParticipant(w.ctx, repo, handed)
	require.NoError(w.t, err)
	stages, err := participant.NewBindingStageParticipant(w.ctx, slog.Default())
	require.NoError(w.t, err)
	rec := reconcile.New(kanamepg.NewReconcileAdapter(runtime, source), slog.Default(), source)
	require.NoError(w.t, rec.WithStagedBindingReconciler(stages))
	resources, err := kanamepg.NewResourceObjectParticipant(w.ctx, repo, handed)
	require.NoError(w.t, err)
	resourceBeginner, err := resources.RegistrationTxBeginner(runtime)
	require.NoError(w.t, err)
	objects, err := resources.NewObjectReconciler(slog.Default())
	require.NoError(w.t, err)
	require.NoError(w.t, rec.WithObjectReconciler(objects))
	door := authzcascade.WrapAdmitted(relverdict.NewAsker(runtime), personmarks.New(runtime))
	ops := operations.NewRepo(runtime, "kaname")
	keys := kanamepg.NewRegisteredKeys(runtime)
	var selector accessbindingapp.SelectorReconciler = rec
	if len(observers) == 1 {
		selector = observers[0](rec)
		require.NotNil(w.t, selector)
	}
	create := accessbindingapp.NewCreateAccessBindingUseCase(repo, ops, source).
		WithRelationStore(door, slog.Default()).WithRegisteredKeys(keys).
		WithBindingDecisions(writers).WithReconciler(selector)
	del := accessbindingapp.NewDeleteAccessBindingUseCase(repo, ops).WithRelationStore(door, slog.Default()).WithBindingWithdrawal(stages)
	get := accessbindingapp.NewGetAccessBindingUseCase(repo).WithRelationStore(door, slog.Default())
	revoke := accessbindingapp.NewRevokeAccessBindingUseCase(repo, ops).WithRelationStore(door, slog.Default()).WithBindingWithdrawal(stages)
	w.ab = accessbindingapp.NewHandler(create, del, get, nil, nil, nil, nil).WithRevoke(revoke)
	w.roles = roleapp.NewHandler(roleapp.NewCreateRoleUseCase(repo, ops, source).
		WithRelationStore(door, slog.Default()).WithRegisteredKeys(keys).
		WithObjectReconciler(rec).WithGrantReferencePlans(w.plans).WithRoleAuthorityWriter(writers), nil, nil, nil, nil)
	w.pool, w.repo, w.ops, w.door, w.rec = runtime, repo, ops, door, rec
	w.facts, w.stages = facts, stages
	// FB09 сохраняет будущую регистрацию ПОСЛЕ решения и activation.
	// Её фактический UC и object hooks используют тот же runtime participant.
	w.reg = internaliam.NewRegisterResourceUseCase(
		kanamepg.NewFGAOutboxEmitter(), kanamepg.NewResourceMirrorEmitter(),
		kanamepg.NewPoolTxBeginner(runtime), kanamepg.NewCatalogTypeReader(), kanamepg.NewPublicReadPublisher(),
		accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), source),
		kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader(),
	).WithRegistrationAuthority(registrationwriterfixture.Authority{Module: "registry"}).
		WithResourceTxBeginner(resourceBeginner).WithObjectReconciler(rec, slog.Default())
	require.NoError(w.t, ownerRepo.ActivateAuthorityBundle(w.ctx, bundle))
	var phase, enforcement string
	// Закрытое состояние наблюдает fixture owner; runtime ACL и actor-пути
	// остаются прежними и проверяются отдельным настоящим LOGIN.
	require.NoError(w.t, ownerPool.QueryRow(w.ctx, `SELECT a.phase,p.enforcement FROM kaname.authority_semantic_identity a CROSS JOIN kaname.authority_writer_protocol p`).Scan(&phase, &enforcement))
	require.Equal(w.t, "active", phase)
	require.Equal(w.t, "strict", enforcement)
	w.t.Log("FB explicit mode: ordinary LOGIN, active/strict; binding, role, registration and object participants connected")
}

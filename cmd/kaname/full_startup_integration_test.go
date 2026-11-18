// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/types/known/fieldmaskpb"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/observability/metrics"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/servicemanifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/activewayin"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Только личности и owning rows до cutover; исследуемые роли/выдачи создаёт
// реальный production handler. Авторизующих tuples или permissive ports нет.
func fullStartupSeedPerson(t *testing.T, ctx context.Context, pool *pgxpool.Pool, label string) (string, string) {
	t.Helper()
	user, account := ids.NewID(domain.PrefixUser), ids.NewID(domain.PrefixAccount)
	tx, err := pool.Begin(ctx)
	require.NoError(t, err)
	defer func() { _ = tx.Rollback(ctx) }()
	_, err = tx.Exec(ctx, `INSERT INTO kaname.users(id,account_id,external_id,email,display_name,invite_status,email_verified_at)
        VALUES($1,$2,$3,$4,$5,'ACTIVE',clock_timestamp())`, user, account, "full-startup-"+user, user+"@example.test", label)
	require.NoError(t, err)
	_, err = tx.Exec(ctx, `INSERT INTO kaname.accounts(id,name,owner_user_id,labels) VALUES($1,$2,$3,'{}'::jsonb)`, account, "full-startup-"+account, user)
	require.NoError(t, err)
	activewayin.Seed(t, ctx, tx)
	require.NoError(t, tx.Commit(ctx))
	return user, account
}

func fullStartupRuntimePool(t *testing.T, ctx context.Context, owner *pgxpool.Pool) *pgxpool.Pool {
	t.Helper()
	login, password := "full_startup_"+ids.NewID("rol"), ids.NewID("pwd")
	quoted := pgx.Identifier{login}.Sanitize()
	_, err := owner.Exec(ctx, "CREATE ROLE "+quoted+" LOGIN PASSWORD '"+password+"' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT")
	require.NoError(t, err)
	t.Cleanup(func() {
		cleanup, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_, _ = owner.Exec(cleanup, "DROP OWNED BY "+quoted)
		_, _ = owner.Exec(cleanup, "DROP ROLE "+quoted)
	})
	_, err = owner.Exec(ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, login)
	require.NoError(t, err)
	cfg := owner.Config()
	cfg.ConnConfig.User, cfg.ConnConfig.Password, cfg.AfterConnect = login, password, nil
	if trace, ok := ctx.Value(fullStartupDiagnosticScope{}).(*fullStartupDiagnostic); ok {
		cfg.ConnConfig.Tracer = trace.combine(cfg.ConnConfig.Tracer)
	}
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	require.NoError(t, pool.Ping(ctx))
	return pool
}

func fullStartupTestBundle(t *testing.T, ctx context.Context, pool *pgxpool.Pool) (preparedModel, *granteffect.Bundle) {
	t.Helper()
	model, err := prepareComposedModel(slog.Default(), nil)
	require.NoError(t, err)
	rows, err := kanamepg.NewCatalogRepo(pool).ReadCatalogHalves(ctx)
	require.NoError(t, err)
	bundle, err := granteffect.NewBundle(ctx, model.text, rows, granteffect.ProjectorVersion, model.report.KeyTerms...)
	require.NoError(t, err)
	return model, bundle
}

func TestFullStartupInvalidSelectorRefusesBeforeDatabase(t *testing.T) {
	_, profile, err := prepareFullStartup(context.Background(), config.Config{AuthorityProtocol: config.AuthorityProtocolConfig{FullSemantics: true}}, nil, slog.Default())
	require.ErrorContains(t, err, "requires participation=participant")
	require.Nil(t, profile)
}

// Lifecycle выполняется явно владельцем в Given. Сборщик startup не получает
// owner и не активирует схему: разные фазы проверяются настоящим runtime LOGIN.
func TestFullStartupStagedCompatibilityAndUnactivatedFullRefusal(t *testing.T) {
	ctx, owner, _, _ := bootRolesOnLiveBase(t)
	runtime := fullStartupRuntimePool(t, ctx, owner)
	_, bundle := fullStartupTestBundle(t, ctx, owner)
	cfg := config.Config{}
	original := ctx
	got, profile, err := prepareFullStartup(ctx, cfg, runtime, slog.Default())
	require.NoError(t, err)
	require.Nil(t, profile)
	require.Equal(t, original, got, "false/false не прикрепляет full profile")
	cfg.AuthorityProtocol = config.AuthorityProtocolConfig{Participation: "participant", FullSemantics: true}
	_, profile, err = prepareFullStartup(ctx, cfg, runtime, slog.Default())
	require.Error(t, err, "пустой full bundle не включает legacy fallback")
	require.Nil(t, profile)
	repository := kanamepg.New(owner, nil)
	require.NoError(t, repository.StageFullAuthorityBundle(ctx, bundle))
	_, profile, err = prepareFullStartup(ctx, cfg, runtime, slog.Default())
	require.Error(t, err, "prepared full bundle ещё не active/strict")
	require.Nil(t, profile)
	require.NoError(t, repository.ActivateFullAuthorityBundle(ctx, bundle))
	cfg.AuthorityProtocol.FullSemantics = false
	_, profile, err = prepareFullStartup(ctx, cfg, runtime, slog.Default())
	require.Error(t, err, "staged writer не стартует поверх full2")
	require.Nil(t, profile)
}

func fullStartupAwait(t *testing.T, ctx context.Context, ops operations.Repo, id string) *operations.Operation {
	t.Helper()
	var done *operations.Operation
	require.Eventually(t, func() bool {
		var err error
		done, err = ops.Get(ctx, id)
		require.NoError(t, err)
		return done.Done
	}, 20*time.Second, 20*time.Millisecond)
	require.Nil(t, done.Error)
	return done
}

// Профиль записи объявляется посадкой, а не умолчанием config.Load.
// Значения того же класса, что loginLaneCfg и production profile: штатные ENV
// bindings проходят настоящий загрузчик и закрытый перечень passwordverify.
func fullStartupCompositionConfig(t *testing.T) config.Config {
	t.Helper()
	t.Setenv("KANAME_AUTHN__LOGIN__HASHER_FORMAT", "argon2id")
	t.Setenv("KANAME_AUTHN__LOGIN__HASHER_MEMORY", "65536")
	t.Setenv("KANAME_AUTHN__LOGIN__HASHER_ITERATIONS", "3")
	t.Setenv("KANAME_AUTHN__LOGIN__HASHER_PARALLELISM", "4")
	cfg, err := config.Load("")
	require.NoError(t, err)
	require.NoError(t, cfg.AuthN.Login.ValidateHasher())
	require.Equal(t, loginLaneCfg().AuthN.Login.Declared(), cfg.AuthN.Login.Declared())
	return cfg
}

// Один production factory подключает staged participants И все full ports.
// Удаление wireFullStartupServices должно ломать положительный non-admin Create;
// никаких WithBindingDecisions/WithRoleAuthorityWriter из фикстуры здесь нет.
func TestFullStartupProductionCompositionGrantsOnlyWithSeparateCreate(t *testing.T) {
	cfg := fullStartupCompositionConfig(t)
	ctx, ownerPool, _, logger := bootRolesOnLiveBase(t)
	trace := &fullStartupDiagnostic{started: time.Now()}
	ctx = context.WithValue(ctx, fullStartupDiagnosticScope{}, trace)
	// Зарегистрировано до runtime pool: LIFO печатает только после его Close.
	t.Cleanup(func() { trace.report(t) })
	ownerID, accountID := fullStartupSeedPerson(t, ctx, ownerPool, "owner")
	actorID, _ := fullStartupSeedPerson(t, ctx, ownerPool, "actor")
	recipientID, _ := fullStartupSeedPerson(t, ctx, ownerPool, "recipient")
	// Owning rows создаются до full cutover обычным прежним writer.
	// Это не настройка исследуемых metadata ports: их подключит только production factory.
	seedWriter, err := kanamepg.New(ownerPool, nil).Writer(ctx)
	require.NoError(t, err)
	defer func() { _ = seedWriter.Rollback(ctx) }()
	project, err := seedWriter.ProjectsW().Insert(ctx, domain.Project{
		ID: domain.ProjectID(ids.NewID(domain.PrefixProject)), AccountID: domain.AccountID(accountID),
		Name: domain.ProjectName("startup-metadata-project"), Labels: domain.Labels{},
	})
	require.NoError(t, err)
	serviceAccount, err := seedWriter.ServiceAccountsW().Insert(ctx, domain.ServiceAccount{
		ID: domain.ServiceAccountID(ids.NewID(domain.PrefixServiceAccount)), AccountID: domain.AccountID(accountID),
		Name: domain.SvcAccountName("startup-metadata-sa"),
	})
	require.NoError(t, err)
	// Та же структурная проекция, которую Project.Create со-коммитит со строкой.
	// Одного projects.account_id недостаточно: native ancestry читает relation_fact.
	projectFacts := project.StructuralFacts()
	projectTuples := make([]service.RelationTuple, 0, len(projectFacts))
	for _, fact := range projectFacts {
		projectTuples = append(projectTuples, service.RelationTuple{User: fact.User, Relation: fact.Relation, Object: fact.Object})
	}
	require.NoError(t, seedWriter.EmitFGARelationWrite(ctx, projectTuples))
	require.NoError(t, seedWriter.Commit(ctx))
	for _, person := range []string{actorID, recipientID} {
		_, err := ownerPool.Exec(ctx, `INSERT INTO kaname.memberships(id,user_id,account_id,state)
            VALUES(kaname.membership_mirror_id($1,$2),$1,$2,'ACTIVE')`, person, accountID)
		require.NoError(t, err)
	}
	runtime := fullStartupRuntimePool(t, ctx, ownerPool)
	model, bundle := fullStartupTestBundle(t, ctx, ownerPool)
	privileged := kanamepg.New(ownerPool, nil)
	require.NoError(t, privileged.StageFullAuthorityBundle(ctx, bundle))
	require.NoError(t, privileged.ActivateFullAuthorityBundle(ctx, bundle))
	cfg.AuthorityProtocol = config.AuthorityProtocolConfig{Participation: "participant", FullSemantics: true}
	// Тот же штатный IAM manifest на входе реальной production Module delivery.
	// Он не добавляет новый тип/модель, поэтому существующая full identity сохраняется.
	deliveryDir := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(deliveryDir, "iam"), 0700))
	require.NoError(t, os.WriteFile(filepath.Join(deliveryDir, "iam", "manifest.yaml"), servicemanifest.Raw(), 0600))
	cfg.Manifests.Dir = deliveryDir
	ctx, profile, err := prepareFullStartup(ctx, cfg, runtime, logger)
	require.NoError(t, err)
	require.NotNil(t, profile)
	rows, err := kanamepg.NewCatalogRepo(runtime).ReadCatalogHalves(ctx)
	require.NoError(t, err)
	facts, err := catalog.NewFacts(rows)
	require.NoError(t, err)
	ops := operations.NewRepo(runtime, "kaname")
	operations.Start()
	// Тот же настоящий constructor, что buildServices; ошибка здесь завершает
	// тест с cleanup, а не весь Go test процесс через production log.Fatal.
	interactiveProvider, err := interactiveClientProvider(cfg, kanamepg.NewOAuthCeremonyRepo(runtime))
	require.NoError(t, err)
	require.IsType(t, &kanamepg.OwnInteractiveClientProvider{}, interactiveProvider)
	missingHasher := cfg
	missingHasher.AuthN.Login.HasherFormat = ""
	refusedProvider, err := interactiveClientProvider(missingHasher, kanamepg.NewOAuthCeremonyRepo(runtime))
	require.ErrorContains(t, err, "password_hasher")
	require.Nil(t, refusedProvider, "без объявления класса нет permissive executor fallback")
	svcs := buildServices(runtime, nil, ops, profile.primary, profile.primary, catalog.Fixed{F: facts},
		kanamepg.NewCatalogRepo(runtime), metrics.NewRegistry(), cfg, testModuleRoster(), nil, logger, model.plans)
	participants, err := wireFullStartupServices(ctx, profile, profile.primary, svcs, runtime)
	require.NoError(t, err)
	// Тот же participant, что production serve передаёт buildLoginLane:
	// открываем настоящие stores на active/full2 DB; legacy fallback здесь бы отказал.
	registration, recovery, err := humanAdmissionStores(runtime, cfg.AuthorityProtocol, participants.admission)
	require.NoError(t, err)
	registrationWriter, err := registration.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, registrationWriter.Rollback(ctx))
	recoveryWriter, err := recovery.RecoveryCompletionWriter(ctx, domain.UserID(actorID))
	require.NoError(t, err)
	verified, err := recoveryWriter.AddressVerified(ctx, domain.UserID(actorID))
	require.NoError(t, err)
	require.True(t, verified, "login recovery store читает реального verified человека")
	require.NoError(t, recoveryWriter.Rollback(ctx))
	// Resource handle также настоящий: Begin исполняет full protocol entry.
	resourceBeginner, err := participants.resources.RegistrationTxBeginner(runtime)
	require.NoError(t, err)
	resourceTX, err := resourceBeginner.Begin(ctx)
	require.NoError(t, err)
	require.NoError(t, resourceTX.Rollback(ctx))
	as := func(id string) context.Context {
		return operations.WithPrincipal(ctx, operations.Principal{Type: "user", ID: id})
	}
	makeRole := func(name string, rule *iamv1.Rule) string {
		op, e := svcs.roleHandler.Create(as(ownerID), &iamv1.CreateRoleRequest{Name: name, Rules: []*iamv1.Rule{rule},
			DefinitionTier: &iamv1.DefinitionTier{TierType: "iam.account", TierId: accountID}})
		require.NoError(t, e)
		fullStartupAwait(t, ctx, ops, op.GetId())
		var md iamv1.CreateRoleMetadata
		require.NoError(t, op.GetMetadata().UnmarshalTo(&md))
		require.NotEmpty(t, md.GetRoleId())
		return md.GetRoleId()
	}
	ordinary := func() *iamv1.Rule {
		return &iamv1.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get", "list"}}
	}
	source := makeRole("startup_source", ordinary())
	proposed := makeRole("startup_proposed", ordinary())
	require.NotEqual(t, source, proposed)
	capability := makeRole("startup_create", &iamv1.Rule{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}})
	request := func(subject, role string) *iamv1.CreateAccessBindingRequest {
		return &iamv1.CreateAccessBindingRequest{Subjects: []*iamv1.Subject{{Type: iamv1.SubjectType_SUBJECT_TYPE_USER, Id: subject}}, RoleId: role,
			ScopeType: "iam.account", ScopeId: accountID, Target: &iamv1.AccessTarget{Target: &iamv1.AccessTarget_AllInScope{AllInScope: &iamv1.AccessTargetAllInScope{}}}}
	}
	grant := func(actor string, req *iamv1.CreateAccessBindingRequest) string {
		op, e := svcs.accessBindingHandler.Create(as(actor), req)
		require.NoError(t, e)
		fullStartupAwait(t, ctx, ops, op.GetId())
		var md iamv1.CreateAccessBindingMetadata
		require.NoError(t, op.GetMetadata().UnmarshalTo(&md))
		require.NotEmpty(t, md.GetAccessBindingId())
		return md.GetAccessBindingId()
	}
	ask := func(subject string, want relverdict.Verdict) {
		require.Eventually(t, func() bool {
			tx, e := runtime.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
			require.NoError(t, e)
			defer func() { _ = tx.Rollback(ctx) }()
			got, _, e := relverdict.Ask(ctx, tx, relverdict.Query{PreparedPlans: model.plans,
				Subject: "user:" + subject, Relation: "v_get", ObjectType: "account", ObjectID: accountID})
			require.NoError(t, e, "Unknown/error не является Deny")
			return got == want
		}, 20*time.Second, 30*time.Millisecond)
	}
	grant(ownerID, request(actorID, source))
	ask(actorID, relverdict.Allow)
	ask(recipientID, relverdict.Deny)
	req := request(recipientID, proposed)
	before := 0
	require.NoError(t, runtime.QueryRow(ctx, `SELECT count(*) FROM kaname.access_bindings WHERE subject_id=$1 AND role_id=$2`, recipientID, proposed).Scan(&before))
	op, err := svcs.accessBindingHandler.Create(as(actorID), req)
	require.Nil(t, op)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Equal(t, "permission denied", status.Convert(err).Message())
	after := -1
	require.NoError(t, runtime.QueryRow(ctx, `SELECT count(*) FROM kaname.access_bindings WHERE subject_id=$1 AND role_id=$2`, recipientID, proposed).Scan(&after))
	require.Equal(t, before, after)
	ask(actorID, relverdict.Allow)
	ask(recipientID, relverdict.Deny)
	grant(ownerID, request(actorID, capability))
	id := grant(actorID, req)
	var savedRole, savedSubject, savedScope, state string
	require.NoError(t, runtime.QueryRow(ctx, `SELECT role_id,subject_id,resource_id,status FROM kaname.access_bindings WHERE id=$1`, id).Scan(&savedRole, &savedSubject, &savedScope, &state))
	require.Equal(t, proposed, savedRole)
	require.Equal(t, recipientID, savedSubject)
	require.Equal(t, accountID, savedScope)
	require.Equal(t, "ACTIVE", state)
	ask(recipientID, relverdict.Allow)
	// Та же общая background composition, что serve: handles из public factory,
	// реальный PG binding reconcile и независимый lower-port контроль после него.
	background := reconcile.New(kanamepg.NewReconcileAdapter(runtime, catalog.Fixed{F: facts}), logger, catalog.Fixed{F: facts})
	require.NoError(t, wireBackgroundAuthorityParticipants(background, participants.bindings, participants.objects, participants.groups))
	require.NoError(t, background.ReconcileBinding(ctx, domain.AccessBindingID(id)))
	ask(recipientID, relverdict.Allow)
	// Реальные публичные Update handlers используют те же UC из buildServices.
	// Дано: обычный recipient получает update через production Role/Binding, без ручных ports.
	metadataRole := makeRole("startup_metadata", &iamv1.Rule{Module: "iam",
		Resources: []string{"account", "project", "serviceAccount"}, Verbs: []string{"update"}})
	metadataBinding := grant(ownerID, request(recipientID, metadataRole))
	// Operation.done гарантирует durable binding, но не detached materialization.
	// Вызываем тот же настоящий background reconciler из production composition.
	require.NoError(t, background.ReconcileBinding(ctx, domain.AccessBindingID(metadataBinding)))
	// Дано проверяется отдельно от Update: native verb и совместимый editor tier
	// существуют у recipient; actor не получил их вместе с отдельным CreateBinding.
	for _, object := range []struct {
		ref  string
		tier bool
	}{
		{"account:" + accountID, true},
		{"project:" + string(project.ID), true},
		{"iam_service_account:" + string(serviceAccount.ID), false},
	} {
		for _, principal := range []struct {
			id      string
			allowed bool
		}{
			{recipientID, true},
			{actorID, false},
		} {
			relations := []string{"v_update"}
			if object.tier {
				relations = append(relations, "editor")
			}
			for _, relation := range relations {
				require.Eventually(t, func() bool {
					allowed, e := svcs.ownGates.Check(as(principal.id), "user:"+principal.id, relation, object.ref)
					require.NoError(t, e, "ошибка авторитета не является Deny")
					return allowed == principal.allowed
				}, 20*time.Second, 20*time.Millisecond, "metadata Given: %s %s %s", principal.id, relation, object.ref)
			}
		}
	}
	description := "production metadata committed"
	patchMask := &fieldmaskpb.FieldMask{Paths: []string{"description"}}
	accountOp, err := svcs.accountHandler.Update(as(recipientID), &iamv1.UpdateAccountRequest{
		AccountId: accountID, Description: description, UpdateMask: patchMask})
	require.NoError(t, err)
	require.NotNil(t, accountOp)
	fullStartupAwait(t, ctx, ops, accountOp.GetId())
	projectOp, err := svcs.projectHandler.Update(as(recipientID), &iamv1.UpdateProjectRequest{
		ProjectId: string(project.ID), Description: description, UpdateMask: patchMask})
	require.NoError(t, err)
	require.NotNil(t, projectOp)
	fullStartupAwait(t, ctx, ops, projectOp.GetId())
	serviceAccountOp, err := svcs.serviceAccountHandler.Update(as(recipientID), &iamv1.UpdateServiceAccountRequest{
		ServiceAccountId: string(serviceAccount.ID), Description: description, UpdateMask: patchMask})
	require.NoError(t, err)
	require.NotNil(t, serviceAccountOp)
	fullStartupAwait(t, ctx, ops, serviceAccountOp.GetId())
	var durableDescriptions int
	require.NoError(t, runtime.QueryRow(ctx, `SELECT
        (SELECT count(*) FROM kaname.accounts WHERE id=$1 AND description=$4)+
        (SELECT count(*) FROM kaname.projects WHERE id=$2 AND description=$4)+
        (SELECT count(*) FROM kaname.service_accounts WHERE id=$3 AND description=$4)`,
		accountID, string(project.ID), string(serviceAccount.ID), description).Scan(&durableDescriptions))
	require.Equal(t, 3, durableDescriptions, "все три handler завершили durable metadata запись")
	// Оба state RPC используют сохранённые UC из той же production composition.
	disabled, err := svcs.serviceAccountHandler.Disable(context.WithValue(as(recipientID), fullStartupDiagnosticOperation{}, "disable"), &iamv1.DisableServiceAccountRequest{ServiceAccountId: string(serviceAccount.ID)})
	require.NoError(t, err)
	fullStartupAwait(t, ctx, ops, disabled.GetId())
	var enabled bool
	require.NoError(t, runtime.QueryRow(ctx, `SELECT enabled FROM kaname.service_accounts WHERE id=$1`, string(serviceAccount.ID)).Scan(&enabled))
	require.False(t, enabled)
	enabledOp, err := svcs.serviceAccountHandler.Enable(context.WithValue(as(recipientID), fullStartupDiagnosticOperation{}, "enable"), &iamv1.EnableServiceAccountRequest{ServiceAccountId: string(serviceAccount.ID)})
	require.NoError(t, err)
	fullStartupAwait(t, ctx, ops, enabledOp.GetId())
	require.NoError(t, runtime.QueryRow(ctx, `SELECT enabled FROM kaname.service_accounts WHERE id=$1`, string(serviceAccount.ID)).Scan(&enabled))
	require.True(t, enabled)
	snapshotMetadata := func() string {
		var snapshot string
		require.NoError(t, runtime.QueryRow(ctx, `SELECT jsonb_build_array(
            (SELECT to_jsonb(a) FROM kaname.accounts a WHERE id=$1),
            (SELECT to_jsonb(p) FROM kaname.projects p WHERE id=$2),
            (SELECT to_jsonb(s) FROM kaname.service_accounts s WHERE id=$3))::text`,
			accountID, string(project.ID), string(serviceAccount.ID)).Scan(&snapshot))
		return snapshot
	}
	beforeDeniedMetadata := snapshotMetadata()
	// Actor имеет get/list и отдельный createBinding, но не metadata update.
	deniedAccount, err := svcs.accountHandler.Update(as(actorID), &iamv1.UpdateAccountRequest{
		AccountId: accountID, Description: "denied account", UpdateMask: patchMask})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Nil(t, deniedAccount)
	deniedProject, err := svcs.projectHandler.Update(as(actorID), &iamv1.UpdateProjectRequest{
		ProjectId: string(project.ID), Description: "denied project", UpdateMask: patchMask})
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Nil(t, deniedProject)
	// SA admission проверяет только authenticated; отказ writer обязан стать terminal error LRO.
	deniedSA, err := svcs.serviceAccountHandler.Update(as(actorID), &iamv1.UpdateServiceAccountRequest{
		ServiceAccountId: string(serviceAccount.ID), Description: "denied service account", UpdateMask: patchMask})
	require.NoError(t, err)
	require.NotNil(t, deniedSA)
	var deniedDone *operations.Operation
	require.Eventually(t, func() bool {
		deniedDone, err = ops.Get(ctx, deniedSA.GetId())
		require.NoError(t, err)
		return deniedDone.Done
	}, 20*time.Second, 20*time.Millisecond)
	require.NotNil(t, deniedDone.Error)
	require.Equal(t, int32(codes.PermissionDenied), deniedDone.Error.Code)
	require.Equal(t, beforeDeniedMetadata, snapshotMetadata(), "отказы трёх Update не изменили persisted rows")
	// Module RPC получает новый root context, НЕ contract.Context(startupCtx).
	// Единственный retained profile должен прийти из production CatalogWriteRepo copy.
	rpcBase, cancelRPC := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancelRPC()
	var moduleAdmin string
	require.NoError(t, runtime.QueryRow(rpcBase, `SELECT subject_id FROM kaname.cluster_admin_grants
        WHERE subject_type='service_account' AND cluster_id=$1 AND (granted_until IS NULL OR granted_until>clock_timestamp())
        ORDER BY id LIMIT 1`, domain.ClusterSingletonID).Scan(&moduleAdmin))
	rpcCtx := operations.WithPrincipal(rpcBase, operations.Principal{Type: "service_account", ID: moduleAdmin})
	allowed, err := svcs.ownGates.Check(rpcCtx, "service_account:"+moduleAdmin, "system_admin", "cluster:"+domain.ClusterSingletonID)
	require.NoError(t, err)
	require.True(t, allowed, "Дано: реальный stock bootstrap admin, без нового разрешающего tuple")
	plan, err := svcs.moduleHandler.Plan(rpcCtx, &iamv1.PlanModuleRequest{Module: "iam"})
	require.NoError(t, err)
	require.NotEmpty(t, plan.GetExpectedState())
	zero := int32(0)
	applied, err := svcs.moduleHandler.Apply(rpcCtx, &iamv1.ApplyModuleRequest{Module: "iam", ExpectedState: plan.GetExpectedState(),
		MaxResettledRuleRefs: &zero, MaxResettledRoleVerbs: &zero})
	require.NoError(t, err, "Module.Apply с independent RPC ctx должен использовать retained full writer")
	require.NotNil(t, applied)
	fullStartupAwait(t, rpcCtx, ops, applied.GetId())
	var moduleLive bool
	require.NoError(t, runtime.QueryRow(rpcCtx, `SELECT live FROM kaname.catalog_module WHERE module='iam'`).Scan(&moduleLive))
	require.True(t, moduleLive, "durable каталог после терминального Apply")
	ask(recipientID, relverdict.Allow)
	t.Log(fmt.Sprintf("full production factory durable binding %s", id))
}

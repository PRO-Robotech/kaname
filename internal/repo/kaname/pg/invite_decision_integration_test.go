// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package pg_test

import (
	"context"
	"errors"
	"fmt"
	"github.com/PRO-Robotech/kaname/internal/migrations"
	"github.com/jackc/pgx/v5"
	"log/slog"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	bindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	membershipapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/membership"
	userapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type inviteDecisionFixture struct {
	r       protocolRig
	actor   string
	editor  domain.AccessBindingID
	project domain.ProjectID
	role    domain.RoleID
	runner  *kanamepg.InviteDecisions
	uc      *userapp.InviteUserUseCase
	ops     operations.Repo
}

func newInviteDecisionFixture(t *testing.T) inviteDecisionFixture {
	t.Helper()
	r := identityLifecycleSingle(t, writerProtocolRig(t))
	actor := seedMemberUser(t, r.ctx, r.admin, r.a, "invite-editor")
	_, err := r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=$1`, actor)
	require.NoError(t, err)
	editor := groupLifecycleBinding(t, r, r.a, actor, "invite_editor", domain.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"update"}})
	source := rolePolicyCatalog(t, r)
	seedEngine := reconcile.New(kanamepg.NewReconcileAdapter(r.admin, source), slog.Default(), source)
	require.NoError(t, seedEngine.ReconcileBinding(r.ctx, editor))
	native := delegationNativeDoor{r: r}
	yes, err := native.Check(r.ctx, "user:"+actor, "editor", "account:"+r.a)
	require.NoError(t, err)
	require.True(t, yes, "Дано: настоящий editor producer")
	yes, err = native.Check(r.ctx, "user:"+actor, "admin", "account:"+r.a)
	require.NoError(t, err)
	require.False(t, yes, "Дано: нет admin bypass")
	project := domain.ProjectID(kac127SeedProject(t, r.ctx, r.admin, r.a, "invite"))
	// Обычная предлагаемая роль, реальные selectors/verbs, без capability.
	targetHolder := groupLifecycleBinding(t, r, r.a, bindingPublicOwner(t, r), "invite_target", domain.Rule{Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}})
	role := bindingRow(t, r, targetHolder).RoleID
	runner, err := kanamepg.NewInviteDecisionRunner(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	resource, err := kanamepg.NewResourceObjectParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	engine, err := resource.NewObjectReconciler(slog.Default())
	require.NoError(t, err)
	require.NoError(t, engine.WithStagedBindingReconciler(withdrawalParticipant(t, r, nil)))
	ops := operations.NewRepo(r.runtime, "kaname")
	uc := userapp.NewInviteUserUseCase(r.repo, ops, native).WithInviteDecisions(runner).WithInviteTTL(time.Hour).WithInviteMailRateLimit(outboxtypes.InviteMailRateLimit{MaxPerWindow: 5, Window: time.Hour}, nil).WithObjectReconciler(engine)
	return inviteDecisionFixture{r, actor, editor, project, role, runner, uc, ops}
}
func (f inviteDecisionFixture) execute(t *testing.T, email domain.Email, membership, optional bool) *operations.Operation {
	t.Helper()
	ctx := declarerCtx(f.r.ctx, f.actor)
	in := userapp.InviteUserInput{AccountID: domain.AccountID(f.r.a), Email: email, DisplayName: "Invited"}
	if optional {
		in.ProjectID = f.project
		in.RoleID = f.role
	}
	var op *operations.Operation
	var err error
	if membership {
		op, err = f.uc.CreateMembership(ctx, membershipapp.CreateInput{AccountID: in.AccountID, Email: in.Email, DisplayName: in.DisplayName, ProjectID: in.ProjectID, RoleID: in.RoleID})
	} else {
		op, err = f.uc.Execute(ctx, in)
	}
	require.NoError(t, err)
	require.NotNil(t, op)
	return op
}
func inviteArtifacts(t *testing.T, r protocolRig, email domain.Email) string {
	t.Helper()
	observer, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 5*time.Second)
	defer cancel()
	var snapshot string
	require.NoError(t, r.admin.QueryRow(observer, `SELECT jsonb_build_object('users',(SELECT jsonb_agg(to_jsonb(u)) FROM kaname.users u WHERE lower(email)=lower($1)), 'memberships',(SELECT jsonb_agg(to_jsonb(m)) FROM kaname.memberships m JOIN kaname.users u ON u.id=m.user_id WHERE lower(u.email)=lower($1)), 'bindings',(SELECT count(*) FROM kaname.access_bindings b JOIN kaname.users u ON u.id=b.subject_id WHERE lower(u.email)=lower($1)), 'mail',(SELECT count(*) FROM kaname.invite_mail_outbox WHERE payload->>'to'=$1), 'window',(SELECT to_jsonb(w) FROM kaname.invite_mail_windows w WHERE kind='invite' AND recipient=lower($1)))::text`, string(email)).Scan(&snapshot))
	return snapshot
}

func TestInviteDecisionPublicDoorsPreparedAndStrict(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, membership := range []bool{false, true} {
			t.Run(fmt.Sprintf("strict_%v_membership_%v", strict, membership), func(t *testing.T) {
				f := newInviteDecisionFixture(t)
				email := domain.Email("new-" + ids.NewID("tst") + "@example.invalid")
				var foreign string
				if membership {
					foreign = seedMemberUser(t, f.r.ctx, f.r.admin, f.r.b, "invite-foreign")
					require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT email FROM kaname.users WHERE id=$1`, foreign).Scan(&email))
				}
				if strict {
					require.NoError(t, lifecycleOwner(f.r).ActivateAuthorityBundle(f.r.ctx, f.r.bundle))
				}
				op := f.execute(t, email, membership, false)
				require.Nil(t, awaitDelegatedOperation(t, f.r.ctx, f.ops, op.ID).Error)
				var uid, home, state string
				var queued int
				require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT u.id,u.account_id,m.state,(SELECT count(*) FROM kaname.invite_mail_outbox WHERE payload->>'user_id'=u.id) FROM kaname.users u JOIN kaname.memberships m ON m.user_id=u.id AND m.account_id=$2 WHERE lower(u.email)=lower($1)`, string(email), f.r.a).Scan(&uid, &home, &state, &queued))
				if membership {
					require.Equal(t, foreign, uid)
					require.Equal(t, f.r.b, home)
					require.Equal(t, "ACTIVE", state)
					require.Zero(t, queued)
				} else {
					require.Equal(t, f.r.a, home)
					require.Equal(t, "PENDING", state)
					require.Equal(t, 1, queued)
					var journal, fga, reconcileCount int
					require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT (SELECT count(*) FROM kaname.resource_journal WHERE resource_id=$1),(SELECT count(*) FROM kaname.fga_outbox WHERE payload->>'object'='iam_user:'||$1),(SELECT count(*) FROM kaname.resource_reconcile_outbox WHERE object_type='iam.user' AND object_id=$1)`, uid).Scan(&journal, &fga, &reconcileCount))
					require.Positive(t, journal)
					require.Positive(t, fga)
					require.Positive(t, reconcileCount)
				}
				authorityWaitReleased(t, f.r.runtime)
			})
		}
	}
}

// Источник capability и нижняя граница создаются настоящими repo writers и
// projection producer. Никакой raw tuple/native allow в Given нет.
func inviteCoverageHolder(t *testing.T, f inviteDecisionFixture) domain.RoleID {
	return inviteCoverageHolderFor(t, f, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(f.actor)})
}
func inviteCoverageHolderFor(t *testing.T, f inviteDecisionFixture, actor domain.Subject) domain.RoleID {
	t.Helper()
	r := f.r
	source := rolePolicyCatalog(t, r)
	facts := source.Facts()
	require.NotNil(t, facts)
	w, err := lifecycleOwner(r).Writer(r.ctx)
	require.NoError(t, err)
	defer policyFixtureRollback(w)
	rules := domain.Rules{{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}}, {Module: "iam", Resources: []string{"project"}, Verbs: []string{"get"}}}
	ordinary, caps, err := domain.SplitGrantCapabilityRules(rules)
	require.NoError(t, err)
	perms, err := domain.CompileRules(rules)
	require.NoError(t, err)
	role, err := w.RolesW().Insert(r.ctx, domain.Role{ID: domain.RoleID(ids.NewID("rol")), AccountID: domain.AccountID(r.a), Name: "invite_coverage", Rules: rules, Permissions: perms})
	require.NoError(t, err)
	require.NoError(t, w.RolesW().ReplaceRuleSelectors(r.ctx, role.ID, facts.GrantSelectors(ordinary.MaterializingSelectors(), domain.TenantPolicy())))
	require.NoError(t, w.RolesW().ReplaceRoleVerbs(r.ctx, role.ID, facts.RoleVerbsFromSelectors(ordinary.MaterializingSelectors(), domain.TenantPolicy())))
	require.NoError(t, w.RolesW().ReplaceGrantCapabilities(r.ctx, role.ID, caps))
	_, err = bindingset.Insert(r.ctx, w.AccessBindingsW(), domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID("acb")), SubjectType: actor.Type, SubjectID: actor.ID, RoleID: role.ID, ResourceType: "project", ResourceID: string(f.project), Scope: domain.ScopeProject, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true}})
	require.NoError(t, err)
	require.NoError(t, w.Commit(r.ctx))
	return role.ID
}
func TestInviteDecisionOptionalOldAuthorityAndCarrierVersion(t *testing.T) {
	for _, mode := range []string{"prepared", "strict_denied", "strict_covered"} {
		t.Run(mode, func(t *testing.T) {
			f := newInviteDecisionFixture(t)
			var capRole domain.RoleID
			if mode == "strict_covered" {
				capRole = inviteCoverageHolder(t, f)
			}
			if mode != "prepared" {
				require.NoError(t, lifecycleOwner(f.r).ActivateAuthorityBundle(f.r.ctx, f.r.bundle))
			}
			if capRole != "" {
				writers, err := kanamepg.NewGrantPolicyWriters(f.r.ctx, f.r.repo, f.r.bundle)
				require.NoError(t, err)
				owner := bindingPublicOwner(t, f.r)
				promoter, err := writers.RoleAuthorityWriter(declarerCtx(f.r.ctx, owner), domain.Role{ID: capRole, AccountID: domain.AccountID(f.r.a)}, false, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(owner)})
				require.NoError(t, err)
				defer policyFixtureRollback(promoter)
				require.NoError(t, promoter.(kaname.RoleCapabilityPromoter).PromoteRoleCapabilities(f.r.ctx, capRole))
				require.NoError(t, promoter.Commit(f.r.ctx))
			}
			email := domain.Email("optional-" + ids.NewID("tst") + "@example.invalid")
			before := inviteArtifacts(t, f.r, email)
			op := f.execute(t, email, false, true)
			done := awaitDelegatedOperation(t, f.r.ctx, f.ops, op.ID)
			if mode == "strict_denied" {
				require.NotNil(t, done.Error)
				require.EqualValues(t, 7, done.Error.Code)
				require.Equal(t, before, inviteArtifacts(t, f.r, email))
				return
			}
			require.Nil(t, done.Error)
			var version, subjects, ledger int
			var uid string
			require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT b.grant_capability_version,u.id,(SELECT count(*) FROM kaname.access_binding_subjects s WHERE s.binding_id=b.id),(SELECT count(*) FROM kaname.access_binding_emitted_tuples e WHERE e.binding_id=b.id) FROM kaname.access_bindings b JOIN kaname.users u ON u.id=b.subject_id WHERE lower(u.email)=lower($1)`, string(email)).Scan(&version, &uid, &subjects, &ledger))
			require.Equal(t, map[bool]int{false: 0, true: 1}[mode == "strict_covered"], version)
			require.Equal(t, 1, subjects)
			require.Positive(t, ledger)
			// Ordinary v_get получается из selectors, а не материализованного leaf.
			var nativeRows int
			require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT count(*) FROM kaname.relation_fact WHERE subject=$1 AND object_type='project' AND object_id=$2 AND relation='v_get'`, "user:"+uid, string(f.project)).Scan(&nativeRows))
			require.Zero(t, nativeRows)
			native := delegationNativeDoor{r: f.r}
			allowed, err := native.Check(f.r.ctx, "user:"+uid, "v_get", "project:"+string(f.project))
			require.NoError(t, err)
			require.False(t, allowed, "PENDING получатель не admitted")
			inviteActivateRecipient(t, f, domain.UserID(uid), email)
			allowed, err = native.Check(f.r.ctx, "user:"+uid, "v_get", "project:"+string(f.project))
			require.NoError(t, err)
			require.True(t, allowed, "ACTIVE verified recipient получает реальный ordinary native эффект")
			authorityWaitReleased(t, f.r.runtime)
		})
	}
}

func inviteRunnerIntent(f inviteDecisionFixture, email domain.Email) userapp.InviteDecisionIntent {
	return userapp.InviteDecisionIntent{Actor: domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(f.actor)}, CandidateUserID: domain.UserID(ids.NewID(domain.PrefixUser)), AccountID: domain.AccountID(f.r.a), Email: email, InvitedBy: domain.UserID(f.actor), GrantedBy: domain.UserID(f.actor)}
}
func inviteRunnerInsert(ctx context.Context, w userapp.InviteMutationWriter, p userapp.PreparedInvite, in userapp.InviteDecisionIntent) error {
	u, _, err := w.UsersW().InsertPending(ctx, domain.User{ID: in.CandidateUserID, AccountID: in.AccountID, Email: in.Email, InviteStatus: domain.InviteStatusPending, InvitedBy: in.InvitedBy}, p.DecisionAt().Add(time.Hour))
	if err != nil {
		return err
	}
	if u.ID != p.RecipientID() {
		return iamerr.ErrAborted
	}
	return nil
}
func TestInviteDecisionProspectiveIdentityAndOrdinaryMissingSubject(t *testing.T) {
	f := newInviteDecisionFixture(t)
	capRole := inviteCoverageHolder(t, f)
	require.NoError(t, lifecycleOwner(f.r).ActivateAuthorityBundle(f.r.ctx, f.r.bundle))
	invitePromoteCoverage(t, f, capRole)
	in := inviteRunnerIntent(f, "prospective-"+domain.Email(ids.NewID("tst"))+"@example.invalid")
	writers, err := kanamepg.NewGrantPolicyWriters(f.r.ctx, f.r.repo, f.r.bundle)
	require.NoError(t, err)
	create := bindingapp.NewCreateAccessBindingUseCase(f.r.repo, f.ops, rolePolicyCatalog(t, f.r)).WithBindingDecisions(writers)
	proposal := domain.AccessBinding{RoleID: f.role, ResourceType: "project", ResourceID: string(f.project), Scope: domain.ScopeProject, Subjects: []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(f.actor)}}, Target: domain.AccessTarget{AllInScope: true}}
	op, err := create.Execute(declarerCtx(f.r.ctx, f.actor), proposal)
	require.NoError(t, err)
	require.NotNil(t, op)
	require.Nil(t, awaitDelegatedOperation(t, f.r.ctx, f.ops, op.ID).Error, "тот же actor и OLD authority дают существующему typed subject полный эффект")
	proposal.Subjects[0].ID = domain.SubjectID(in.CandidateUserID)
	op, err = create.Execute(declarerCtx(f.r.ctx, f.actor), proposal)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Nil(t, op, "отсутствующий ordinary subject отвергается до операции")
	called := 0
	err = f.runner.RunInviteDecision(declarerCtx(f.r.ctx, f.actor), in, func(ctx context.Context, w userapp.InviteMutationWriter, p userapp.PreparedInvite) error {
		called++
		require.Equal(t, in.CandidateUserID, p.RecipientID())
		return inviteRunnerInsert(ctx, w, p, in)
	})
	require.NoError(t, err)
	require.Equal(t, 1, called)
	// Повторный email выбирает уже канонический ID, не candidate другого attempt.
	second := in
	second.CandidateUserID = domain.UserID(ids.NewID(domain.PrefixUser))
	require.NoError(t, f.runner.RunInviteDecision(declarerCtx(f.r.ctx, f.actor), second, func(_ context.Context, _ userapp.InviteMutationWriter, p userapp.PreparedInvite) error {
		require.Equal(t, in.CandidateUserID, p.RecipientID())
		return nil
	}))
	collision := in
	collision.Email = "collision@example.invalid"
	err = f.runner.RunInviteDecision(declarerCtx(f.r.ctx, f.actor), collision, func(context.Context, userapp.InviteMutationWriter, userapp.PreparedInvite) error {
		t.Error("collision reached body")
		return nil
	})
	require.ErrorIs(t, err, iamerr.ErrAlreadyExists)
	authorityWaitReleased(t, f.r.runtime)
}

// Декоратор запускает переданный UC callback в настоящем runner. Он меняет
// только точку отказа после всего общего body, не подменяя policy или writer.
type inviteObservedRunner struct {
	base userapp.InviteDecisionRunner
	run  func(context.Context, userapp.InviteDecisionIntent, func(context.Context, userapp.InviteMutationWriter, userapp.PreparedInvite) error) error
}

func (r inviteObservedRunner) RunInviteDecision(ctx context.Context, in userapp.InviteDecisionIntent, body func(context.Context, userapp.InviteMutationWriter, userapp.PreparedInvite) error) error {
	return r.run(ctx, in, body)
}

func inviteAllArtifacts(t *testing.T, r protocolRig) map[string]string {
	t.Helper()
	observer, cancel := context.WithTimeout(context.WithoutCancel(r.ctx), 5*time.Second)
	defer cancel()
	result := map[string]string{}
	// Sequence gaps допустимы; проверяются все строки атомарных бизнес-артефактов.
	for _, table := range []string{"users", "memberships", "issued_user_ids", "project_resource_quotas", "own_ceilings", "access_bindings", "access_binding_subjects", "access_binding_target_members", "access_binding_emitted_tuples", "invite_mail_windows", "invite_mail_outbox", "resource_journal", "fga_outbox", "relation_fact", "resource_reconcile_outbox", "subject_change_outbox", "audit_outbox", "authority_policy_epoch", "authority_binding_epoch", "authority_policy_carrier_pending"} {
		var value string
		require.NoError(t, r.admin.QueryRow(observer, `SELECT coalesce(jsonb_agg(item ORDER BY item::text),'[]'::jsonb)::text FROM (SELECT to_jsonb(t) item FROM kaname.`+table+` t) snapshot`).Scan(&value))
		result[table] = value
	}
	return result
}
func TestInviteDecisionWholeAttemptRollbackAndCancellation(t *testing.T) {
	for _, membership := range []bool{false, true} {
		for _, mode := range []string{"body_error", "retry_40001", "commit_40001", "exhaustion", "cancel_body", "duplicate_grant", "closed"} {
			t.Run(fmt.Sprintf("membership_%v_%s", membership, mode), func(t *testing.T) {
				f := newInviteDecisionFixture(t)
				capRole := inviteCoverageHolder(t, f)
				require.NoError(t, lifecycleOwner(f.r).ActivateAuthorityBundle(f.r.ctx, f.r.bundle))
				invitePromoteCoverage(t, f, capRole)
				if mode == "commit_40001" {
					// Owner-only fault injector, не runtime capability и не business allow.
					// Sequence хранит число попыток вне отката; первый DEFERRED callback падает.
					_, e := f.r.admin.Exec(f.r.ctx, `CREATE SEQUENCE kaname.invite_fixture_retry_seq;
 CREATE FUNCTION kaname.invite_fixture_commit_retry() RETURNS trigger LANGUAGE plpgsql SECURITY DEFINER SET search_path=pg_catalog AS $$ BEGIN IF nextval('kaname.invite_fixture_retry_seq')=1 THEN RAISE EXCEPTION 'fixture commit serialization' USING ERRCODE='40001'; END IF; RETURN NULL; END $$;
 REVOKE ALL ON FUNCTION kaname.invite_fixture_commit_retry() FROM PUBLIC;
 CREATE CONSTRAINT TRIGGER invite_fixture_commit_retry AFTER INSERT ON kaname.users DEFERRABLE INITIALLY DEFERRED FOR EACH ROW EXECUTE FUNCTION kaname.invite_fixture_commit_retry()`)
					require.NoError(t, e)
					t.Cleanup(func() {
						c, stop := context.WithTimeout(context.Background(), 5*time.Second)
						defer stop()
						_, _ = f.r.admin.Exec(c, `DROP TRIGGER IF EXISTS invite_fixture_commit_retry ON kaname.users; DROP FUNCTION IF EXISTS kaname.invite_fixture_commit_retry(); DROP SEQUENCE IF EXISTS kaname.invite_fixture_retry_seq`)
					})
				}

				email := domain.Email("whole-" + ids.NewID("tst") + "@example.invalid")
				if mode == "closed" {
					require.NoError(t, lifecycleOwner(f.r).CloseAuthorityBundle(f.r.ctx))
				}
				before := inviteAllArtifacts(t, f.r)
				calls := 0
				var first time.Time
				var binding domain.AccessBindingID
				var recipient domain.UserID
				var retained userapp.InviteMutationWriter
				injected := errors.New("failure after complete Invite body")
				observed := inviteObservedRunner{base: f.runner}
				observed.run = func(ctx context.Context, in userapp.InviteDecisionIntent, body func(context.Context, userapp.InviteMutationWriter, userapp.PreparedInvite) error) error {
					attemptCtx, cancel := context.WithCancel(ctx)
					defer cancel()
					return observed.base.RunInviteDecision(attemptCtx, in, func(ctx context.Context, w userapp.InviteMutationWriter, p userapp.PreparedInvite) error {
						calls++
						if calls == 1 {
							first = p.DecisionAt()
							binding = p.Binding().ID
							recipient = p.RecipientID()
						} else {
							require.True(t, p.DecisionAt().After(first))
							require.Equal(t, binding, p.Binding().ID)
							require.Equal(t, recipient, p.RecipientID())
							require.Equal(t, before, inviteAllArtifacts(t, f.r), "до нового body предыдущая попытка полностью откатилась")
							_, e := retained.Users().Get(ctx, recipient)
							require.Error(t, e, "facade предыдущей TX закрыт")
						}
						retained = w
						if err := body(ctx, w, p); err != nil {
							return err
						}
						// Проверяем, что fault стоит после issued/quota/journal/FGA/mail/AB body.
						user, err := w.Users().Get(ctx, p.RecipientID())
						if err != nil {
							return err
						}
						require.Equal(t, email, user.Email)
						if mode == "duplicate_grant" {
							_, err := w.AccessBindingsW().Insert(ctx, p.Binding())
							return err
						}
						switch mode {
						case "body_error":
							return injected
						case "retry_40001":
							if calls == 1 {
								return &pgconn.PgError{Code: "40001"}
							}
						case "exhaustion":
							return &pgconn.PgError{Code: "40001"}
						case "cancel_body":
							cancel()
							return ctx.Err()
						}
						return nil
					})
				}
				f.uc.WithInviteDecisions(observed)
				op := f.execute(t, email, membership, true)
				done := awaitDelegatedOperation(t, f.r.ctx, f.ops, op.ID)
				switch mode {
				case "retry_40001", "commit_40001":
					require.Nil(t, done.Error)
					require.Equal(t, 2, calls)
					var users, bindings, mail int
					require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT (SELECT count(*) FROM kaname.users WHERE email=$1),(SELECT count(*) FROM kaname.access_bindings WHERE id=$2),(SELECT count(*) FROM kaname.invite_mail_outbox WHERE payload->>'to'=$1)`, string(email), string(binding)).Scan(&users, &bindings, &mail))
					require.Equal(t, 1, users)
					require.Equal(t, 1, bindings)
					require.Equal(t, 1, mail)
				default:
					require.NotNil(t, done.Error)
					if mode == "closed" {
						require.Zero(t, calls)
					} else if mode == "exhaustion" {
						require.Equal(t, 3, calls)
						require.EqualValues(t, codes.Aborted, done.Error.Code)
					} else {
						require.Equal(t, 1, calls)
					}
					if mode == "duplicate_grant" {
						require.EqualValues(t, codes.AlreadyExists, done.Error.Code)
					}
					require.Equal(t, before, inviteAllArtifacts(t, f.r))
				}
				authorityWaitReleased(t, f.r.runtime)
			})
		}
	}
}

// Положительный и истёкший близнецы ждут ОДИН настоящий blocker на preflight.
// Важно: без optional AB тоже обязаны ждать journal/FGA/reconcile/sequence.
func TestInviteDecisionWaitsBeforeFinalClock(t *testing.T) {
	for _, barrier := range []string{"user_row", "mail_window", "journal_table", "fold_table", "reconcile_table", "fga_table", "epoch_table", "membership_table", "optional_role_fk", "optional_project_fk", "sequence"} {
		for _, expire := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_expire_%v", barrier, expire), func(t *testing.T) {
				f := newInviteDecisionFixture(t)
				optional := barrier == "optional_role_fk" || barrier == "optional_project_fk"
				var capRole domain.RoleID
				if optional {
					capRole = inviteCoverageHolder(t, f)
				}
				email := domain.Email("wait-" + ids.NewID("tst") + "@example.invalid")
				if barrier == "mail_window" {
					_, err := f.r.admin.Exec(f.r.ctx, `INSERT INTO kaname.invite_mail_windows(kind,recipient,window_started_at,sent,updated_at) VALUES('invite',$1,clock_timestamp(),1,clock_timestamp())`, string(email))
					require.NoError(t, err)
				}
				interval := "1 hour"
				if expire {
					interval = "3 seconds"
				}
				var expires time.Time
				require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp()+$2::interval WHERE id=$1 RETURNING expires_at`, string(f.editor), interval).Scan(&expires))
				require.NoError(t, lifecycleOwner(f.r).ActivateAuthorityBundle(f.r.ctx, f.r.bundle))
				if optional {
					invitePromoteCoverage(t, f, capRole)
				}
				before := inviteArtifacts(t, f.r, email)
				blocker, err := f.r.admin.Begin(f.r.ctx)
				require.NoError(t, err)
				defer policyFixtureRollback(blocker)
				var pid int
				require.NoError(t, blocker.QueryRow(f.r.ctx, `SELECT pg_backend_pid()`).Scan(&pid))
				switch barrier {
				case "user_row":
					var uid string
					err = blocker.QueryRow(f.r.ctx, `SELECT id FROM kaname.users WHERE id=$1 FOR UPDATE`, f.actor).Scan(&uid)
					require.Equal(t, f.actor, uid)
				case "mail_window":
					var to string
					err = blocker.QueryRow(f.r.ctx, `SELECT recipient FROM kaname.invite_mail_windows WHERE kind='invite' AND recipient=$1 FOR UPDATE`, string(email)).Scan(&to)
					require.Equal(t, string(email), to)
				case "journal_table":
					_, err = blocker.Exec(f.r.ctx, `LOCK TABLE kaname.resource_journal IN SHARE MODE`)
				case "fold_table":
					_, err = blocker.Exec(f.r.ctx, `LOCK TABLE kaname.relation_fact IN SHARE MODE`)
				case "reconcile_table":
					_, err = blocker.Exec(f.r.ctx, `LOCK TABLE kaname.resource_reconcile_outbox IN SHARE MODE`)
				case "fga_table":
					_, err = blocker.Exec(f.r.ctx, `LOCK TABLE kaname.fga_outbox IN SHARE MODE`)
				case "epoch_table":
					_, err = blocker.Exec(f.r.ctx, `LOCK TABLE kaname.authority_policy_epoch IN SHARE MODE`)
				case "membership_table":
					_, err = blocker.Exec(f.r.ctx, `LOCK TABLE kaname.memberships IN SHARE MODE`)
				case "optional_role_fk":
					var id string
					err = blocker.QueryRow(f.r.ctx, `SELECT id FROM kaname.roles WHERE id=$1 FOR UPDATE`, string(f.role)).Scan(&id)
				case "optional_project_fk":
					var id string
					err = blocker.QueryRow(f.r.ctx, `SELECT id FROM kaname.projects WHERE id=$1 FOR UPDATE`, string(f.project)).Scan(&id)
				case "sequence":
					_, err = blocker.Exec(f.r.ctx, `ALTER SEQUENCE kaname.resource_reconcile_outbox_id_seq CACHE 1`)
				}
				require.NoError(t, err)
				op := f.execute(t, email, false, optional)
				require.Eventually(t, func() bool {
					var waiting bool
					e := f.r.admin.QueryRow(f.r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND position('authority_invite_preflight' in query)>0)`, pid).Scan(&waiting)
					return e == nil && waiting
				}, 5*time.Second, 10*time.Millisecond, "worker должен ждать именно preflight, не упасть до него")
				if expire {
					require.Eventually(t, func() bool {
						var passed bool
						e := f.r.admin.QueryRow(f.r.ctx, `SELECT clock_timestamp()>$1::timestamptz`, expires).Scan(&passed)
						return e == nil && passed
					}, 5*time.Second, 10*time.Millisecond)
				}
				require.NoError(t, blocker.Rollback(f.r.ctx))
				done := awaitDelegatedOperation(t, f.r.ctx, f.ops, op.ID)
				if expire {
					require.NotNil(t, done.Error)
					require.EqualValues(t, 7, done.Error.Code)
					require.Equal(t, before, inviteArtifacts(t, f.r, email))
				} else {
					require.Nil(t, done.Error)
					require.NotEqual(t, before, inviteArtifacts(t, f.r, email))
				}
				authorityWaitReleased(t, f.r.runtime)
			})
		}
	}
}
func TestInviteDecisionPreflightRequiresActualEntry(t *testing.T) {
	f := newInviteDecisionFixture(t)
	for _, strict := range []bool{false, true} {
		if strict {
			require.NoError(t, lifecycleOwner(f.r).ActivateAuthorityBundle(f.r.ctx, f.r.bundle))
		}
		for _, kind := range []string{"none", "group", "identity", "wrong_purpose", "account_mode"} {
			tx, err := f.r.runtime.Begin(f.r.ctx)
			require.NoError(t, err)
			// Cleanup регистрируется до assertion: отказ SQL не оставляет единственный slot.
			defer policyFixtureRollback(tx)
			if kind != "none" {
				in := kaname.AuthorityWriteIntent{Kind: kaname.AuthorityOperation(kind), Bundle: f.r.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}}
				purpose := "participant"
				if kind == "wrong_purpose" {
					in.Kind = kaname.AuthorityIdentity
					purpose = "transition"
					if strict {
						purpose = "decision"
					}
				}
				if kind == "account_mode" {
					in = f.r.intent(f.r.a)
					in.Kind = kaname.AuthorityIdentity
				}
				_, err = protocolEnter(f.r.ctx, tx, in, purpose)
				if kind == "account_mode" {
					var pe *pgconn.PgError
					require.ErrorAs(t, err, &pe)
					require.Equal(t, "22023", pe.Code)
					require.NoError(t, tx.Rollback(f.r.ctx))
					continue
				}
				require.NoError(t, err)
			}
			_, err = tx.Exec(f.r.ctx, `SELECT kaname.authority_invite_preflight(false)`)
			if kind == "identity" {
				require.NoError(t, err)
			} else {
				var pgerr *pgconn.PgError
				require.ErrorAs(t, err, &pgerr)
				require.Equal(t, "42501", pgerr.Code)
			}
			require.NoError(t, tx.Rollback(f.r.ctx))
		}
	}
	var private bool
	require.NoError(t, f.r.runtime.QueryRow(f.r.ctx, `SELECT has_table_privilege(current_user,'kaname.authority_writer_protocol','SELECT') OR has_table_privilege(current_user,'kaname.authority_bundle_handoff','UPDATE')`).Scan(&private))
	require.False(t, private)
}

func TestInviteDecisionCancelWhileGlobalWaitsAccountWriter(t *testing.T) {
	f := newInviteDecisionFixture(t)
	require.NoError(t, lifecycleOwner(f.r).ActivateAuthorityBundle(f.r.ctx, f.r.bundle))
	// Blocker использует отдельную настоящую LOGIN connection; MaxConns=1 у UC.
	other, err := pgxpool.NewWithConfig(f.r.ctx, f.r.runtime.Config())
	require.NoError(t, err)
	t.Cleanup(other.Close)
	blocker, err := other.Begin(f.r.ctx)
	require.NoError(t, err)
	defer policyFixtureRollback(blocker)
	// Обычный account participant без business DML.
	_, err = protocolEnter(f.r.ctx, blocker, f.r.intent(f.r.a), "participant")
	require.NoError(t, err)
	var pid int
	require.NoError(t, blocker.QueryRow(f.r.ctx, `SELECT pg_backend_pid()`).Scan(&pid))
	in := inviteRunnerIntent(f, "cancel-global@example.invalid")
	before := inviteArtifacts(t, f.r, in.Email)
	ctx, cancel := context.WithCancel(declarerCtx(f.r.ctx, f.actor))
	defer cancel()
	done := make(chan error, 1)
	go func() {
		done <- f.runner.RunInviteDecision(ctx, in, func(context.Context, userapp.InviteMutationWriter, userapp.PreparedInvite) error {
			return errors.New("body reached while blocked")
		})
	}()
	require.Eventually(t, func() bool {
		var blocked bool
		e := f.r.admin.QueryRow(f.r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND position('authority_protocol_enter' in query)>0)`, pid).Scan(&blocked)
		return e == nil && blocked
	}, 5*time.Second, 10*time.Millisecond)
	cancel()
	select {
	case e := <-done:
		require.ErrorIs(t, e, context.Canceled)
	case <-time.After(5 * time.Second):
		t.Fatal("cancel не вернул global waiter")
	}
	require.NoError(t, blocker.Rollback(f.r.ctx))
	require.Equal(t, before, inviteArtifacts(t, f.r, in.Email))
	authorityWaitReleased(t, f.r.runtime)
}

func TestInviteDecisionGroupAndServiceAccountEditorSources(t *testing.T) {
	for _, mode := range []string{"group_live", "group_removed", "service_account_live", "service_account_disabled"} {
		t.Run(mode, func(t *testing.T) {
			f := newInviteDecisionFixture(t)
			role := bindingRow(t, f.r, f.editor).RoleID
			w, err := lifecycleOwner(f.r).Writer(f.r.ctx)
			require.NoError(t, err)
			defer policyFixtureRollback(w)
			var actor domain.Subject
			var groupID domain.GroupID
			if mode == "group_live" || mode == "group_removed" {
				groupID = domain.GroupID(ids.NewID("grp"))
				_, err = w.GroupsW().Insert(f.r.ctx, domain.Group{ID: groupID, AccountID: domain.AccountID(f.r.a), Name: "invite-editor-group"})
				require.NoError(t, err)
				require.NoError(t, w.GroupsW().AddMember(f.r.ctx, domain.GroupMember{GroupID: groupID, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(f.actor)}))
				actor = domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(f.actor)}
			} else {
				// Seed на owner pool: runtime writer ещё не писал и не удерживает row locks.
				actor = domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(seedSAID(t, f.r.ctx, f.r.admin, f.r.a, "invite-editor-sa"))}
			}
			holder := actor
			if groupID != "" {
				holder = domain.Subject{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(groupID)}
			}
			b, err := bindingset.Insert(f.r.ctx, w.AccessBindingsW(), domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID("acb")), Subjects: []domain.Subject{holder}, SubjectType: holder.Type, SubjectID: holder.ID, RoleID: role, ResourceType: "account", ResourceID: f.r.a, Scope: domain.ScopeAccount, Target: domain.AccessTarget{AllInScope: true}})
			require.NoError(t, err)
			require.NoError(t, w.Commit(f.r.ctx))
			// Снимается только прямой editor исходной user fixture. Его старый native
			// факт может остаться, но живым producer после отзыва он не считается.
			_, err = f.r.admin.Exec(f.r.ctx, `UPDATE kaname.access_bindings SET status='REVOKED',revoked_at=clock_timestamp() WHERE id=$1`, string(f.editor))
			require.NoError(t, err)
			source := rolePolicyCatalog(t, f.r)
			engine := reconcile.New(kanamepg.NewReconcileAdapter(f.r.admin, source), slog.Default(), source)
			require.NoError(t, engine.ReconcileBinding(f.r.ctx, b.ID))
			if mode == "group_removed" {
				_, err = f.r.admin.Exec(f.r.ctx, `DELETE FROM kaname.group_members WHERE group_id=$1 AND member_type='user' AND member_id=$2`, string(groupID), f.actor)
				require.NoError(t, err)
			}
			if mode == "service_account_disabled" {
				_, err = f.r.admin.Exec(f.r.ctx, `UPDATE kaname.service_accounts SET enabled=false WHERE id=$1`, string(actor.ID))
				require.NoError(t, err)
			}
			require.NoError(t, lifecycleOwner(f.r).ActivateAuthorityBundle(f.r.ctx, f.r.bundle))
			ctx := operations.WithPrincipal(f.r.ctx, operations.Principal{Type: string(actor.Type), ID: string(actor.ID)})
			in := inviteRunnerIntent(f, domain.Email(mode+"@example.invalid"))
			in.Actor = actor
			in.GrantedBy = domain.UserID(actor.ID)
			if actor.Type == domain.SubjectTypeServiceAccount {
				in.InvitedBy = ""
			}
			before := inviteArtifacts(t, f.r, in.Email)
			called := 0
			err = f.runner.RunInviteDecision(ctx, in, func(ctx context.Context, w userapp.InviteMutationWriter, p userapp.PreparedInvite) error {
				called++
				return inviteRunnerInsert(ctx, w, p, in)
			})
			if mode == "group_removed" || mode == "service_account_disabled" {
				require.Error(t, err)
				require.Zero(t, called)
				require.Equal(t, before, inviteArtifacts(t, f.r, in.Email))
			} else {
				require.NoError(t, err)
				require.Equal(t, 1, called)
				if actor.Type == domain.SubjectTypeServiceAccount {
					var human bool
					require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT invited_by IS NOT NULL FROM kaname.users WHERE id=$1`, string(in.CandidateUserID)).Scan(&human))
					require.False(t, human)
				}
			}
			authorityWaitReleased(t, f.r.runtime)
		})
	}
}

func invitePromoteCoverage(t *testing.T, f inviteDecisionFixture, id domain.RoleID) {
	t.Helper()
	writers, err := kanamepg.NewGrantPolicyWriters(f.r.ctx, f.r.repo, f.r.bundle)
	require.NoError(t, err)
	owner := bindingPublicOwner(t, f.r)
	w, err := writers.RoleAuthorityWriter(declarerCtx(f.r.ctx, owner), domain.Role{ID: id, AccountID: domain.AccountID(f.r.a)}, false, domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(owner)})
	require.NoError(t, err)
	defer policyFixtureRollback(w)
	require.NoError(t, w.(kaname.RoleCapabilityPromoter).PromoteRoleCapabilities(f.r.ctx, id))
	require.NoError(t, w.Commit(f.r.ctx))
}
func inviteActivateRecipient(t *testing.T, f inviteDecisionFixture, id domain.UserID, email domain.Email) {
	t.Helper()
	participant, err := kanamepg.NewHumanAdmissionParticipant(f.r.ctx, f.r.repo, f.r.bundle)
	require.NoError(t, err)
	store, err := kanamepg.NewRecoveryCompletionStore(f.r.runtime, userapp.ActivateInviteForLane)
	require.NoError(t, err)
	store = store.WithHumanAdmissionParticipant(participant)
	w, err := store.RecoveryCompletionWriter(f.r.ctx, id)
	require.NoError(t, err)
	defer policyFixtureRollback(w)
	verifier, err := domain.NewLoginVerifier("invite-native-fixture-password-verifier")
	require.NoError(t, err)
	created, err := w.PutLoginVerifier(f.r.ctx, domain.LoginMethod{UserID: id, Kind: domain.LoginMethodPassword, Verifier: verifier, State: domain.LoginMethodStateActive})
	require.NoError(t, err)
	require.True(t, created)
	marked, err := w.MarkEmailVerified(f.r.ctx, id, email, time.Now())
	require.NoError(t, err)
	require.True(t, marked)
	_, err = w.ActivateInviteOnVerification(f.r.ctx, domain.User{ID: id, AccountID: domain.AccountID(f.r.a), Email: email, InviteStatus: domain.InviteStatusPending})
	require.NoError(t, err)
	require.NoError(t, w.Commit(f.r.ctx))
}

func TestInviteDecisionAdmissionIdentityRace(t *testing.T) {
	for _, strict := range []bool{false, true} {
		for _, race := range []string{"deleted", "live_collision", "email_winner"} {
			t.Run(fmt.Sprintf("strict_%v_%s", strict, race), func(t *testing.T) {
				f := newInviteDecisionFixture(t)
				email := domain.Email("identity-race-" + ids.NewID("tst") + "@example.invalid")
				var selected string
				if race == "deleted" {
					selected = seedMemberUser(t, f.r.ctx, f.r.admin, f.r.b, "invite-race-delete")
					require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT email FROM kaname.users WHERE id=$1`, selected).Scan(&email))
				}
				if strict {
					require.NoError(t, lifecycleOwner(f.r).ActivateAuthorityBundle(f.r.ctx, f.r.bundle))
				}
				calls := 0
				var candidate domain.UserID
				var winner domain.UserID
				var afterRace map[string]string
				f.uc.WithInviteDecisions(inviteObservedRunner{run: func(ctx context.Context, in userapp.InviteDecisionIntent, body func(context.Context, userapp.InviteMutationWriter, userapp.PreparedInvite) error) error {
					candidate = in.CandidateUserID
					if race == "deleted" {
						require.Equal(t, selected, string(candidate), "admission выбрал существующий ID до удаления")
						participant, err := kanamepg.NewHumanAdmissionParticipant(f.r.ctx, f.r.repo, f.r.bundle)
						if err != nil {
							return err
						}
						w, err := participant.IdentityLifecycleWriter(ctx, kaname.IdentityDelete, candidate)
						if err != nil {
							return err
						}
						defer policyFixtureRollback(w)
						if err = w.UsersW().Delete(ctx, candidate); err != nil {
							return err
						}
						if err = w.Commit(ctx); err != nil {
							return err
						}
					} else {
						w, err := f.r.repo.ParticipantAuthorityWriter(ctx, kaname.AuthorityWriteIntent{Kind: kaname.AuthorityIdentity, Bundle: f.r.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}})
						if err != nil {
							return err
						}
						defer policyFixtureRollback(w)
						winner = candidate
						otherEmail := email
						if race == "live_collision" {
							otherEmail = "other-" + email
						} else {
							winner = domain.UserID(ids.NewID(domain.PrefixUser))
						}
						_, _, err = w.UsersW().InsertPending(ctx, domain.User{ID: winner, AccountID: domain.AccountID(f.r.b), Email: otherEmail, InviteStatus: domain.InviteStatusPending}, time.Now().Add(time.Hour))
						if err != nil {
							return err
						}
						if err = w.Commit(ctx); err != nil {
							return err
						}
					}
					afterRace = inviteAllArtifacts(t, f.r)
					return f.runner.RunInviteDecision(ctx, in, func(ctx context.Context, w userapp.InviteMutationWriter, p userapp.PreparedInvite) error {
						calls++
						if race == "email_winner" {
							require.Equal(t, winner, p.RecipientID())
							require.NotEqual(t, candidate, winner)
						}
						return body(ctx, w, p)
					})
				}})
				done := awaitDelegatedOperation(t, f.r.ctx, f.ops, f.execute(t, email, true, false).ID)
				if race == "email_winner" {
					require.Nil(t, done.Error)
					require.Equal(t, 1, calls)
				} else {
					require.NotNil(t, done.Error)
					require.Zero(t, calls)
					if race == "deleted" {
						require.EqualValues(t, codes.FailedPrecondition, done.Error.Code)
						require.Contains(t, done.Error.Message, fmt.Sprintf("User %s not found", candidate))
					} else {
						require.EqualValues(t, codes.AlreadyExists, done.Error.Code)
					}
					require.Equal(t, afterRace, inviteAllArtifacts(t, f.r))
				}
				authorityWaitReleased(t, f.r.runtime)
			})
		}
	}
}

func TestInviteDecisionPostWaitSourceWithdrawal(t *testing.T) {
	for _, sourceKind := range []string{"direct_revoke", "group_remove"} {
		for _, withdraw := range []bool{false, true} {
			t.Run(fmt.Sprintf("%s_withdraw_%v", sourceKind, withdraw), func(t *testing.T) {
				f := newInviteDecisionFixture(t)
				var group domain.GroupID
				if sourceKind == "group_remove" {
					role := bindingRow(t, f.r, f.editor).RoleID
					w, err := lifecycleOwner(f.r).Writer(f.r.ctx)
					require.NoError(t, err)
					defer policyFixtureRollback(w)
					group = domain.GroupID(ids.NewID("grp"))
					_, err = w.GroupsW().Insert(f.r.ctx, domain.Group{ID: group, AccountID: domain.AccountID(f.r.a), Name: "wait-group"})
					require.NoError(t, err)
					require.NoError(t, w.GroupsW().AddMember(f.r.ctx, domain.GroupMember{GroupID: group, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(f.actor)}))
					b, err := bindingset.Insert(f.r.ctx, w.AccessBindingsW(), domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID("acb")), Subjects: []domain.Subject{{Type: domain.SubjectTypeGroup, ID: domain.SubjectID(group)}}, SubjectType: domain.SubjectTypeGroup, SubjectID: domain.SubjectID(group), RoleID: role, ResourceType: "account", ResourceID: f.r.a, Scope: domain.ScopeAccount, Target: domain.AccessTarget{AllInScope: true}})
					require.NoError(t, err)
					require.NoError(t, w.Commit(f.r.ctx))
					_, err = f.r.admin.Exec(f.r.ctx, `UPDATE kaname.access_bindings SET status='REVOKED',revoked_at=clock_timestamp() WHERE id=$1`, string(f.editor))
					require.NoError(t, err)
					catalog := rolePolicyCatalog(t, f.r)
					engine := reconcile.New(kanamepg.NewReconcileAdapter(f.r.admin, catalog), slog.Default(), catalog)
					require.NoError(t, engine.ReconcileBinding(f.r.ctx, b.ID))
				}
				require.NoError(t, lifecycleOwner(f.r).ActivateAuthorityBundle(f.r.ctx, f.r.bundle))
				other, err := pgxpool.NewWithConfig(f.r.ctx, f.r.runtime.Config())
				require.NoError(t, err)
				t.Cleanup(other.Close)
				otherRig := f.r
				otherRig.runtime = other
				otherRig.repo = kanamepg.New(other, nil)
				var pid int
				require.NoError(t, other.QueryRow(f.r.ctx, `SELECT pg_backend_pid()`).Scan(&pid))
				entered := make(chan struct{})
				release := make(chan struct{})
				mutation := make(chan error, 1)
				released := false
				defer func() {
					if !released {
						close(release)
					}
				}()
				if sourceKind == "direct_revoke" {
					participant := withdrawalParticipant(t, otherRig, nil)
					owner := bindingPublicOwner(t, f.r)
					withdrawCtx := declarerCtx(f.r.ctx, owner)
					keepSource := errors.New("контроль сохраняет живой источник")
					go func() {
						reachedBarrier := false
						_, e := participant.WithdrawBinding(withdrawCtx, f.editor, kaname.BindingWithdrawalRevoke, owner, func(ctx context.Context, _ kaname.Writer, _ clients.RelationStore, _ domain.AccessBinding) error {
							reachedBarrier = true
							close(entered)
							select {
							case <-release:
							case <-ctx.Done():
								return ctx.Err()
							}
							if !withdraw {
								return keepSource
							}
							return nil
						}, func(context.Context, kaname.Writer, domain.AccessBinding) error { return nil })
						// Только наш отказ ПОСЛЕ настоящего fence означает успешный
						// контроль. Ошибку entry или rollback скрывать нельзя.
						if !withdraw && reachedBarrier && errors.Is(e, keepSource) {
							e = nil
						}
						mutation <- e
					}()
				} else {
					participant, e := kanamepg.NewGroupMembershipParticipant(f.r.ctx, otherRig.repo, f.r.bundle)
					require.NoError(t, e)
					go func() {
						member := domain.GroupMember{GroupID: group, MemberType: domain.SubjectTypeUser, MemberID: domain.SubjectID(f.actor)}
						w, e := participant.GroupMembershipWriter(f.r.ctx, member)
						if e != nil {
							mutation <- e
							return
						}
						defer policyFixtureRollback(w)
						close(entered)
						select {
						case <-release:
						case <-f.r.ctx.Done():
							mutation <- f.r.ctx.Err()
							return
						}
						if withdraw {
							e = w.GroupsW().RemoveMember(f.r.ctx, group, member.MemberType, member.MemberID)
							if e == nil {
								e = w.Commit(f.r.ctx)
							}
						} else {
							e = w.Rollback(f.r.ctx)
						}
						mutation <- e
					}()
				}
				select {
				case <-entered:
				case e := <-mutation:
					t.Fatalf("source writer failed before fence: %v", e)
				case <-time.After(5 * time.Second):
					t.Fatal("source writer not ready")
				}
				email := domain.Email("post-wait-" + ids.NewID("tst") + "@example.invalid")
				before := inviteArtifacts(t, f.r, email)
				op := f.execute(t, email, false, false)
				require.Eventually(t, func() bool {
					var waiting bool
					e := f.r.admin.QueryRow(f.r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND wait_event_type='Lock' AND $1=ANY(pg_blocking_pids(pid)) AND position('authority_protocol_enter' in query)>0)`, pid).Scan(&waiting)
					return e == nil && waiting
				}, 5*time.Second, 10*time.Millisecond)
				close(release)
				released = true
				select {
				case e := <-mutation:
					require.NoError(t, e)
				case <-time.After(5 * time.Second):
					t.Fatal("source writer did not finish")
				}
				// Проверяем фактическую смену источника, а не один сигнал callback.
				if sourceKind == "direct_revoke" {
					binding := bindingRow(t, f.r, f.editor)
					if withdraw {
						require.Equal(t, domain.AccessBindingStatusRevoked, binding.Status)
						require.NotNil(t, binding.RevokedAt)
					} else {
						require.Equal(t, domain.AccessBindingStatusActive, binding.Status)
						require.Nil(t, binding.RevokedAt)
					}
				} else {
					var member bool
					require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT EXISTS(SELECT 1 FROM kaname.group_members WHERE group_id=$1 AND member_type='user' AND member_id=$2)`, string(group), f.actor).Scan(&member))
					require.Equal(t, !withdraw, member)
				}
				done := awaitDelegatedOperation(t, f.r.ctx, f.ops, op.ID)
				if withdraw {
					require.NotNil(t, done.Error)
					require.Equal(t, before, inviteArtifacts(t, f.r, email))
				} else {
					require.Nil(t, done.Error)
				}
				authorityWaitReleased(t, f.r.runtime)
				authorityWaitReleased(t, other)
			})
		}
	}
}

func TestInviteDecisionRawEditorCannotAuthorizeMutation(t *testing.T) {
	f := newInviteDecisionFixture(t)
	_, err := f.r.admin.Exec(f.r.ctx, `DELETE FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1`, string(f.editor))
	require.NoError(t, err)
	_, err = f.r.admin.Exec(f.r.ctx, `UPDATE kaname.access_bindings SET status='REVOKED',revoked_at=clock_timestamp() WHERE id=$1`, string(f.editor))
	require.NoError(t, err)
	_, err = f.r.admin.Exec(f.r.ctx, `INSERT INTO kaname.relation_fact(object_type,object_id,relation,subject) VALUES('account',$1,'editor',$2) ON CONFLICT DO NOTHING`, f.r.a, "user:"+f.actor)
	require.NoError(t, err)
	yes, err := (delegationNativeDoor{r: f.r}).Check(f.r.ctx, "user:"+f.actor, "editor", "account:"+f.r.a)
	require.NoError(t, err)
	require.True(t, yes, "дешёвый native admission видит сырой leaf")
	require.NoError(t, lifecycleOwner(f.r).ActivateAuthorityBundle(f.r.ctx, f.r.bundle))
	email := domain.Email("raw-editor@example.invalid")
	before := inviteAllArtifacts(t, f.r)
	done := awaitDelegatedOperation(t, f.r.ctx, f.ops, f.execute(t, email, false, false).ID)
	require.NotNil(t, done.Error)
	require.Equal(t, before, inviteAllArtifacts(t, f.r))
	authorityWaitReleased(t, f.r.runtime)
}
func TestInviteDecisionSelfAndNewMembershipDoNotSupplyOldAuthority(t *testing.T) {
	for _, which := range []string{"self_denied", "foreign_membership_denied", "pending_deadline_denied", "self_old_covered"} {
		t.Run(which, func(t *testing.T) {
			f := newInviteDecisionFixture(t)
			recipient := f.actor
			if which == "foreign_membership_denied" {
				recipient = seedMemberUser(t, f.r.ctx, f.r.admin, f.r.b, "old-recipient")
			}
			if which == "pending_deadline_denied" {
				w, err := lifecycleOwner(f.r).Writer(f.r.ctx)
				require.NoError(t, err)
				defer policyFixtureRollback(w)
				pending, _, err := w.UsersW().InsertPending(f.r.ctx, domain.User{ID: domain.UserID(ids.NewID(domain.PrefixUser)), AccountID: domain.AccountID(f.r.b), Email: "pending-deadline@example.invalid", InviteStatus: domain.InviteStatusPending}, time.Now().Add(10*time.Minute))
				require.NoError(t, err)
				require.NoError(t, w.Commit(f.r.ctx))
				recipient = string(pending.ID)
			}
			var email domain.Email
			require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT email FROM kaname.users WHERE id=$1`, recipient).Scan(&email))
			var capRole domain.RoleID
			if which == "self_old_covered" {
				capRole = inviteCoverageHolder(t, f)
			}
			require.NoError(t, lifecycleOwner(f.r).ActivateAuthorityBundle(f.r.ctx, f.r.bundle))
			if capRole != "" {
				invitePromoteCoverage(t, f, capRole)
			}
			before := inviteAllArtifacts(t, f.r)
			done := awaitDelegatedOperation(t, f.r.ctx, f.ops, f.execute(t, email, true, true).ID)
			if which == "self_old_covered" {
				require.Nil(t, done.Error)
			} else {
				require.NotNil(t, done.Error)
				require.EqualValues(t, codes.PermissionDenied, done.Error.Code)
				require.Equal(t, before, inviteAllArtifacts(t, f.r))
			}
			authorityWaitReleased(t, f.r.runtime)
		})
	}
}

// Проверяется настоящий read-time checkpoint на coordinated writer. Вычисленный
// bundle.Projection сам по себе не подтверждает ни строки БД, ни снятие pending.
func inviteAssertTypedAuthority(t *testing.T, f inviteDecisionFixture, actor domain.Subject, roleID domain.RoleID, owner bool) {
	t.Helper()
	w, err := f.r.repo.CoordinatedAuthorityWriter(f.r.ctx, kaname.AuthorityWriteIntent{Kind: kaname.AuthorityIdentity, Bundle: f.r.bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}})
	require.NoError(t, err)
	defer policyFixtureRollback(w)
	role, err := w.Roles().Get(f.r.ctx, roleID)
	require.NoError(t, err)
	want, err := f.r.bundle.Projection(role)
	require.NoError(t, err)
	got, cost, err := w.(kaname.SemanticSourceReader).RoleProjectionCheckpoint(f.r.ctx, roleID)
	require.NoError(t, err, "Дано: выбранная системная роль имеет полный живой checkpoint")
	require.Equal(t, want.Checkpoint, got)
	require.Positive(t, cost.Rows)
	require.Positive(t, cost.Reads)
	sources, next, err := w.CanonicalDirectSources(f.r.ctx, kaname.CanonicalSourceFilter{Actor: actor, Limit: kaname.MaxCanonicalSourcePage})
	require.NoError(t, err)
	require.Empty(t, next, "Дано: конечная canonical population этой fixture")
	accountOwner := false
	for _, source := range sources {
		accountOwner = accountOwner || source.SourceKind == kaname.CanonicalAccountOwner && source.ObjectID == f.r.a && source.Recipient == actor
	}
	require.Equal(t, owner, accountOwner, "Дано: owner подтверждён accounts.owner_user_id, admin не владелец")
	for _, q := range []struct {
		object string
		want   bool
	}{{"account:" + f.r.a, owner}, {"project:" + string(f.project), true}} {
		allowed, checkErr := w.SemanticRelationChecker().Check(f.r.ctx, string(actor.Type)+":"+string(actor.ID), "admin", q.object)
		require.NoError(t, checkErr, "Дано: подтверждённый producer, не один native bool: %s", q.object)
		require.Equal(t, q.want, allowed, q.object)
	}
	require.NoError(t, w.Rollback(f.r.ctx))
}

func TestInviteDecisionTypedOwnerAndServiceAccountOptional(t *testing.T) {
	for _, mode := range []string{"owner", "admin", "service_account_denied", "service_account_covered"} {
		t.Run(mode, func(t *testing.T) {
			f := newInviteDecisionFixture(t)
			actor := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(bindingPublicOwner(t, f.r))}
			var capRole, authorityRole domain.RoleID
			if strings.HasPrefix(mode, "service_account") {
				actor = domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(seedSAID(t, f.r.ctx, f.r.admin, f.r.a, "optional-sa"))}
				role := bindingRow(t, f.r, f.editor).RoleID
				w, err := lifecycleOwner(f.r).Writer(f.r.ctx)
				require.NoError(t, err)
				defer policyFixtureRollback(w)
				b, err := bindingset.Insert(f.r.ctx, w.AccessBindingsW(), domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID("acb")), Subjects: []domain.Subject{actor}, SubjectType: actor.Type, SubjectID: actor.ID, RoleID: role, ResourceType: "account", ResourceID: f.r.a, Scope: domain.ScopeAccount, Target: domain.AccessTarget{AllInScope: true}})
				require.NoError(t, err)
				require.NoError(t, w.Commit(f.r.ctx))
				catalog := rolePolicyCatalog(t, f.r)
				engine := reconcile.New(kanamepg.NewReconcileAdapter(f.r.admin, catalog), slog.Default(), catalog)
				require.NoError(t, engine.ReconcileBinding(f.r.ctx, b.ID))
				if mode == "service_account_covered" {
					capRole = inviteCoverageHolderFor(t, f, actor)
				}
			}
			if mode == "owner" || mode == "admin" {
				owner := bindingPublicOwner(t, f.r)
				role := domain.RoleID(domain.OwnerRoleID)
				scopeType, scopeID, scope := domain.ResourceType("account"), f.r.a, domain.ScopeAccount
				if mode == "admin" {
					actor = domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(f.actor)}
					role = domain.RoleID(domain.ClusterAdminRoleID)
					// В плоской модели account.admin не наследуется project.admin.
					// Точный project carrier даёт самостоятельный D3 на неизменный proposal.
					scopeType, scopeID, scope = domain.ResourceType("project"), string(f.project), domain.ScopeProject
					require.NotEqual(t, owner, string(actor.ID), "admin не является account owner")
				} else {
					require.Equal(t, owner, string(actor.ID), "владелец подтверждён accounts.owner_user_id")
				}
				var pendingBefore, verbsBefore int
				require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT (SELECT count(*) FROM kaname.role_selector_verbs_pending WHERE role_id=$1),(SELECT count(*) FROM kaname.role_verb WHERE role_id=$1)`, role).Scan(&pendingBefore, &verbsBefore))
				t.Logf("Дано до startup producer: role=%s pending=%d verbs=%d", role, pendingBefore, verbsBefore)
				// Штатный startup-досев закрывает миграционные selectors/verbs;
				// native материализация сама по себе read-time checkpoint не создаёт.
				source := rolePolicyCatalog(t, f.r)
				require.NoError(t, seed.SyncAllSystemRoleSelectors(f.r.ctx, f.r.admin))
				census, seedErr := seed.ReseedSystemRoleVerbs(f.r.ctx, lifecycleOwner(f.r), f.r.admin, source.Facts(), nil)
				require.NoError(t, seedErr)
				require.True(t, census.Completed)
				require.Positive(t, census.Reseeded)
				require.Zero(t, census.Failed)
				authorityRole = role
				var eligible bool
				require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT invite_status='ACTIVE' AND email_verified_at IS NOT NULL FROM kaname.users WHERE id=$1`, string(actor.ID)).Scan(&eligible))
				require.True(t, eligible, "Дано: реальная допущенная человеческая личность")
				w, err := lifecycleOwner(f.r).Writer(f.r.ctx)
				require.NoError(t, err)
				defer policyFixtureRollback(w)
				// Fixture аккаунта не создаёт owner auto-binding. Воспроизводим
				// его typed producer; у admin отдельный точный project carrier.
				b, err := bindingset.Insert(f.r.ctx, w.AccessBindingsW(), domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID("acb")), Subjects: []domain.Subject{actor}, SubjectType: actor.Type, SubjectID: actor.ID, RoleID: role, ResourceType: scopeType, ResourceID: scopeID, Scope: scope, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true}})
				require.NoError(t, err)
				require.NoError(t, w.Commit(f.r.ctx))
				catalog := rolePolicyCatalog(t, f.r)
				engine := reconcile.New(kanamepg.NewReconcileAdapter(f.r.admin, catalog), slog.Default(), catalog)
				require.NoError(t, engine.ReconcileBinding(f.r.ctx, b.ID))
				stored := bindingRow(t, f.r, b.ID)
				require.Equal(t, role, stored.RoleID)
				require.Len(t, stored.Subjects, 1)
				require.Equal(t, actor, stored.Subjects[0])
				require.Equal(t, scopeID, stored.ResourceID)
				require.Equal(t, scopeType, stored.ResourceType)
				require.Equal(t, scope, stored.Scope)
				require.True(t, stored.Target.AllInScope)
				require.Empty(t, stored.Target.Resources)
				native := delegationNativeDoor{r: f.r}
				for _, q := range []struct {
					relation, object string
					want             bool
				}{{"editor", "account:" + f.r.a, true}, {"admin", "account:" + f.r.a, mode == "owner"}, {"admin", "project:" + string(f.project), true}} {
					yes, err := native.Check(f.r.ctx, "user:"+string(actor.ID), q.relation, q.object)
					require.NoError(t, err)
					require.Equal(t, q.want, yes, "Дано: native %s(%s)", q.relation, q.object)
				}
				yes, err := native.Check(f.r.ctx, "user:"+string(actor.ID), "system_admin", "cluster:"+domain.ClusterSingletonID)
				require.NoError(t, err)
				require.False(t, yes, "account/project источник не даёт cluster bypass")
			}
			require.NoError(t, lifecycleOwner(f.r).ActivateAuthorityBundle(f.r.ctx, f.r.bundle))
			if capRole != "" {
				invitePromoteCoverage(t, f, capRole)
			}
			if authorityRole != "" {
				inviteAssertTypedAuthority(t, f, actor, authorityRole, mode == "owner")
			}
			// Декоратор только сохраняет точную ошибку до публичного mapping;
			// решение и общий UC body исполняет прежний настоящий runner.
			rawResult := make(chan error, 1)
			f.uc.WithInviteDecisions(inviteObservedRunner{base: f.runner, run: func(ctx context.Context, in userapp.InviteDecisionIntent, body func(context.Context, userapp.InviteMutationWriter, userapp.PreparedInvite) error) error {
				err := f.runner.RunInviteDecision(ctx, in, body)
				rawResult <- err
				return err
			}})
			email := domain.Email(mode + "@example.invalid")
			before := inviteAllArtifacts(t, f.r)
			ctx := operations.WithPrincipal(f.r.ctx, operations.Principal{Type: string(actor.Type), ID: string(actor.ID)})
			op, err := f.uc.Execute(ctx, userapp.InviteUserInput{AccountID: domain.AccountID(f.r.a), Email: email, ProjectID: f.project, RoleID: f.role})
			require.NoError(t, err)
			require.NotNil(t, op)
			done := awaitDelegatedOperation(t, f.r.ctx, f.ops, op.ID)
			var decisionErr error
			select {
			case decisionErr = <-rawResult:
			default:
				t.Fatal("Operation завершилась без возврата настоящего Invite runner")
			}
			if mode == "service_account_denied" {
				require.NotNil(t, done.Error)
				require.Equal(t, before, inviteAllArtifacts(t, f.r))
			} else {
				require.NoError(t, decisionErr, "Ошибка actual decision до Operation mapping")
				require.Nil(t, done.Error)
				var human bool
				var version int
				require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT u.invited_by IS NOT NULL,b.grant_capability_version FROM kaname.users u JOIN kaname.access_bindings b ON b.subject_id=u.id WHERE u.email=$1`, string(email)).Scan(&human, &version))
				require.Equal(t, 1, version)
				require.Equal(t, actor.Type == domain.SubjectTypeUser, human)
			}
			authorityWaitReleased(t, f.r.runtime)
		})
	}
}

func TestInviteDecisionClosedMigrationProfileACL(t *testing.T) {
	f := newInviteDecisionFixture(t)
	raw, err := migrations.FS.ReadFile("20261114120000_authority_invite_decision_preflight.sql")
	require.NoError(t, err)
	parts := strings.Split(string(raw), "-- +goose Down")
	require.Len(t, parts, 2)
	var before string
	const aclSQL = `SELECT jsonb_agg(jsonb_build_array(c.relname,c.relowner,c.relacl) ORDER BY c.relname)::text FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND c.relname IN ('authority_writer_protocol','authority_semantic_identity','authority_bundle_handoff','users','memberships')`
	require.NoError(t, f.r.admin.QueryRow(f.r.ctx, aclSQL).Scan(&before))
	// Исторический SELECT semantic identity разрешён; закрытые протокол и
	// handoff и запись metadata остаются недоступны в обеих фазах миграции.
	runtimePrivileges := func() [4]bool {
		var got [4]bool
		require.NoError(t, f.r.runtime.QueryRow(f.r.ctx, `SELECT
		 has_table_privilege(current_user,'kaname.authority_semantic_identity','SELECT'),
		 has_table_privilege(current_user,'kaname.authority_writer_protocol','SELECT'),
		 has_table_privilege(current_user,'kaname.authority_bundle_handoff','SELECT'),
		 has_table_privilege(current_user,'kaname.authority_semantic_identity','INSERT,UPDATE,DELETE,TRUNCATE,TRIGGER')`).Scan(&got[0], &got[1], &got[2], &got[3]))
		return got
	}
	baselinePrivileges := runtimePrivileges()
	require.Equal(t, [4]bool{true, false, false, false}, baselinePrivileges)
	require.Error(t, f.r.repo.ActivateAuthorityBundle(f.r.ctx, f.r.bundle), "runtime не может сам включить strict")
	for _, up := range []bool{false, true} {
		section := parts[1]
		if up {
			section = parts[0]
		}
		tx, err := f.r.admin.Begin(f.r.ctx)
		require.NoError(t, err)
		defer policyFixtureRollback(tx)
		_, err = tx.Exec(f.r.ctx, section)
		require.NoError(t, err)
		require.NoError(t, tx.Commit(f.r.ctx))
		var current string
		require.NoError(t, f.r.admin.QueryRow(f.r.ctx, aclSQL).Scan(&current))
		require.Equal(t, before, current)
		require.Equal(t, baselinePrivileges, runtimePrivileges(), "Up/Down не меняет права runtime на authority metadata")
		var present bool
		require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT to_regprocedure('kaname.authority_invite_phase_snapshot()') IS NOT NULL`).Scan(&present))
		require.Equal(t, up, present)
		var helpers int
		require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='kaname' AND p.proname=ANY($1::text[])`, []string{"authority_invite_phase_snapshot", "authority_invite_phase_held", "authority_invite_preflight", "authority_invite_final_clock"}).Scan(&helpers))
		require.Equal(t, map[bool]int{false: 0, true: 4}[up], helpers)
		if up {
			var executable bool
			require.NoError(t, f.r.runtime.QueryRow(f.r.ctx, `SELECT has_function_privilege(current_user,'kaname.authority_invite_preflight(boolean)','EXECUTE')`).Scan(&executable))
			var guarded int
			require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace WHERE n.nspname='kaname' AND p.proname=ANY($1::text[]) AND p.prosecdef AND p.proowner=(SELECT relowner FROM pg_class WHERE oid='kaname.authority_semantic_identity'::regclass) AND array_to_string(p.proconfig,',') LIKE '%search_path=pg_catalog, pg_temp%'`, []string{"authority_invite_phase_snapshot", "authority_invite_phase_held", "authority_invite_preflight", "authority_invite_final_clock"}).Scan(&guarded))
			require.Equal(t, 4, guarded)
			require.True(t, executable)
			_, err = f.r.runtime.Exec(f.r.ctx, `SELECT kaname.authority_invite_preflight(false)`)
			var pe *pgconn.PgError
			require.ErrorAs(t, err, &pe)
			require.Equal(t, "42501", pe.Code)
		}
	}
}

type invitePhaseBarrier struct {
	armed            atomic.Bool
	snapshots        atomic.Int32
	once             sync.Once
	entered, release chan struct{}
}

func (b *invitePhaseBarrier) TraceQueryStart(ctx context.Context, _ *pgx.Conn, d pgx.TraceQueryStartData) context.Context {
	if strings.Contains(d.SQL, "authority_invite_phase_snapshot") {
		b.snapshots.Add(1)
	}
	if b.armed.Load() && strings.HasPrefix(d.SQL, "begin isolation level read committed") {
		b.once.Do(func() {
			close(b.entered)
			select {
			case <-b.release:
			case <-ctx.Done():
			}
		})
	}
	return ctx
}
func (*invitePhaseBarrier) TraceQueryEnd(context.Context, *pgx.Conn, pgx.TraceQueryEndData) {}
func TestInviteDecisionTrustedPhaseRestagesAfterActivation(t *testing.T) {
	for _, covered := range []bool{false, true} {
		t.Run(fmt.Sprint(covered), func(t *testing.T) {
			f := newInviteDecisionFixture(t)
			var capRole domain.RoleID
			if covered {
				capRole = inviteCoverageHolder(t, f)
			}
			barrier := &invitePhaseBarrier{entered: make(chan struct{}), release: make(chan struct{})}
			cfg := f.r.runtime.Config()
			cfg.ConnConfig.Tracer = barrier
			pool, err := pgxpool.NewWithConfig(f.r.ctx, cfg)
			require.NoError(t, err)
			t.Cleanup(pool.Close)
			runner, err := kanamepg.NewInviteDecisionRunner(f.r.ctx, kanamepg.New(pool, nil), f.r.bundle)
			require.NoError(t, err)
			f.uc.WithInviteDecisions(runner)
			barrier.armed.Store(true)
			released := false
			defer func() {
				if !released {
					close(barrier.release)
				}
			}()
			email := domain.Email("phase-restage@example.invalid")
			before := inviteArtifacts(t, f.r, email)
			op := f.execute(t, email, false, true)
			select {
			case <-barrier.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("RR stage did not reach idle connection boundary")
			}
			require.NoError(t, lifecycleOwner(f.r).ActivateAuthorityBundle(f.r.ctx, f.r.bundle))
			if covered {
				invitePromoteCoverage(t, f, capRole)
			}
			close(barrier.release)
			released = true
			done := awaitDelegatedOperation(t, f.r.ctx, f.ops, op.ID)
			require.GreaterOrEqual(t, barrier.snapshots.Load(), int32(2), "prepared RR нельзя переиспользовать после active switch")
			if covered {
				require.Nil(t, done.Error)
				var version int
				require.NoError(t, f.r.admin.QueryRow(f.r.ctx, `SELECT b.grant_capability_version FROM kaname.access_bindings b JOIN kaname.users u ON u.id=b.subject_id WHERE u.email=$1`, string(email)).Scan(&version))
				require.Equal(t, 1, version)
			} else {
				require.NotNil(t, done.Error)
				require.Equal(t, before, inviteArtifacts(t, f.r, email))
			}
			authorityWaitReleased(t, pool)
		})
	}
}
func TestInviteDecisionTrustedPhaseMismatchStaleClosedAndForeignRepo(t *testing.T) {
	for _, mode := range []string{"transition", "stale", "closed", "foreign_repo", "canceled"} {
		t.Run(mode, func(t *testing.T) {
			f := newInviteDecisionFixture(t)
			in := inviteRunnerIntent(f, domain.Email(mode+"@example.invalid"))
			runner := f.runner
			switch mode {
			case "transition":
				_, err := f.r.admin.Exec(f.r.ctx, `UPDATE kaname.authority_writer_protocol SET enforcement='strict'`)
				require.NoError(t, err)
			case "stale":
				_, err := f.r.admin.Exec(f.r.ctx, `UPDATE kaname.authority_semantic_identity SET projector_version='invite-stale-projector'`)
				require.NoError(t, err)
			case "closed":
				require.NoError(t, lifecycleOwner(f.r).CloseAuthorityBundle(f.r.ctx))
			case "foreign_repo":
				other := writerProtocolRig(t)
				var err error
				runner, err = kanamepg.NewInviteDecisionRunner(other.ctx, other.repo, other.bundle)
				require.NoError(t, err)
			}
			before := inviteAllArtifacts(t, f.r)
			ctx, cancel := context.WithCancel(declarerCtx(f.r.ctx, f.actor))
			defer cancel()
			if mode == "canceled" {
				cancel()
			}
			called := false
			err := runner.RunInviteDecision(ctx, in, func(context.Context, userapp.InviteMutationWriter, userapp.PreparedInvite) error {
				called = true
				return nil
			})
			require.Error(t, err)
			require.False(t, called)
			if mode == "canceled" {
				require.ErrorIs(t, err, context.Canceled)
			}
			require.Equal(t, before, inviteAllArtifacts(t, f.r))
			authorityWaitReleased(t, f.r.runtime)
		})
	}
}

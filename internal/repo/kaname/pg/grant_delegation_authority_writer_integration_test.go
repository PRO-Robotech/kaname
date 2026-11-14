// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"context"
	"encoding/json"
	"log/slog"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	gdapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/grant_delegation"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleroles"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/manifest/roleexport"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
)

// Primitive fixture отделяет проверку writer protocol от policy Create: роли
// локальны специально, чтобы сравнить OLD+NEW и независимые account fences.
func delegationProtocolFixture(t *testing.T, r protocolRig, account string) domain.GrantDelegation {
	t.Helper()
	sa, role := ids.NewID("sva"), ids.NewID("rol")
	_, err := r.admin.Exec(r.ctx, `INSERT INTO kaname.service_accounts(id,account_id,name) VALUES($1,$2,$1)`, sa, account)
	require.NoError(t, err)
	_, err = r.admin.Exec(r.ctx, `INSERT INTO kaname.roles(id,account_id,name,permissions,rules) VALUES($1,$2,$1,'[]','[]')`, role, account)
	require.NoError(t, err)
	var owner string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, account).Scan(&owner))
	return domain.GrantDelegation{ID: domain.GrantDelegationID(ids.NewID("gdl")), AccountID: domain.AccountID(account), DelegateID: domain.ServiceAccountID(sa), RoleIDs: []domain.RoleID{domain.RoleID(role)}, TargetTypes: []string{"registry.registries"}, SubjectTypes: []domain.SubjectType{domain.SubjectTypeUser}, Module: "registry", DelegatedBy: domain.GrantDelegationActor{Type: "user", ID: owner}}
}
func TestGrantDelegationParticipantCreateUpdateAndRollback(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "strict"}[strict], func(t *testing.T) {
			r := writerProtocolRig(t)
			a, b := delegationProtocolFixture(t, r, r.a), delegationProtocolFixture(t, r, r.b)
			p, err := kanamepg.NewGrantDelegationParticipant(r.ctx, r.repo, r.bundle)
			require.NoError(t, err)
			if strict {
				r.strict(t)
			}
			w, err := p.GrantDelegationWriter(delegationProtocolContext(r.ctx, a), kaname.GrantDelegationCreate, a)
			require.NoError(t, err)
			f := w.(kaname.AuthorityWriter).AuthorityFence()
			require.Equal(t, []domain.AccountID{a.AccountID}, f.Accounts())
			_, err = w.AccessBindingsW().GrantDelegationsW().Insert(r.ctx, a)
			require.NoError(t, err)
			require.NoError(t, w.Commit(r.ctx))
			next := a
			next.RoleIDs = append(next.RoleIDs, b.RoleIDs...)
			w, err = p.GrantDelegationWriter(delegationProtocolContext(r.ctx, next), kaname.GrantDelegationUpdate, next)
			require.NoError(t, err)
			require.ElementsMatch(t, []domain.AccountID{a.AccountID, b.AccountID}, w.(kaname.AuthorityWriter).AuthorityFence().Accounts())
			_, err = w.AccessBindingsW().GrantDelegationsW().LockForRevoke(r.ctx, a.ID)
			require.NoError(t, err)
			_, err = w.AccessBindingsW().GrantDelegationsW().UpdateAxes(r.ctx, next)
			require.NoError(t, err)
			require.NoError(t, w.Rollback(r.ctx))
			rd, err := r.repo.Reader(r.ctx)
			require.NoError(t, err)
			got, err := rd.AccessBindings().GrantDelegations().Get(r.ctx, a.ID)
			require.NoError(t, err)
			require.Equal(t, a.RoleIDs, got.RoleIDs)
			require.NoError(t, rd.Rollback(r.ctx))
			w, err = p.GrantDelegationWriter(delegationProtocolContext(r.ctx, next), kaname.GrantDelegationUpdate, next)
			require.NoError(t, err)
			_, err = w.AccessBindingsW().GrantDelegationsW().LockForRevoke(r.ctx, a.ID)
			require.NoError(t, err)
			_, err = w.AccessBindingsW().GrantDelegationsW().UpdateAxes(r.ctx, next)
			require.NoError(t, err)
			require.NoError(t, w.Commit(r.ctx))

			authorityWaitReleased(t, r.runtime)
		})
	}
}
func TestGrantDelegationParticipantAccountsIndependentAndCancelledWait(t *testing.T) {
	r := writerProtocolRig(t)
	a, b := delegationProtocolFixture(t, r, r.a), delegationProtocolFixture(t, r, r.b)
	p, err := kanamepg.NewGrantDelegationParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	r.strict(t)
	first, err := p.GrantDelegationWriter(delegationProtocolContext(r.ctx, a), kaname.GrantDelegationCreate, a)
	require.NoError(t, err)
	defer func() { _ = first.Rollback(context.Background()) }()
	ctx, cancel := context.WithTimeout(r.ctx, 3*time.Second)
	defer cancel()
	other, err := p.GrantDelegationWriter(delegationProtocolContext(ctx, b), kaname.GrantDelegationCreate, b)
	require.NoError(t, err, "другой account проходит при удерживаемом первом fence")
	require.NoError(t, other.Rollback(r.ctx))
	blocked, stop := context.WithTimeout(r.ctx, 100*time.Millisecond)
	defer stop()
	same, err := p.GrantDelegationWriter(delegationProtocolContext(blocked, a), kaname.GrantDelegationCreate, a)
	require.Error(t, err)
	require.Nil(t, same)
	require.NoError(t, first.Rollback(r.ctx))
	authorityWaitReleased(t, r.runtime)
}
func TestGrantDelegationLegacyPrimitiveCompatibility(t *testing.T) {
	r := writerProtocolRig(t)
	d := delegationProtocolFixture(t, r, r.a)
	w, err := r.repo.Writer(r.ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().GrantDelegationsW().Insert(r.ctx, d)
	require.NoError(t, err)
	require.NoError(t, w.Commit(r.ctx))
	r.strict(t)
	w, err = r.repo.Writer(r.ctx)
	require.NoError(t, err)
	_, err = w.AccessBindingsW().GrantDelegationsW().UpdateAxes(r.ctx, d)
	require.Error(t, err, "raw отказ не заменяет успешный participant counterpart")
	_ = w.Rollback(r.ctx)
	authorityWaitReleased(t, r.runtime)
}

// Тот же manifest/catalog/roles pipeline, что у мира kaname#1032, поверх protocolRig
// с настоящим ordinary LOGIN. До установки нового bundle идут только owner
// fixture writes; прежний prepared bundle не используется для этих мутаций.
type delegationUCWorld struct {
	r             protocolRig
	source        catalog.Fixed
	door          delegationNativeDoor
	participant   *kanamepg.GrantDelegationParticipant
	ops           operations.Repo
	owner, member string
	input         gdapp.CreateInput
}

func delegationUCFixture(t *testing.T) delegationUCWorld {
	t.Helper()
	r := writerProtocolRig(t)
	raw, err := publicreadfixture.Read("registry.delegation-fixture.yaml")
	require.NoError(t, err)
	raw, err = publicreadfixture.WithWrites(raw)
	require.NoError(t, err)
	m, err := manifest.Load(raw)
	require.NoError(t, err)
	_, err = modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(r.admin)).ApplyAll(r.ctx, []*manifest.Manifest{m})
	require.NoError(t, err)
	live, err := kanamepg.NewCatalogRepo(r.admin).ReadLiveCatalog(r.ctx)
	require.NoError(t, err)
	facts, err := catalog.NewFacts(catalog.Halves{Live: live})
	require.NoError(t, err)
	reg, err := seed.LoadPermissionRegistry(r.ctx, slog.Default())
	require.NoError(t, err)
	entries := make([]roleexport.CatalogEntry, 0)
	for _, row := range reg.All() {
		entries = append(entries, roleexport.CatalogEntry{FQN: row.FQN, RequiredRelation: row.RequiredRelation, ScopeObjectType: row.ScopeExtractor.ObjectType})
	}
	attributed, _ := roleexport.Attribute(entries)
	rights, err := moduleroles.NewRightsExport(facts, attributed)
	require.NoError(t, err)
	_, err = moduleroles.NewApplier(moduleroles.NewRepoTxRunner(lifecycleOwner(r)), rights).Apply(r.ctx, m, moduleroles.BootActorID)
	require.NoError(t, err)
	require.NoError(t, seed.SyncAllSystemRoleSelectors(r.ctx, r.admin))
	_, err = seed.ReseedSystemRoleVerbs(r.ctx, lifecycleOwner(r), r.admin, facts, nil)
	require.NoError(t, err)
	model, rep, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	require.NoError(t, err)
	halves, err := kanamepg.NewCatalogRepo(r.admin).ReadCatalogHalves(r.ctx)
	require.NoError(t, err)
	r.bundle, err = granteffect.NewBundle(r.ctx, model, halves, granteffect.ProjectorVersion, rep.KeyTerms...)
	require.NoError(t, err)
	require.NoError(t, lifecycleOwner(r).PrepareAuthorityBundle(r.ctx, r.bundle))
	handoff, err := r.repo.LoadAuthorityBundle(r.ctx, model, rep.KeyTerms...)
	require.NoError(t, err)
	participant, err := kanamepg.NewGrantDelegationParticipant(r.ctx, r.repo, handoff)
	require.NoError(t, err)
	var owner, role string
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, r.a).Scan(&owner))
	member := seedMemberUser(t, r.ctx, r.admin, r.a, "delegation-native-member")
	_, err = r.admin.Exec(r.ctx, `UPDATE kaname.users SET email_verified_at=clock_timestamp() WHERE id=ANY($1::text[])`, []string{owner, member})
	require.NoError(t, err)
	sa := seedSAID(t, r.ctx, r.admin, r.a, "delegation-native-recipient")
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT id FROM kaname.roles WHERE name='registry.puller' AND owner_module='registry'`).Scan(&role))
	return delegationUCWorld{r: r, source: catalog.Fixed{F: facts}, door: delegationNativeDoor{r: r}, participant: participant, ops: operations.NewRepo(r.runtime, "kaname"), owner: owner, member: member, input: gdapp.CreateInput{AccountID: r.a, DelegateType: "SUBJECT_TYPE_SERVICE_ACCOUNT", DelegateID: sa, RoleIDs: []string{role}, TargetTypes: []string{"registry.registries"}, SubjectTypes: []string{"SUBJECT_TYPE_SERVICE_ACCOUNT"}}}
}

// Только читающий test adapter к реальному relverdict/admission, без своих
// ответов о policy и без Shared. Worker спрашивает отдельный TX checker p.
type delegationNativeDoor struct{ r protocolRig }

func (d delegationNativeDoor) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	tx, err := d.r.runtime.BeginTx(ctx, pgx.TxOptions{AccessMode: pgx.ReadOnly})
	if err != nil {
		return false, err
	}
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	var at time.Time
	if err = tx.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&at); err != nil {
		return false, err
	}
	checker := authzcascade.WrapAdmitted(relverdict.NewSemanticTransactionAsker(tx, d.r.bundle, at), personmarks.NewTransaction(tx))
	return checker.Check(ctx, subject, relation, object)
}

type delegationObservedFactory struct {
	p      kaname.GrantDelegationWriterFactory
	opened chan kaname.Writer
}

func (p delegationObservedFactory) GrantDelegationWriter(ctx context.Context, k kaname.GrantDelegationMutation, d domain.GrantDelegation) (kaname.Writer, error) {
	w, err := p.p.GrantDelegationWriter(ctx, k, d)
	if err == nil {
		// Whole-TX retry не блокируется на прежней откатившейся попытке;
		// time/assertions ниже проверяют последнюю фактически открытую TX.
		select {
		case p.opened <- w:
		default:
			<-p.opened
			p.opened <- w
		}
	}
	return w, err
}
func (w delegationUCWorld) create(t *testing.T, who string, installation bool) string {
	t.Helper()
	f := delegationObservedFactory{p: w.participant, opened: make(chan kaname.Writer, 1)}
	uc := gdapp.NewCreateGrantDelegationUseCase(w.r.repo, w.ops, w.source).WithRelationStore(w.door, nil).WithAuthorityWriter(f)
	plans, err := authzmodel.New(w.r.bundle.ModelSource())
	require.NoError(t, err)
	uc.WithInstallationModel(plans)
	var op *operations.Operation
	if installation {
		op, err = uc.ExecuteInstallation(declarerCtx(w.r.ctx, who), w.input)
	} else {
		op, err = uc.Execute(declarerCtx(w.r.ctx, who), w.input)
	}
	require.NoError(t, err)
	done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
	require.Nil(t, done.Error)
	select {
	case tx := <-f.opened:
		require.False(t, tx.(kaname.AuthorityWriter).AuthorityFence().DecisionAt().IsZero())
	default:
		t.Fatal("actual Create worker не вызвал participant")
	}
	var id string
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT id FROM kaname.grant_delegations WHERE account_id=$1 AND delegate_id=$2 AND status='ACTIVE'`, w.input.AccountID, w.input.DelegateID).Scan(&id))
	return id
}
func (w delegationUCWorld) grantAdmin(t *testing.T) domain.AccessBindingID {
	t.Helper()
	writer, err := lifecycleOwner(w.r).Writer(w.r.ctx)
	require.NoError(t, err)
	defer func() { _ = writer.Rollback(context.WithoutCancel(w.r.ctx)) }()
	b, err := bindingset.Insert(w.r.ctx, writer.AccessBindingsW(), domain.AccessBinding{ID: domain.AccessBindingID(ids.NewID("acb")), SubjectType: domain.SubjectTypeUser, SubjectID: domain.SubjectID(w.member), RoleID: domain.RoleID(domain.ClusterAdminRoleID), ResourceType: "account", ResourceID: w.r.a, Scope: domain.ScopeAccount, Status: domain.AccessBindingStatusActive, Target: domain.AccessTarget{AllInScope: true}})
	require.NoError(t, err)
	require.NoError(t, writer.Commit(w.r.ctx))
	// Insert пишет выдачу и субъектов, но не материализует scope-self admin.
	// Вывод кортежей, ledger и outbox выполняет настоящий production reconciler.
	engine := reconcile.New(kanamepg.NewReconcileAdapter(w.r.admin, w.source), slog.Default(), w.source)
	require.NoError(t, engine.ReconcileBinding(w.r.ctx, b.ID))
	var holders int
	require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.access_binding_emitted_tuples WHERE binding_id=$1 AND member_object_type='iam.account' AND member_object_id=$2 AND fga_user=$3 AND relation='admin' AND object=$4`, string(b.ID), w.r.a, "user:"+w.member, "account:"+w.r.a).Scan(&holders))
	require.Equal(t, 1, holders, "admin должен происходить из ledger этой выдачи")
	allowed, err := w.door.Check(w.r.ctx, "user:"+w.member, "admin", "account:"+w.r.a)
	require.NoError(t, err)
	require.True(t, allowed, "Дано: реальная admin выдача разрешает native account authority")
	return b.ID
}

// GrantAdmin.doGrant пишет исходную выдачу и её native-проекцию одной TX.
// Row-only seedClusterAdmin предназначен для last-admin тестов, не для Check.
func (w delegationUCWorld) grantClusterAdmin(t *testing.T) {
	t.Helper()
	tx, err := w.r.admin.Begin(w.r.ctx)
	require.NoError(t, err)
	defer func() {
		cleanup, cancel := context.WithTimeout(context.WithoutCancel(w.r.ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(cleanup)
	}()
	grant, created, err := kanamepg.NewClusterAdminGrantWriter(w.r.admin).Grant(w.r.ctx, tx, domain.GrantSubjectTypeUser, domain.SubjectID(w.member), w.owner)
	require.NoError(t, err)
	require.True(t, created)
	require.True(t, grant.IsActive())
	require.NoError(t, kanamepg.NewFGAOutboxEmitter().EmitWriteTx(w.r.ctx, tx, fgaTuplesGrantSystemAdmin(w.member)))
	require.NoError(t, tx.Commit(w.r.ctx))
}

func delegationAuditCount(t *testing.T, r protocolRig, id string) int {
	t.Helper()
	var n int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.grant_delegation.updated' AND event_payload->>'delegation_id'=$1`, id).Scan(&n))
	return n
}

// Actual Update.Execute: preflight проходит пока admin AccessBinding жив, а
// native actor/creator проверяется после реального ожидания строки GD. Expiry
// принадлежит authority source, никакого TTL у GrantDelegation не добавляется.
func TestGrantDelegationNativeUpdateLateExpiryAfterRowWait(t *testing.T) {
	for _, barrier := range []string{"fence", "pair", "row"} {
		for _, axis := range []string{"actor", "creator"} {
			for _, expired := range []bool{false, true} {
				t.Run(barrier+"_"+axis+map[bool]string{false: "_live", true: "_expired"}[expired], func(t *testing.T) {
					w := delegationUCFixture(t)
					authority := w.grantAdmin(t)
					creator, actor := w.owner, w.member
					if axis == "creator" {
						creator, actor = w.member, w.owner
					}
					id := w.create(t, creator, false)
					before := delegationAuditCount(t, w.r, id)
					locker, err := w.r.admin.Begin(w.r.ctx)
					require.NoError(t, err)
					lifecycleRollback(t, locker)
					// Compat source UPDATE после worker guard создаёт настоящий цикл.
					// Worker первым обнаруживает цикл и обязан целиком restage;
					// owner locker держит старый GD lock до source commit.
					var detectorFast bool
					require.NoError(t, w.r.runtime.QueryRow(w.r.ctx, `SELECT current_setting('deadlock_timeout')::interval < interval '5 seconds'`).Scan(&detectorFast))
					require.True(t, detectorFast)
					_, err = locker.Exec(w.r.ctx, `SET LOCAL deadlock_timeout='5s'`)
					require.NoError(t, err)
					var xid string
					switch barrier {
					case "row":
						require.NoError(t, locker.QueryRow(w.r.ctx, `SELECT id FROM kaname.grant_delegations WHERE id=$1 FOR UPDATE`, id).Scan(new(string)))
					case "pair":
						_, err = locker.Exec(w.r.ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,1038))`, w.input.AccountID+"/"+w.input.DelegateID)
						require.NoError(t, err)
					case "fence":
						_, err = locker.Exec(w.r.ctx, `SELECT pg_advisory_xact_lock(1262569283,0)`)
						require.NoError(t, err)
					}
					require.NoError(t, locker.QueryRow(w.r.ctx, `SELECT pg_current_xact_id()::text`).Scan(&xid))
					observed := delegationObservedFactory{p: w.participant, opened: make(chan kaname.Writer, 1)}
					uc := gdapp.NewUpdateGrantDelegationUseCase(w.r.repo, w.ops, w.source).WithRelationStore(w.door, nil).WithAuthorityWriter(observed)
					op, err := uc.Execute(declarerCtx(w.r.ctx, actor), gdapp.UpdateInput{GrantDelegationID: id, SubjectTypes: []string{"SUBJECT_TYPE_SERVICE_ACCOUNT", "SUBJECT_TYPE_USER"}, UpdateMask: []string{"subject_types"}})
					require.NoError(t, err)
					switch barrier {
					case "row":
						semanticWaitIdentity(t, w.r.ctx, w.r.admin, xid)
					case "fence":
						authorityWaitLock(t, w.r.ctx, w.r.admin)
					case "pair":
						require.Eventually(t, func() bool {
							var waiting bool
							err := w.r.admin.QueryRow(w.r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objsubid=1 AND NOT granted)`).Scan(&waiting)
							return err == nil && waiting
						}, 5*time.Second, 10*time.Millisecond, "worker должен ждать настоящий legacy pair lock")
					}
					var expires time.Time
					sql := `UPDATE kaname.access_bindings SET expires_at=clock_timestamp()+interval '1 hour' WHERE id=$1 RETURNING expires_at`
					if expired {
						sql = `UPDATE kaname.access_bindings SET expires_at=clock_timestamp() WHERE id=$1 RETURNING expires_at`
					}
					require.NoError(t, locker.QueryRow(w.r.ctx, sql, string(authority)).Scan(&expires))
					require.NoError(t, locker.Commit(w.r.ctx))
					done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
					var tx kaname.Writer
					select {
					case tx = <-observed.opened:
					case <-time.After(5 * time.Second):
						t.Fatal("actual Update worker не вызвал participant")
					}
					if expired {
						require.True(t, tx.(kaname.AuthorityWriter).AuthorityFence().DecisionAt().After(expires))
						require.NotNil(t, done.Error)
						want := codes.PermissionDenied
						if axis == "creator" {
							want = codes.FailedPrecondition
						}
						require.Equal(t, int32(want), done.Error.Code)
					} else {
						require.Nil(t, done.Error)
					}
					rd, err := w.r.repo.Reader(w.r.ctx)
					require.NoError(t, err)
					got, err := rd.AccessBindings().GrantDelegations().Get(w.r.ctx, domain.GrantDelegationID(id))
					require.NoError(t, err)
					_ = rd.Rollback(w.r.ctx)
					require.Equal(t, creator, got.DelegatedBy.ID, "creator provenance не заменяется actor")
					if expired {
						require.Equal(t, []domain.SubjectType{domain.SubjectTypeServiceAccount}, got.SubjectTypes)
						require.Equal(t, before, delegationAuditCount(t, w.r, id))
					} else {
						require.Contains(t, got.SubjectTypes, domain.SubjectTypeUser)
						require.Equal(t, before+1, delegationAuditCount(t, w.r, id))
						var payload []byte
						require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT event_payload FROM kaname.audit_outbox WHERE event_type='iam.grant_delegation.updated' AND event_payload->>'delegation_id'=$1`, id).Scan(&payload))
						var audit map[string]any
						require.NoError(t, json.Unmarshal(payload, &audit))
						require.Equal(t, actor, audit["actor"])
					}
					authorityWaitReleased(t, w.r.runtime)
				})
			}
		}
	}
}

func TestGrantDelegationExecuteInstallationParticipantHistory(t *testing.T) {
	for _, strict := range []bool{false, true} {
		t.Run(map[bool]string{false: "prepared", true: "strict"}[strict], func(t *testing.T) {
			w := delegationUCFixture(t)
			w.grantClusterAdmin(t)
			allowed, err := w.door.Check(w.r.ctx, "user:"+w.member, "system_admin", "cluster:"+domain.ClusterSingletonID)
			require.NoError(t, err)
			require.True(t, allowed)
			if strict {
				w.r.strict(t)
			}
			first := w.create(t, w.member, true)
			second := w.create(t, w.member, true)
			require.Equal(t, first, second, "InstallationPair сохраняет победивший id")
			var total, audit int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.grant_delegations WHERE account_id=$1 AND delegate_id=$2`, w.input.AccountID, w.input.DelegateID).Scan(&total))
			require.Equal(t, 1, total)
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.grant_delegation.created' AND event_payload->>'delegation_id'=$1`, first).Scan(&audit))
			require.Equal(t, 1, audit)
			// Уже отозванная история не заменяется новым ACTIVE при повторе установки.
			// kaname#1034: strict сохраняет backstop и для подготовки истории;
			// штатный writer подтверждает область и меняет состояние typed CAS.
			history, err := w.participant.GrantDelegationWriter(declarerCtx(w.r.ctx, w.member), kaname.GrantDelegationUpdate, domain.GrantDelegation{ID: domain.GrantDelegationID(first)})
			require.NoError(t, err)
			t.Cleanup(func() {
				cleanup, cancel := context.WithTimeout(context.WithoutCancel(w.r.ctx), 5*time.Second)
				defer cancel()
				_ = history.Rollback(cleanup)
			})
			_, err = history.AccessBindingsW().GrantDelegationsW().LockForRevoke(w.r.ctx, domain.GrantDelegationID(first))
			require.NoError(t, err)
			_, err = history.AccessBindingsW().GrantDelegationsW().MarkRevoked(w.r.ctx, domain.GrantDelegationID(first), domain.GrantDelegationActor{Type: "user", ID: w.member}, history.(kaname.AuthorityWriter).AuthorityFence().DecisionAt())
			require.NoError(t, err)
			require.NoError(t, history.Commit(w.r.ctx))
			plans, err := authzmodel.New(w.r.bundle.ModelSource())
			require.NoError(t, err)
			uc := gdapp.NewCreateGrantDelegationUseCase(w.r.repo, w.ops, w.source).WithRelationStore(w.door, nil).WithInstallationModel(plans).WithAuthorityWriter(w.participant)
			op, err := uc.ExecuteInstallation(declarerCtx(w.r.ctx, w.member), w.input)
			require.NoError(t, err)
			done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
			require.NotNil(t, done.Error)
			require.Equal(t, int32(codes.FailedPrecondition), done.Error.Code)
			var active int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.grant_delegations WHERE account_id=$1 AND delegate_id=$2 AND status='ACTIVE'`, w.input.AccountID, w.input.DelegateID).Scan(&active))
			require.Zero(t, active)
			authorityWaitReleased(t, w.r.runtime)
		})
	}
}

// Реальный глобальный fence не подменяется sleep. Каждая следующая TX
// ставится в очередь ПОСЛЕ participant, прежде чем предыдущая отпускает fence.
type delegationFenceGate struct {
	tx   pgx.Tx
	done chan error
}

func delegationQueueFence(t *testing.T, r protocolRig) *delegationFenceGate {
	t.Helper()
	tx, err := r.admin.Begin(r.ctx)
	require.NoError(t, err)
	lifecycleRollback(t, tx)
	g := &delegationFenceGate{tx: tx, done: make(chan error, 1)}
	go func() { _, err := tx.Exec(r.ctx, `SELECT pg_advisory_xact_lock(1262569283,0)`); g.done <- err }()
	return g
}
func (g *delegationFenceGate) acquired(t *testing.T) {
	t.Helper()
	select {
	case err := <-g.done:
		require.NoError(t, err)
	case <-time.After(5 * time.Second):
		t.Fatal("fixture fence не получен")
	}
}

type delegationOpenResult struct {
	writer kaname.Writer
	err    error
}

func delegationStart(t *testing.T, r protocolRig, p *kanamepg.GrantDelegationParticipant, d domain.GrantDelegation) chan delegationOpenResult {
	t.Helper()
	out := make(chan delegationOpenResult, 1)
	go func() {
		w, err := p.GrantDelegationWriter(delegationProtocolContext(r.ctx, d), kaname.GrantDelegationCreate, d)
		out <- delegationOpenResult{w, err}
	}()
	return out
}
func delegationTake(t *testing.T, out chan delegationOpenResult) delegationOpenResult {
	t.Helper()
	select {
	case got := <-out:
		return got
	case <-time.After(5 * time.Second):
		t.Fatal("bounded writer не завершил entry")
		return delegationOpenResult{}
	}
}
func TestGrantDelegationOwnershipReclassificationBeforeMutation(t *testing.T) {
	for _, axis := range []string{"role", "recipient"} {
		t.Run(axis, func(t *testing.T) {
			r := writerProtocolRig(t)
			d := delegationProtocolFixture(t, r, r.a)
			p, err := kanamepg.NewGrantDelegationParticipant(r.ctx, r.repo, r.bundle)
			require.NoError(t, err)
			gate := delegationQueueFence(t, r)
			gate.acquired(t)
			out := delegationStart(t, r, p, d)
			authorityWaitLock(t, r.ctx, r.admin)
			if axis == "role" {
				_, err = gate.tx.Exec(r.ctx, `UPDATE kaname.roles SET account_id=$2 WHERE id=$1`, string(d.RoleIDs[0]), r.b)
			} else {
				_, err = gate.tx.Exec(r.ctx, `UPDATE kaname.service_accounts SET account_id=$2 WHERE id=$1`, string(d.DelegateID), r.b)
			}
			require.NoError(t, err)
			require.NoError(t, gate.tx.Commit(r.ctx))
			got := delegationTake(t, out)
			require.NoError(t, got.err)
			require.NotNil(t, got.writer)
			require.ElementsMatch(t, []domain.AccountID{domain.AccountID(r.a), domain.AccountID(r.b)}, got.writer.(kaname.AuthorityWriter).AuthorityFence().Accounts(), "fresh union после rollback/re-entry; shared fence не повышается")
			_, err = got.writer.AccessBindingsW().GrantDelegationsW().Insert(r.ctx, d)
			require.NoError(t, err)
			require.NoError(t, got.writer.Rollback(r.ctx))
			var rows int
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.grant_delegations WHERE id=$1`, string(d.ID)).Scan(&rows))
			require.Zero(t, rows)
			authorityWaitReleased(t, r.runtime)
		})
	}
}
func TestGrantDelegationOwnershipChurnExhaustsBoundWithoutPartialWrite(t *testing.T) {
	r := writerProtocolRig(t)
	d := delegationProtocolFixture(t, r, r.a)
	p, err := kanamepg.NewGrantDelegationParticipant(r.ctx, r.repo, r.bundle)
	require.NoError(t, err)
	gate := delegationQueueFence(t, r)
	gate.acquired(t)
	out := delegationStart(t, r, p, d)
	// Coordinator имеет три попытки. Ownership меняется под каждым удерживаемым
	// fixture fence ПОСЛЕ discovery и до проверки его actual anchors.
	for attempt := 0; attempt < 3; attempt++ {
		authorityWaitLock(t, r.ctx, r.admin)
		var next *delegationFenceGate
		if attempt < 2 {
			next = delegationQueueFence(t, r)
			// Две ожидающие TX подтверждают FIFO-предпосылку очереди fences.
			require.Eventually(t, func() bool {
				var n int
				err := r.admin.QueryRow(r.ctx, `SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND objsubid=2 AND NOT granted`).Scan(&n)
				return err == nil && n >= 2
			}, 5*time.Second, 10*time.Millisecond)
		}
		account := r.b
		if attempt%2 == 1 {
			account = r.a
		}
		_, err = gate.tx.Exec(r.ctx, `UPDATE kaname.service_accounts SET account_id=$2 WHERE id=$1`, string(d.DelegateID), account)
		require.NoError(t, err)
		require.NoError(t, gate.tx.Commit(r.ctx))
		if next != nil {
			next.acquired(t)
			gate = next
		}
	}
	got := delegationTake(t, out)
	require.Nil(t, got.writer)
	require.ErrorIs(t, got.err, kaname.ErrAuthorityClassificationChanged)
	require.ErrorIs(t, got.err, iamerr.ErrAborted)
	var rows int
	require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT count(*) FROM kaname.grant_delegations WHERE id=$1`, string(d.ID)).Scan(&rows))
	require.Zero(t, rows)
	authorityWaitReleased(t, r.runtime)
}
func TestGrantDelegationParticipantRejectsMalformedStaleAndClosedBundle(t *testing.T) {
	for _, kind := range []string{"malformed", "stale", "closed"} {
		t.Run(kind, func(t *testing.T) {
			w := delegationUCFixture(t)
			if kind == "malformed" {
				for _, bad := range []*granteffect.Bundle{nil, {}} {
					p, err := kanamepg.NewGrantDelegationParticipant(w.r.ctx, w.r.repo, bad)
					require.ErrorIs(t, err, granteffect.ErrInvalidBundle)
					require.Nil(t, p)
				}
				return
			}
			if kind == "stale" {
				_, err := w.r.admin.Exec(w.r.ctx, `UPDATE kaname.authority_semantic_identity SET projector_version='stale-projector'`)
				require.NoError(t, err)
			} else {
				require.NoError(t, lifecycleOwner(w.r).CloseAuthorityBundle(w.r.ctx))
			}
			uc := gdapp.NewCreateGrantDelegationUseCase(w.r.repo, w.ops, w.source).WithRelationStore(w.door, nil).WithAuthorityWriter(w.participant)
			op, err := uc.Execute(declarerCtx(w.r.ctx, w.owner), w.input)
			require.NoError(t, err)
			done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
			require.NotNil(t, done.Error, "worker не должен fallback на raw Writer")
			var rows, audit int
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.grant_delegations WHERE account_id=$1 AND delegate_id=$2`, w.input.AccountID, w.input.DelegateID).Scan(&rows))
			require.Zero(t, rows)
			require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.grant_delegation.created' AND event_payload->>'delegate'=$1`, w.input.DelegateID).Scan(&audit))
			require.Zero(t, audit)
			authorityWaitReleased(t, w.r.runtime)
		})
	}
}

// Public Create сохраняет исходный preflight, но не переносит его разрешение
// через ожидание pair/fence. Смена владельца и expiry — реальные DB источники.
func TestGrantDelegationOrdinaryCreateRechecksLiveAuthorityInsideParticipant(t *testing.T) {
	for _, source := range []string{"owner", "native-admin"} {
		for _, denied := range []bool{false, true} {
			t.Run(source+map[bool]string{false: "_live", true: "_lost"}[denied], func(t *testing.T) {
				w := delegationUCFixture(t)
				actor := w.owner
				var binding domain.AccessBindingID
				if source == "native-admin" {
					actor = w.member
					binding = w.grantAdmin(t)
				}
				locker, err := w.r.admin.Begin(w.r.ctx)
				require.NoError(t, err)
				lifecycleRollback(t, locker)
				var detectorFast bool
				require.NoError(t, w.r.runtime.QueryRow(w.r.ctx, `SELECT current_setting('deadlock_timeout')::interval < interval '5 seconds'`).Scan(&detectorFast))
				require.True(t, detectorFast)
				_, err = locker.Exec(w.r.ctx, `SET LOCAL deadlock_timeout='5s'`)
				require.NoError(t, err)
				if source == "owner" {
					_, err = locker.Exec(w.r.ctx, `SELECT pg_advisory_xact_lock(1262569283,0)`)
				} else {
					_, err = locker.Exec(w.r.ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1,1038))`, w.input.AccountID+"/"+w.input.DelegateID)
				}
				require.NoError(t, err)
				observed := delegationObservedFactory{p: w.participant, opened: make(chan kaname.Writer, 1)}
				uc := gdapp.NewCreateGrantDelegationUseCase(w.r.repo, w.ops, w.source).WithRelationStore(w.door, nil).WithAuthorityWriter(observed)
				op, err := uc.Execute(declarerCtx(w.r.ctx, actor), w.input)
				require.NoError(t, err, "Дано: preflight authority ещё жив")
				if source == "owner" {
					authorityWaitLock(t, w.r.ctx, w.r.admin)
				} else {
					require.Eventually(t, func() bool {
						var yes bool
						err := w.r.admin.QueryRow(w.r.ctx, `SELECT EXISTS(SELECT 1 FROM pg_locks WHERE locktype='advisory' AND objsubid=1 AND NOT granted)`).Scan(&yes)
						return err == nil && yes
					}, 5*time.Second, 10*time.Millisecond)
				}
				if denied {
					if source == "owner" {
						_, err = locker.Exec(w.r.ctx, `UPDATE kaname.accounts SET owner_user_id=$2 WHERE id=$1`, w.r.a, w.member)
					} else {
						_, err = locker.Exec(w.r.ctx, `UPDATE kaname.access_bindings SET expires_at=clock_timestamp() WHERE id=$1`, string(binding))
					}
					require.NoError(t, err)
				}
				require.NoError(t, locker.Commit(w.r.ctx))
				done := awaitOperation(t, w.r.ctx, w.ops, op.ID)
				var tx kaname.Writer
				select {
				case tx = <-observed.opened:
				case <-time.After(5 * time.Second):
					t.Fatal("actual Create worker не вызвал participant")
				}
				var rows, audit int
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.grant_delegations WHERE account_id=$1 AND delegate_id=$2`, w.input.AccountID, w.input.DelegateID).Scan(&rows))
				require.NoError(t, w.r.admin.QueryRow(w.r.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.grant_delegation.created' AND event_payload->>'delegate'=$1`, w.input.DelegateID).Scan(&audit))
				if denied {
					require.NotNil(t, done.Error)
					require.Equal(t, int32(codes.PermissionDenied), done.Error.Code)
					require.Zero(t, rows)
					require.Zero(t, audit)
				} else {
					require.Nil(t, done.Error)
					require.Equal(t, 1, rows)
					require.Equal(t, 1, audit)
				}
				checker, err := tx.TransactionRelationChecker(nil)
				require.NoError(t, err)
				allowed, err := checker.Check(w.r.ctx, "user:"+actor, "admin", "account:"+w.r.a)
				require.Error(t, err)
				require.False(t, allowed, "закрытый writer не открывает pool fallback")
				authorityWaitReleased(t, w.r.runtime)
			})
		}
	}
}

func delegationProtocolContext(ctx context.Context, d domain.GrantDelegation) context.Context {
	return operations.WithPrincipal(ctx, operations.Principal{Type: d.DelegatedBy.Type, ID: d.DelegatedBy.ID})
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding/reconcile"
	groupapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/group"
	internaliam "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/internal_iam"
	projectapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project"
	roleapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/role"
	"github.com/PRO-Robotech/kaname/internal/authzcascade"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/personmarks"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/PRO-Robotech/kaname/internal/testsupport/registrationwriterfixture"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/timestamppb"
)

// Каждый мир использует прежний настоящий runtime LOGIN и тот же DB bundle.
// Новые адаптеры наблюдают только завершение настоящих callbacks настройки.
type fbRemainingWorld struct {
	*fbStructuredWorld
	groups *groupapp.Handler
}

func newFBRemainingWorld(t *testing.T, identityFixtures ...func(*atcWorld)) *fbRemainingWorld {
	t.Helper()
	w := &fbRemainingWorld{fbStructuredWorld: newFBStructuredWorld(t, false, identityFixtures...)}
	composed, report, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{w.manifest(false)})
	require.NoError(t, err)
	bundle, err := w.repo.LoadAuthorityBundle(w.ctx, composed, report.KeyTerms...)
	require.NoError(t, err)
	writers, err := kanamepg.NewGrantPolicyWriters(w.ctx, w.repo, bundle)
	require.NoError(t, err)
	participant, err := kanamepg.NewGroupMembershipParticipant(w.ctx, w.repo, bundle)
	require.NoError(t, err)
	objects := &fbRoleObjects{Reconciler: w.rec, callbacks: w.callbacks}
	w.groups = groupapp.NewHandler(
		groupapp.NewCreateGroupUseCase(w.repo, w.ops).WithRelationStore(w.door, slog.Default()).
			WithLifecycleWriter(participant).WithObjectReconciler(objects),
		nil, nil, nil, nil,
		groupapp.NewAddMemberUseCase(w.repo, w.ops).
			WithGrantAuthority(accessbindingapp.NewScopeGrantAuthority(w.repo, w.door)).
			WithMembershipWriter(participant).WithGroupAdditionAuthorityWriter(writers),
		nil, nil,
	)
	return w
}

func (w *fbRemainingWorld) role(name string, rules ...*iamv1.Rule) domain.RoleID {
	w.t.Helper()
	id := w.fullBindWorld.role(name, rules...)
	require.NoError(w.t, w.callbacks.awaitSetup(w.ctx, "iam.role", string(id)))
	return id
}

func (w *fbRemainingWorld) group(name string) domain.GroupID {
	w.t.Helper()
	op, err := w.groups.Create(asUser(w.ctx, w.usrA), &iamv1.CreateGroupRequest{AccountId: string(w.accA), Name: name})
	require.NoError(w.t, err)
	require.NotNil(w.t, op)
	require.Nil(w.t, awaitOp(w.t, w.ctx, w.ops, op.GetId()).Error)
	var md iamv1.CreateGroupMetadata
	require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md))
	require.NotEmpty(w.t, md.GetGroupId())
	require.NoError(w.t, w.callbacks.awaitSetup(w.ctx, "iam.group", md.GetGroupId()))
	var account string
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT account_id FROM kaname.groups WHERE id=$1`, md.GetGroupId()).Scan(&account))
	require.Equal(w.t, string(w.accA), account)
	return domain.GroupID(md.GetGroupId())
}

func (w *fbRemainingWorld) groupMethod(id domain.GroupID) {
	w.t.Helper()
	r := w.role("fb_group_update", &iamv1.Rule{Module: "iam", Resources: []string{"group"}, Verbs: []string{"update"}, ResourceNames: []string{string(id)}})
	w.grant(fbStructuredRequest(userSubject(w.usrD), r, "account", string(w.accA)))
	w.native("user:"+string(w.usrD), "v_update", "iam_group", string(id), relverdict.Allow)
	w.native("user:"+string(w.usrD), "admin", "iam_group", string(id), relverdict.Deny)
	w.noScopeAdmin("user:" + string(w.usrD))
}

// Operation lifecycle разрешён отдельным оракулом. Полные остальные строки
// должны совпадать при отказе worker, включая journal, projection и audit.
func (w *fbRemainingWorld) business() map[string]string {
	w.t.Helper()
	out := w.artifacts()
	delete(out, "operations")
	for _, table := range []string{"groups", "group_members", "memberships"} {
		var rows string
		require.NoError(w.t, w.observer.QueryRow(w.ctx, "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM kaname."+table+" r").Scan(&rows))
		out[table] = rows
	}
	return out
}

func (w *fbRemainingWorld) memberAbsent(group domain.GroupID, member domain.Subject) {
	w.t.Helper()
	var n int
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.group_members WHERE group_id=$1 AND member_type=$2 AND member_id=$3`, group, member.Type, member.ID).Scan(&n))
	require.Zero(w.t, n)
	w.native(string(member.Type)+":"+string(member.ID), "member", "group", string(group), relverdict.Deny)
}

func (w *fbRemainingWorld) addMember(req *iamv1.AddGroupMemberRequest, want codes.Code, message string) {
	w.t.Helper()
	fixed, before := proto.Clone(req), w.business()
	member := domain.Subject{Type: domain.SubjectType(req.GetMemberType()), ID: domain.SubjectID(req.GetMemberId())}
	var operationsBefore int
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.operations`).Scan(&operationsBefore))
	op, err := w.groups.AddMember(asUser(w.ctx, w.usrD), req)
	// Configured policy принимает Operation, затем решает полный эффект и
	// принадлежность аккаунту в настоящем worker. Sync-ошибка — другая стадия.
	require.NoError(w.t, err)
	require.NotNil(w.t, op)
	done := awaitOp(w.t, w.ctx, w.ops, op.GetId())
	if want == codes.OK {
		require.Nil(w.t, done.Error)
		var n int
		require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.group_members WHERE group_id=$1 AND member_type=$2 AND member_id=$3`, req.GetGroupId(), member.Type, member.ID).Scan(&n))
		require.Equal(w.t, 1, n)
		w.native(string(member.Type)+":"+string(member.ID), "member", "group", req.GetGroupId(), relverdict.Allow)
	} else {
		require.NotNil(w.t, done.Error)
		require.Equal(w.t, int32(want), done.Error.Code)
		require.Equal(w.t, message, done.Error.Message)
		require.Equal(w.t, before, w.business(), "worker отказ не меняет бизнес/projection/audit/FGA")
		w.memberAbsent(domain.GroupID(req.GetGroupId()), member)
	}
	var operationsAfter int
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.operations`).Scan(&operationsAfter))
	require.Equal(w.t, operationsBefore+1, operationsAfter)
	require.True(w.t, proto.Equal(fixed, req))
}

// FB21: первые 256 выдач имеют только get, последняя добавляет list. Порядок
// подтверждён настоящим reader с тем же PageSize, а не временем вставки.
func TestFullBind_FB21_GroupAdditionChecksTheLastBindingPage(t *testing.T) {
	w := newFBRemainingWorld(t)
	g := w.group("fb21-pages")
	w.groupMethod(g)
	w.createCapability(userSubject(w.usrD), "project", string(w.prjA))
	get := w.role("fb21_source_get", fullBindBoxRule("get"))
	list := w.role("fb21_source_list", fullBindBoxRule("list"))
	w.grant(fbStructuredRequest(userSubject(w.usrD), get, "project", string(w.prjA)))
	// Все роли по-прежнему создаются публичным API с ожиданием настоящего
	// worker и object callback. До выдач достаточно один раз материализовать
	// прежнего owner после полного набора ролей, а не повторять полный проход
	// после каждой роли. Права исследуемого actor от этого не меняются.
	started := time.Now()
	pageRoles := make([]domain.RoleID, 0, 257)
	for n := 0; n < 257; n++ {
		verbs := []string{"get"}
		if n == 256 {
			verbs = append(verbs, "list")
		}
		op, err := w.roles.Create(asUser(w.ctx, w.usrA), &iamv1.CreateRoleRequest{
			Name: fmt.Sprintf("fb21_page_role_%03d", n), Rules: []*iamv1.Rule{fullBindBoxRule(verbs...)},
			DefinitionTier: &iamv1.DefinitionTier{TierType: "iam.account", TierId: string(w.accA)},
		})
		require.NoError(t, err)
		require.NotNil(t, op)
		require.Nil(t, awaitOp(t, w.ctx, w.ops, op.GetId()).Error)
		var md iamv1.CreateRoleMetadata
		require.NoError(t, op.GetMetadata().UnmarshalTo(&md))
		require.NotEmpty(t, md.GetRoleId())
		require.NoError(t, w.callbacks.awaitSetup(w.ctx, "iam.role", md.GetRoleId()))
		pageRoles = append(pageRoles, domain.RoleID(md.GetRoleId()))
		if (n+1)%64 == 0 || n == 256 {
			t.Logf("FB21 подготовлено ролей: %d/257, прошло %s", n+1, time.Since(started))
		}
	}
	require.NoError(t, w.rec.ReconcileBinding(w.ctx, w.ownerBinding))
	var last domain.AccessBindingID
	for n, role := range pageRoles {
		req := fbStructuredRequest(&iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_GROUP, Id: string(g)}, role, "project", string(w.prjA))
		id := w.createDone(asUser(w.ctx, w.usrA), req, "FB21: настоящая выдача группе")
		require.NoError(t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", id))
		require.NoError(t, w.rec.ReconcileBinding(w.ctx, domain.AccessBindingID(id)))
		last = domain.AccessBindingID(id)
		if (n+1)%64 == 0 || n == 256 {
			t.Logf("FB21 подготовлено выдач: %d/257, прошло %s", n+1, time.Since(started))
		}
	}
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(t, err)
	page, token, err := rd.AccessBindings().ListBySubject(w.ctx, domain.SubjectTypeGroup, domain.SubjectID(g), repoab.PageFilter{PageSize: 256})
	require.NoError(t, err)
	require.Len(t, page, 256)
	require.NotEmpty(t, token)
	for _, binding := range page {
		require.NotEqual(t, last, binding.ID, "непокрытая выдача должна находиться за первой страницей")
	}
	tail, next, err := rd.AccessBindings().ListBySubject(w.ctx, domain.SubjectTypeGroup, domain.SubjectID(g), repoab.PageFilter{PageSize: 256, PageToken: token})
	require.NoError(t, err)
	require.Len(t, tail, 1)
	require.Equal(t, last, tail[0].ID)
	require.Empty(t, next)
	require.NoError(t, rd.Rollback(w.ctx))
	actor, recipient := "user:"+string(w.usrD), "user:"+string(w.usrE)
	w.noScopeAdmin(actor)
	w.capability(actor, "", "project", string(w.prjA), relverdict.Allow)
	w.native(actor, "v_get", atcBoxType, atcB1, relverdict.Allow)
	w.native(actor, "v_list", atcBoxType, atcB1, relverdict.Deny)
	w.native(recipient, "v_get", atcBoxType, atcB1, relverdict.Deny)
	w.native(recipient, "v_list", atcBoxType, atcB1, relverdict.Deny)
	req := &iamv1.AddGroupMemberRequest{GroupId: string(g), MemberType: "user", MemberId: string(w.usrE)}
	w.addMember(req, codes.PermissionDenied, "Grant authority denied")
	w.native(recipient, "v_get", atcBoxType, atcB1, relverdict.Deny)
	w.grant(fbStructuredRequest(userSubject(w.usrD), list, "project", string(w.prjA)))
	w.native(actor, "v_list", atcBoxType, atcB1, relverdict.Allow)
	w.noScopeAdmin(actor)
	w.addMember(req, codes.OK, "")
	w.native(recipient, "v_get", atcBoxType, atcB1, relverdict.Allow)
	w.native(recipient, "v_list", atcBoxType, atcB1, relverdict.Allow)
	var bindings int
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT count(*) FROM kaname.access_binding_subjects WHERE subject_type='group' AND subject_id=$1`, g).Scan(&bindings))
	require.Equal(t, 257, bindings, "AddMember не переписывает набор выдач группы")
}

// Наблюдается только исходный entry error, до shared.MapRepoErr. Никакие
// DSN, конфигурация подключения или полная Error()-строка не печатаются.
type fb22FactoryObserver struct {
	t        *testing.T
	delegate kanamerepo.GroupAdditionAuthorityWriterFactory
}

func (o *fb22FactoryObserver) GroupAdditionAuthorityWriter(ctx context.Context, m domain.GroupMember, actor domain.Subject) (kanamerepo.SemanticAuthorityWriter, error) {
	w, err := o.delegate.GroupAdditionAuthorityWriter(ctx, m, actor)
	o.t.Logf("FB22 factory stage: member_type=%s raw_error_type=%T writer_nil=%t", m.MemberType, err, w == nil)
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		o.t.Logf("FB22 factory PostgreSQL: code=%q message=%q constraint=%q", pgErr.Code, pgErr.Message, pgErr.ConstraintName)
	} else if err != nil {
		for _, known := range []struct {
			name  string
			value error
		}{
			{"classification_changed", kanamerepo.ErrAuthorityClassificationChanged},
			{"invalid_fence_plan", kanamerepo.ErrInvalidAuthorityFencePlan},
			{"canonical_source_invalid", kanamerepo.ErrCanonicalSourceInvalid},
			{"source_unconfirmed", kanamerepo.ErrSourceUnconfirmed},
			{"source_read_limit", kanamerepo.ErrSourceReadLimit},
			{"permission_denied", iamerr.ErrPermissionDenied},
			{"reference_missing", iamerr.ErrReferenceMissing},
			{"unavailable", iamerr.ErrUnavailable},
			{"aborted", iamerr.ErrAborted},
			{"internal", iamerr.ErrInternal},
			{"canceled", context.Canceled},
			{"deadline", context.DeadlineExceeded},
		} {
			if errors.Is(err, known.value) {
				o.t.Logf("FB22 factory sentinel: %s", known.name)
			}
		}
	}
	return w, err
}

func TestFullBind_FB22_ForeignAndMissingMemberHaveTheSameReferenceRefusal(t *testing.T) {
	for _, branch := range []string{"human_active_membership", "direct_service_account"} {
		t.Run(branch, func(t *testing.T) {
			w := newFBRemainingWorld(t, func(a *atcWorld) {
				// Обе identity-ветви исходного мира готовы до Prepare/activation.
				// Владение аккаунтом не подменяет ACTIVE membership человека.
				gdSeedMembership(t, a.ctx, a.pool, a.usrC, a.accB, "ACTIVE")
			})
			// Наблюдатель не меняет factory/writer/error и не выдаёт диагностику за
			// прохождение контракта. Тот же admitted bundle загружается до When.
			composed, report, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{w.manifest(false)})
			require.NoError(t, err)
			bundle, err := w.repo.LoadAuthorityBundle(w.ctx, composed, report.KeyTerms...)
			require.NoError(t, err)
			writers, err := kanamepg.NewGrantPolicyWriters(w.ctx, w.repo, bundle)
			require.NoError(t, err)
			w.groups.WithGroupAdditionAuthorityWriter(&fb22FactoryObserver{t: t, delegate: writers})
			g := w.group("fb22-reference")
			w.groupMethod(g)
			w.createCapability(userSubject(w.usrD), "project", string(w.prjA))
			role := w.role("fb22_get", fullBindBoxRule("get"))
			w.grant(fbStructuredRequest(userSubject(w.usrD), role, "project", string(w.prjA)))
			groupRequest := fbStructuredRequest(&iamv1.Subject{Type: iamv1.SubjectType_SUBJECT_TYPE_GROUP, Id: string(g)}, role, "project", string(w.prjA))
			id := w.createDone(asUser(w.ctx, w.usrA), groupRequest, "FB22: настоящая выдача группе")
			require.NoError(t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", id))
			require.NoError(t, w.rec.ReconcileBinding(w.ctx, domain.AccessBindingID(id)))
			memberType := domain.SubjectTypeUser
			local, foreign := string(w.usrE), string(w.usrC)
			missing := ids.NewID(domain.PrefixUser)
			premise := `SELECT
 EXISTS(SELECT 1 FROM kaname.users WHERE id=$1),
 EXISTS(SELECT 1 FROM kaname.memberships WHERE user_id=$1 AND account_id=$2 AND state='ACTIVE'),
 EXISTS(SELECT 1 FROM kaname.memberships WHERE user_id=$1 AND account_id=$3 AND state='ACTIVE'),
 EXISTS(SELECT 1 FROM kaname.memberships WHERE user_id=$4 AND account_id=$2 AND state='ACTIVE'),
 EXISTS(SELECT 1 FROM kaname.users WHERE id=$5)`
			if branch == "direct_service_account" {
				memberType = domain.SubjectTypeServiceAccount
				local, foreign = w.svaA, w.svaB
				missing = ids.NewID(domain.PrefixServiceAccount)
				premise = `SELECT
 EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$1),
 EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$1 AND account_id=$2),
 EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$1 AND account_id=$3),
 EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$4 AND account_id=$2),
 EXISTS(SELECT 1 FROM kaname.service_accounts WHERE id=$5)`
			}
			var foreignExists, foreignInA, foreignInB, localInA, missingExists bool
			require.NoError(t, w.pool.QueryRow(w.ctx, premise, foreign, w.accA, w.accB, local, missing).
				Scan(&foreignExists, &foreignInA, &foreignInB, &localInA, &missingExists))
			require.True(t, foreignExists)
			require.False(t, foreignInA)
			require.True(t, foreignInB)
			require.True(t, localInA)
			require.False(t, missingExists)
			actor := "user:" + string(w.usrD)
			w.noScopeAdmin(actor)
			w.capability(actor, "", "project", string(w.prjA), relverdict.Allow)
			w.native(actor, "v_get", atcBoxType, atcB1, relverdict.Allow)
			for _, member := range []string{local, foreign} {
				w.memberAbsent(g, domain.Subject{Type: memberType, ID: domain.SubjectID(member)})
				w.native(string(memberType)+":"+member, "v_get", atcBoxType, atcB1, relverdict.Deny)
			}
			for _, member := range []string{foreign, missing} {
				req := &iamv1.AddGroupMemberRequest{GroupId: string(g), MemberType: string(memberType), MemberId: member}
				w.addMember(req, codes.FailedPrecondition, "referenced resource does not exist; create it or correct the reference before retrying")
			}
			w.addMember(&iamv1.AddGroupMemberRequest{GroupId: string(g), MemberType: string(memberType), MemberId: local}, codes.OK, "")
			w.native(string(memberType)+":"+local, "v_get", atcBoxType, atcB1, relverdict.Allow)
			// Отказ не раскрывает существование чужого субъекта и не меняет его.
			w.memberAbsent(g, domain.Subject{Type: memberType, ID: domain.SubjectID(foreign)})
			w.native(string(memberType)+":"+foreign, "v_get", atcBoxType, atcB1, relverdict.Deny)
		})
	}
}

// FB32a и FB32b — разные shape-сценарии. Actor умеет обычный Role.Create и
// передаёт точное bind-полномочие; ни owner, ни admin здесь не исследуются.
func TestFullBind_FB32_BindRuleNeedsFiniteRoleIDsNotLabels(t *testing.T) {
	w := newFBRemainingWorld(t)
	target := w.role("fb32_named_role", fullBindBoxRule("get"))
	finite := &iamv1.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{string(target)}}
	source := w.role("fb32_bind_source", finite)
	w.grant(fbStructuredRequest(userSubject(w.usrD), source, "account", string(w.accA)))
	method := w.role("fb32_method", &iamv1.Rule{Module: "iam", Resources: []string{"account"}, Verbs: []string{"update"}})
	w.grant(fbStructuredRequest(userSubject(w.usrD), method, "account", string(w.accA)))
	actor := "user:" + string(w.usrD)
	w.native(actor, "editor", "account", string(w.accA), relverdict.Allow)
	w.noScopeAdmin(actor)
	w.capability(actor, target, "account", string(w.accA), relverdict.Allow)
	// Bind не даёт чтение referenced custom role: сохраняем тот же Get privacy
	// gate и получаем узкое обычное право через настоящие Role/Binding APIs.
	reads := roleapp.NewHandler(nil, nil, nil,
		roleapp.NewGetRoleUseCase(w.repo, catalog.Fixed{F: w.facts}).WithRelationStore(w.door), nil)
	getRequest := &iamv1.GetRoleRequest{RoleId: string(target)}
	hidden, readErr := reads.Get(asUser(w.ctx, w.usrD), getRequest)
	require.Nil(t, hidden)
	require.Equal(t, codes.NotFound, status.Code(readErr))
	readRole := w.role("fb32_reference_read", &iamv1.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"list"}, ResourceNames: []string{string(target)}})
	w.grant(fbStructuredRequest(userSubject(w.usrD), readRole, "account", string(w.accA)))
	w.native(actor, "v_list", "iam_role", string(target), relverdict.Allow)
	w.native(actor, "admin", "iam_role", string(target), relverdict.Deny)
	w.noScopeAdmin(actor)
	visible, readErr := reads.Get(asUser(w.ctx, w.usrD), getRequest)
	require.NoError(t, readErr)
	require.Equal(t, string(target), visible.GetId())
	valid := &iamv1.CreateRoleRequest{Name: "fb32_finite", DefinitionTier: &iamv1.DefinitionTier{TierType: "iam.account", TierId: string(w.accA)}, Rules: []*iamv1.Rule{finite}}
	fixed := proto.Clone(valid)
	op, err := w.roles.Create(asUser(w.ctx, w.usrD), valid)
	require.NoError(t, err)
	require.NotNil(t, op)
	require.Nil(t, awaitOp(t, w.ctx, w.ops, op.GetId()).Error)
	var md iamv1.CreateRoleMetadata
	require.NoError(t, op.GetMetadata().UnmarshalTo(&md))
	require.NotEmpty(t, md.GetRoleId())
	require.NoError(t, w.callbacks.awaitSetup(w.ctx, "iam.role", md.GetRoleId()))
	rw := &fbRoleMutationWorld{fullBindWorld: w.fullBindWorld, callbacks: w.callbacks}
	rw.assertRules(domain.RoleID(md.GetRoleId()), valid.GetRules())
	require.True(t, proto.Equal(fixed, valid))
	// Shape-отказ происходит до Operation; финальные строки первого сценария
	// остаются неизменными. Селектор не выдаётся за альтернативное имя роли.
	invalid := &iamv1.CreateRoleRequest{Name: "fb32_labels", DefinitionTier: valid.DefinitionTier,
		Rules: []*iamv1.Rule{{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, MatchLabels: map[string]string{"env": "prod"}}}}
	before := w.artifacts()
	fixedInvalid := proto.Clone(invalid)
	op, err = w.roles.Create(asUser(w.ctx, w.usrD), invalid)
	require.Nil(t, op)
	require.Equal(t, codes.InvalidArgument, status.Code(err))
	require.Equal(t, before, w.artifacts())
	require.True(t, proto.Equal(fixedInvalid, invalid))
	w.noScopeAdmin(actor)
	w.capability(actor, target, "account", string(w.accA), relverdict.Allow)
}

// FB31 запускается отдельно с бюджетом 7 минут: публичный Create источника
// требует минимум 5 минут. Срок не переписывается SQL и часы не подделываются.
func TestFullBind_FB31_SourceExpiryAfterHeldWriterClockDoesNotShortenGrant(t *testing.T) {
	w := newFBRemainingWorld(t)
	// Этот helper идёт через newSCWorld с Background, не через двухминутный
	// children world. Ужесточаем общий бюджет, не продлевая прежний deadline.
	if deadline, ok := w.ctx.Deadline(); ok {
		require.Greater(t, time.Until(deadline), accessbindingapp.MinExpiresIn+time.Minute)
	}
	lifetime, stop := context.WithTimeout(w.ctx, 7*time.Minute)
	t.Cleanup(stop)
	w.ctx = lifetime
	role := w.role("fb31_proposed", fullBindBoxRule("get"))
	source := w.role("fb31_source", fullBindBoxRule("get"))
	w.createCapability(userSubject(w.usrD), "project", string(w.prjA))
	var now time.Time
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT clock_timestamp()`).Scan(&now))
	expires := now.Add(accessbindingapp.MinExpiresIn + 10*time.Second)
	sourceRequest := fbStructuredRequest(userSubject(w.usrD), source, "project", string(w.prjA))
	sourceRequest.ExpiresAt = timestamppb.New(expires)
	sourceID := w.grant(sourceRequest)
	var savedExpires time.Time
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT expires_at FROM kaname.access_bindings WHERE id=$1`, sourceID).Scan(&savedExpires))
	require.WithinDuration(t, expires, savedExpires, time.Microsecond)
	actor, recipient := "user:"+string(w.usrD), "user:"+string(w.usrE)
	w.noScopeAdmin(actor)
	w.capability(actor, "", "project", string(w.prjA), relverdict.Allow)
	w.capability(actor, role, "project", string(w.prjA), relverdict.Deny)
	w.native(actor, "v_get", atcBoxType, atcB1, relverdict.Allow)
	req := w.request(w.usrE, role, allInScopeTarget())
	require.Nil(t, req.GetExpiresAt())
	created := w.allow(asUser(w.ctx, w.usrD), req)
	var perpetual bool
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT expires_at IS NULL FROM kaname.access_bindings WHERE id=$1`, created).Scan(&perpetual))
	require.True(t, perpetual, "срок источника не наследуется обычной выдачей")
	w.native(recipient, "v_get", atcBoxType, atcB1, relverdict.Allow)
	fixed, before := proto.Clone(req), w.artifacts()
	// Публичный TTL остаётся настоящим. Начинаем ограниченное ожидание writer
	// в конце срока источника: удержание всех пяти минут превысило бы его
	// штатный бюджет и проверяло бы timeout вместо свежести после ожидания.
	waitTick := time.NewTicker(100 * time.Millisecond)
	defer waitTick.Stop()
	for {
		var live, tail bool
		require.NoError(t, w.observer.QueryRow(w.ctx, `SELECT clock_timestamp()<$1::timestamptz,clock_timestamp()>=$1::timestamptz-interval '10 seconds'`, savedExpires).Scan(&live, &tail))
		require.True(t, live, "FB31: источник должен быть жив перед запуском writer")
		if tail {
			break
		}
		select {
		case <-waitTick.C:
		case <-w.ctx.Done():
			t.Fatal("FB31: общий контекст истёк до конца действительного TTL", w.ctx.Err())
		}
	}
	w.native(actor, "v_get", atcBoxType, atcB1, relverdict.Allow)
	blocker, err := w.observer.BeginTx(w.ctx, pgx.TxOptions{})
	require.NoError(t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
		defer cancel()
		_ = blocker.Rollback(ctx)
	}()
	var blockerPID int
	require.NoError(t, blocker.QueryRow(w.ctx, `SELECT pg_backend_pid()`).Scan(&blockerPID))
	_, err = blocker.Exec(w.ctx, `LOCK TABLE kaname.authority_policy_epoch IN EXCLUSIVE MODE`)
	require.NoError(t, err)
	ctx, cancel := context.WithTimeout(w.ctx, 7*time.Minute)
	defer cancel()
	type outcome struct {
		hasOperation bool
		operationID  string
		err          error
	}
	done := make(chan outcome, 1)
	var out outcome
	returned := false
	defer func() {
		cancel()
		cleanup, stop := context.WithTimeout(context.WithoutCancel(w.ctx), 12*time.Second)
		defer stop()
		_ = blocker.Rollback(cleanup)
		if !returned {
			select {
			case out = <-done:
			case <-cleanup.Done():
				t.Errorf("FB31: Create не завершился после отмены и освобождения барьера: %v", cleanup.Err())
				return
			}
		}
		// Даже ошибочно принятая операция должна завершить свой worker прежде,
		// чем cleanup закроет pool. Она всё равно проваливает основной оракул.
		if out.operationID == "" {
			return
		}
		ticker := time.NewTicker(20 * time.Millisecond)
		defer ticker.Stop()
		for {
			op, err := w.ops.Get(cleanup, out.operationID)
			if err != nil {
				t.Errorf("FB31: чтение неожиданной Operation при cleanup: %v", err)
				return
			}
			if op.Done {
				return
			}
			select {
			case <-ticker.C:
			case <-cleanup.Done():
				t.Errorf("FB31: неожиданная Operation не завершилась при cleanup: %v", cleanup.Err())
				return
			}
		}
	}()
	go func() {
		op, err := w.ab.Create(asUser(ctx, w.usrD), req)
		done <- outcome{hasOperation: op != nil, operationID: op.GetId(), err: err}
	}()
	var observedBeforeExpiry bool
	require.Eventually(t, func() bool {
		var blocked, live bool
		err := w.observer.QueryRow(w.ctx, `SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE datname=current_database() AND usename=$1 AND wait_event_type='Lock' AND $2=ANY(pg_blocking_pids(pid))),clock_timestamp()<$3::timestamptz`, w.pool.Config().ConnConfig.User, blockerPID, savedExpires).Scan(&blocked, &live)
		observedBeforeExpiry = err == nil && blocked && live
		return observedBeforeExpiry
	}, 20*time.Second, 20*time.Millisecond, "настоящий writer должен ждать удерживаемый epoch до истечения источника")
	require.True(t, observedBeforeExpiry)
	// Читаем настоящие часы через сам удерживающий lock transaction. Он не
	// простаивает более idle-in-transaction timeout; настройки БД не меняются.
	// Ранний ответ writer до снятия барьера — отказ пробы, а не скрытая зелень.
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		var expired bool
		require.NoError(t, blocker.QueryRow(w.ctx, `SELECT clock_timestamp()>$1::timestamptz`, savedExpires).Scan(&expired))
		if expired {
			break
		}
		select {
		case out = <-done:
			returned = true
			t.Fatalf("FB31: writer завершился до истечения источника при удержанном барьере: operation=%t code=%s message=%q", out.hasOperation, status.Code(out.err), status.Convert(out.err).Message())
		case <-tick.C:
		case <-w.ctx.Done():
			t.Fatal("FB31: общий контекст истёк до настоящего источника", w.ctx.Err())
		}
	}
	select {
	case out = <-done:
		returned = true
		t.Fatalf("FB31: writer завершился до снятия настоящего барьера: operation=%t code=%s", out.hasOperation, status.Code(out.err))
	default:
	}
	require.NoError(t, blocker.Rollback(w.ctx))
	require.NoError(t, w.ctx.Err(), "срок настоящего источника истёк при живом test context")
	select {
	case out = <-done:
		returned = true
		require.False(t, out.hasOperation, "повторный Create запрещён до Operation")
		require.Equal(t, codes.PermissionDenied, status.Code(out.err))
		require.Equal(t, "permission denied", status.Convert(out.err).Message())
	case <-ctx.Done():
		t.Fatal("writer не завершился после освобождения действительного барьера", ctx.Err())
	}
	require.True(t, proto.Equal(fixed, req))
	require.Equal(t, before, w.artifacts(), "истечение источника не делает частичную запись и не отзывает прежнюю ordinary выдачу")
	w.capability(actor, "", "project", string(w.prjA), relverdict.Allow)
	w.noScopeAdmin(actor)
	w.native(actor, "v_get", atcBoxType, atcB1, relverdict.Deny)
	w.native(recipient, "v_get", atcBoxType, atcB1, relverdict.Allow)
	w.materialized(created, recipient, "v_get", atcBoxType, atcB1, true)
}

func TestFullBind_FB34_AllDirectSARecipientsAreAtomicAndCreatorSpecific(t *testing.T) {
	w := newFBStructuredWorld(t, true)
	// own1 — третья действительная SA в A, созданная API actor V; её ID также
	// пригоден как Z. Это не подстановка пользователя или group userset.
	v, other, z := w.s1, w.s2, w.own1
	require.NotEqual(t, v, z)
	require.NotEqual(t, other, z)
	w.revokeSource(string(w.s1Creator))
	original := &iamv1.CreateAccessBindingRequest{Subjects: []*iamv1.Subject{svaSubject(z), svaSubject(v)}, RoleId: string(w.creator), ScopeType: "iam.account", ScopeId: string(w.accA), Target: allInScopeTarget()}
	originalID := domain.AccessBindingID(w.createDone(asUser(w.ctx, w.usrA), original, "FB34: каноническая исходная C→[Z,V]"))
	require.NoError(t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", string(originalID)))
	require.NoError(t, w.rec.ReconcileBinding(w.ctx, originalID))
	w.createCapability(svaSubject(v), "account", string(w.accA))
	readSubjects := func(id domain.AccessBindingID, first string) []domain.Subject {
		rd, err := w.repo.Reader(w.ctx)
		require.NoError(t, err)
		defer func() { _ = rd.Rollback(w.ctx) }()
		subjects, err := rd.AccessBindings().ListSubjects(w.ctx, id)
		require.NoError(t, err)
		b, err := rd.AccessBindings().Get(w.ctx, id)
		require.NoError(t, err)
		require.Equal(t, w.creator, b.RoleID)
		require.Equal(t, domain.AccessBindingStatusActive, b.Status)
		require.Nil(t, b.RevokedAt)
		require.Equal(t, string(w.accA), b.ResourceID)
		require.Equal(t, domain.ResourceType("account"), b.ResourceType)
		require.True(t, b.Target.AllInScope)
		require.Equal(t, domain.SubjectTypeServiceAccount, b.SubjectType)
		require.Equal(t, domain.SubjectID(first), b.SubjectID, "legacy первый subject сохраняет разные active-grant keys")
		return subjects
	}
	oldSubjects := []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(z)}, {Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(v)}}
	require.ElementsMatch(t, oldSubjects, readSubjects(originalID, z))
	actor := "service_account:" + v
	w.noScopeAdmin(actor)
	w.capability(actor, "", "account", string(w.accA), relverdict.Allow)
	w.capability(actor, w.creator, "account", string(w.accA), relverdict.Deny)
	w.native(actor, sacCreatorRelation, "account", string(w.accA), relverdict.Allow)
	w.native(actor, "v_update", sacSAModelType, w.own1, relverdict.Allow)
	w.native(actor, "v_update", sacSAModelType, w.own2, relverdict.Deny)
	w.native("service_account:"+other, "v_update", sacSAModelType, w.own2, relverdict.Deny)
	req := &iamv1.CreateAccessBindingRequest{Subjects: []*iamv1.Subject{svaSubject(v), svaSubject(other)}, RoleId: string(w.creator), ScopeType: "iam.account", ScopeId: string(w.accA), Target: allInScopeTarget()}
	require.Empty(t, req.GetSubjectType())
	require.Empty(t, req.GetSubjectId())
	fixed := proto.Clone(req)
	w.deny(asSA(w.ctx, v), req)
	require.ElementsMatch(t, oldSubjects, readSubjects(originalID, z))
	w.native(actor, "v_update", sacSAModelType, w.own1, relverdict.Allow)
	w.native("service_account:"+other, "v_update", sacSAModelType, w.own2, relverdict.Deny)
	w.grant(fbStructuredRequest(svaSubject(v), w.saAdmin, "account", string(w.accA)))
	w.noScopeAdmin(actor)
	w.native(actor, "v_update", sacSAModelType, w.own2, relverdict.Allow)
	op, err := w.ab.Create(asSA(w.ctx, v), req)
	require.NoError(t, err)
	require.NotNil(t, op)
	require.Nil(t, awaitOp(t, w.ctx, w.ops, op.GetId()).Error)
	var md iamv1.CreateAccessBindingMetadata
	require.NoError(t, op.GetMetadata().UnmarshalTo(&md))
	require.NotEmpty(t, md.GetAccessBindingId())
	created := domain.AccessBindingID(md.GetAccessBindingId())
	require.NotEqual(t, originalID, created)
	require.NoError(t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", string(created)))
	require.ElementsMatch(t, []domain.Subject{{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(v)}, {Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(other)}}, readSubjects(created, v))
	require.ElementsMatch(t, oldSubjects, readSubjects(originalID, z))
	require.True(t, proto.Equal(fixed, req))
	for _, own := range []struct{ subject, yes, no string }{{v, w.own1, w.own2}, {other, w.own2, w.own1}} {
		w.materialized(created, "service_account:"+own.subject, "v_update", sacSAModelType, own.yes, true)
		w.materialized(created, "service_account:"+own.subject, "v_update", sacSAModelType, own.no, false)
	}
	w.native("service_account:"+other, sacCreatorRelation, "account", string(w.accA), relverdict.Allow)
	w.native("service_account:"+other, "v_update", sacSAModelType, w.own2, relverdict.Allow)
	w.native("service_account:"+other, "v_update", sacSAModelType, w.own1, relverdict.Deny)
	w.noScopeAdmin("service_account:" + other)
}

// Своя композиция нужна именно FB30: custom inspect является admitted alias
// v_get, а неизвестность относится к импликации parent constraint, не к native
// Unknown и не к ошибке backend. Canonical FB13 мир остаётся неизменным.
type fb30CustomWorld struct {
	*fb13ChildrenWorld
	bundle *granteffect.Bundle
}

const fb30TagRoles = `
  - id: probemod.fb30_tag
    description: 'Прямое чтение ярлыков для сравнения с children source.'
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: probemod
        resources: [tags]
        classes: [get, list]
`

func newFB30CustomWorld(t *testing.T) *fb30CustomWorld {
	t.Helper()
	if testing.Short() {
		t.Skip("нужен PostgreSQL")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	t.Cleanup(cancel)
	cfg, err := pgxpool.ParseConfig(setupTestDB(t))
	require.NoError(t, err)
	cfg.MaxConns = 4
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	require.NoError(t, err)
	t.Cleanup(pool.Close)
	canonical, err := os.ReadFile("../../../../manifest/testdata/probemod.children-fixture.yaml")
	require.NoError(t, err)
	// Отдельная fixture FB30 расширяет только tags custom relation и роли.
	// Исходный FB13 и process Shared не меняются; parent/public-read оси сохранены.
	tagStart := strings.Index(string(canonical), "  - name: tags\n")
	require.GreaterOrEqual(t, tagStart, 0)
	tagPrefix, tagTail := string(canonical[:tagStart]), string(canonical[tagStart:])
	require.Equal(t, 1, strings.Count(tagTail, "    producer: derived\n"))
	tagTail = strings.Replace(tagTail, "    producer: derived\n", "    producer: derived\n    relations:\n      - {name: inspect, definition: v_get}\n", 1)
	doc := []byte(tagPrefix + tagTail + fb13SourceRoles + fb30TagRoles)
	delivered, err := manifest.Load(doc)
	require.NoError(t, err)
	composed, report, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{delivered})
	require.NoError(t, err)
	admitted, err := authzmodel.Admit(composed, report.KeyTerms...)
	require.NoError(t, err)
	require.True(t, admitted.Admitted(), admitted.Census())
	plans, err := authzmodel.New(composed)
	require.NoError(t, err)
	for _, typ := range []string{atcBoxType, "probemod_item", "probemod_tag"} {
		for _, rel := range []string{"v_get", "v_list"} {
			_, err = plans.Plan(typ, rel)
			require.NoError(t, err, "полный план исходного canonical world: %s.%s", typ, rel)
		}
	}
	// Собираем отдельный мир сразу на этих plans. newSCWorld/newATCWorld здесь
	// не вызываются: ни чужих mirror seeds, ни process model swap не требуется.
	repo := kanamepg.New(pool, nil)
	door := authzcascade.WrapAdmitted(relverdict.NewPreparedAsker(pool, plans), personmarks.New(pool))
	sc := &scWorld{t: t, ctx: ctx, pool: pool, repo: repo, ops: operations.NewRepo(pool, "kaname"), door: door}
	a := &atcWorld{pcrWorld: &pcrWorld{scWorld: sc}, doc: doc}
	sc.usrA = mustSeedUser(t, ctx, pool, "fb30-owner")
	sc.accA = seedAccountByOwner(t, ctx, pool, "fb30-account", sc.usrA)
	a.usrD = mustSeedUser(t, ctx, pool, "fb30-actor")
	a.usrE = mustSeedUser(t, ctx, pool, "fb30-recipient")
	verifyAddresses(t, ctx, pool)
	gdSeedMembership(t, ctx, pool, a.usrD, sc.accA, "ACTIVE")
	gdSeedMembership(t, ctx, pool, a.usrE, sc.accA, "ACTIVE")
	a.applyDelivered("FB30: literal children fixture и два источника", delivered)
	callbacks := &fb11SetupCallbacks{}
	observe := func(rec *reconcile.Reconciler) accessbindingapp.SelectorReconciler {
		return &fb11SetupReconciler{SelectorReconciler: rec, callbacks: callbacks}
	}
	bootstrap := accessbindingapp.NewCreateAccessBindingUseCase(repo, sc.ops, catalog.Fixed{F: a.facts}).WithRelationStore(door, slog.Default()).WithReconciler(observe(sc.rec))
	sc.ab = accessbindingapp.NewHandler(bootstrap, nil, nil, nil, nil, nil, nil)
	owner := domain.AccessBindingID(sc.createDone(asUser(ctx, sc.usrA), fbStructuredRequest(userSubject(sc.usrA), domain.RoleID(domain.OwnerRoleID), "account", string(sc.accA)), "FB30: actual owner auto-binding"))
	require.NoError(t, callbacks.awaitSetup(ctx, "iam.accessBinding", string(owner)))
	// Project.Create со-коммитит структурные pointers: SQL-посева project→account нет.
	projects := projectapp.NewHandler(projectapp.NewCreateProjectUseCase(repo, sc.ops).WithRelationStore(door, slog.Default()).WithObjectReconciler(&fbStructuredObjects{Reconciler: sc.rec, callbacks: callbacks}), nil, nil, nil, nil)
	op, err := projects.Create(asUser(ctx, sc.usrA), &iamv1.CreateProjectRequest{AccountId: string(sc.accA), Name: "fb30-project"})
	require.NoError(t, err)
	require.NotNil(t, op)
	require.Nil(t, awaitOp(t, ctx, sc.ops, op.GetId()).Error)
	var projectMD iamv1.CreateProjectMetadata
	require.NoError(t, op.GetMetadata().UnmarshalTo(&projectMD))
	sc.prjA = domain.ProjectID(projectMD.GetProjectId())
	require.NotEmpty(t, sc.prjA)
	require.NoError(t, callbacks.awaitSetup(ctx, "iam.project", string(sc.prjA)))
	sc.ownerSeeded = true
	w := &fb13ChildrenWorld{fbStructuredWorld: &fbStructuredWorld{fullBindWorld: &fullBindWorld{atcWorld: a, plans: plans, ownerBinding: owner}, callbacks: callbacks, observer: pool}}
	w.osetr = w.moduleRole("probemod.reader")
	w.partial = w.moduleRole("probemod.fb13_partial")
	w.tail = w.moduleRole("probemod.fb13_tail")
	require.NotEqual(t, w.osetr, w.partial)
	require.NotEqual(t, w.osetr, w.tail)
	require.NotEqual(t, w.partial, w.tail)
	source := catalog.Fixed{F: w.facts}
	authority := registrationwriterfixture.Authority{Module: "probemod"}
	// Gate изолирует только setup регистрации. Ни один Given grant им не выдаётся.
	w.reg = internaliam.NewRegisterResourceUseCase(kanamepg.NewFGAOutboxEmitter(), kanamepg.NewResourceMirrorEmitter(), kanamepg.NewRegistrationTxBeginner(pool), kanamepg.NewCatalogTypeReader(), kanamepg.NewPublicReadPublisher(), accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), source), kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader()).WithRegistrationAuthority(authority).WithReconcile(kanamepg.NewReconcileEventEmitter()).WithObjectReconciler(w.rec, slog.Default())
	w.registration = internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).WithResourceRegistrar(w.reg, authority)
	require.NoError(t, pool.QueryRow(ctx, `SELECT clock_timestamp()`).Scan(&w.version))
	for _, tree := range []struct{ box, item, tag string }{{atcB1, fbStructuredItem, fb13Tag}, {atcB2, fb13OtherItem, fb13OtherTag}} {
		w.register("project:"+string(w.prjA), "project", atcBoxType, "probemod.boxes", tree.box, []string{"project:" + string(w.prjA), "account:" + string(w.accA)})
		w.register(atcBoxType+":"+tree.box, "box", "probemod_item", "probemod.items", tree.item, []string{atcBoxType + ":" + tree.box, "project:" + string(w.prjA), "account:" + string(w.accA)})
		w.register("probemod_item:"+tree.item, "item", "probemod_tag", "probemod.tags", tree.tag, []string{"probemod_item:" + tree.item, atcBoxType + ":" + tree.box, "project:" + string(w.prjA), "account:" + string(w.accA)})
	}
	require.NoError(t, w.rec.ReconcileBinding(ctx, owner))
	// Те же реальные factories, что full-bind startup, но каждый consumer
	// получает local prepared plans либо bundle этой единственной композиции.
	halves, err := kanamepg.NewCatalogRepo(pool).ReadCatalogHalves(ctx)
	require.NoError(t, err)
	bundle, err := granteffect.NewBundle(ctx, composed, halves, granteffect.ProjectorVersion, report.KeyTerms...)
	require.NoError(t, err)
	require.NoError(t, repo.PrepareAuthorityBundle(ctx, bundle))
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	source = catalog.Fixed{F: facts}
	login := "fb30_runtime_" + strings.ReplaceAll(ids.NewID("rol"), "-", "_")
	quoted := pgx.Identifier{login}.Sanitize()
	password := ids.NewID("pwd")
	_, err = pool.Exec(ctx, "CREATE ROLE "+quoted+" LOGIN PASSWORD '"+strings.ReplaceAll(password, "'", "''")+"' NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS NOINHERIT")
	require.NoError(t, err)
	t.Cleanup(func() {
		c, stop := context.WithTimeout(context.Background(), 5*time.Second)
		defer stop()
		_, _ = pool.Exec(c, "DROP OWNED BY "+quoted)
		_, _ = pool.Exec(c, "DROP ROLE "+quoted)
	})
	_, err = pool.Exec(ctx, `SELECT kaname.authority_protocol_grant_runtime($1::regrole)`, login)
	require.NoError(t, err)
	runtimeConfig := pool.Config()
	runtimeConfig.ConnConfig.User, runtimeConfig.ConnConfig.Password = login, password
	runtimeConfig.AfterConnect = nil
	runtime, err := pgxpool.NewWithConfig(ctx, runtimeConfig)
	require.NoError(t, err)
	t.Cleanup(runtime.Close)
	var current, session string
	require.NoError(t, runtime.QueryRow(ctx, `SELECT current_user,session_user`).Scan(&current, &session))
	require.Equal(t, login, current)
	require.Equal(t, login, session)
	runtimeRepo := kanamepg.New(runtime, nil)
	require.NoError(t, runtimeRepo.ValidateAuthorityRuntime(ctx))
	handed, err := runtimeRepo.LoadAuthorityBundle(ctx, composed, report.KeyTerms...)
	require.NoError(t, err)
	require.Equal(t, bundle.Identity(), handed.Identity())
	writers, err := kanamepg.NewGrantPolicyWriters(ctx, runtimeRepo, handed)
	require.NoError(t, err)
	groups, err := kanamepg.NewGroupMembershipParticipant(ctx, runtimeRepo, handed)
	require.NoError(t, err)
	stages, err := groups.NewBindingStageParticipant(ctx, slog.Default())
	require.NoError(t, err)
	rec := reconcile.New(kanamepg.NewReconcileAdapter(runtime, source), slog.Default(), source)
	require.NoError(t, rec.WithStagedBindingReconciler(stages))
	resources, err := kanamepg.NewResourceObjectParticipant(ctx, runtimeRepo, handed)
	require.NoError(t, err)
	resourceBeginner, err := resources.RegistrationTxBeginner(runtime)
	require.NoError(t, err)
	objects, err := resources.NewObjectReconciler(slog.Default())
	require.NoError(t, err)
	require.NoError(t, rec.WithObjectReconciler(objects))
	runtimeDoor := authzcascade.WrapAdmitted(relverdict.NewPreparedAsker(runtime, plans), personmarks.New(runtime))
	runtimeOps := operations.NewRepo(runtime, "kaname")
	keys := kanamepg.NewRegisteredKeys(runtime)
	create := accessbindingapp.NewCreateAccessBindingUseCase(runtimeRepo, runtimeOps, source).WithRelationStore(runtimeDoor, slog.Default()).WithRegisteredKeys(keys).WithBindingDecisions(writers).WithReconciler(observe(rec))
	w.ab = accessbindingapp.NewHandler(create, nil, nil, nil, nil, nil, nil)
	w.roles = roleapp.NewHandler(roleapp.NewCreateRoleUseCase(runtimeRepo, runtimeOps, source).WithRelationStore(runtimeDoor, slog.Default()).WithRegisteredKeys(keys).WithGrantReferencePlans(plans).WithRoleAuthorityWriter(writers).WithObjectReconciler(&fbStructuredObjects{Reconciler: rec, callbacks: callbacks}), nil, nil, nil, nil)
	w.pool, w.repo, w.ops, w.door, w.rec = runtime, runtimeRepo, runtimeOps, runtimeDoor, rec
	w.facts, w.stages = facts, stages
	w.reg = internaliam.NewRegisterResourceUseCase(kanamepg.NewFGAOutboxEmitter(), kanamepg.NewResourceMirrorEmitter(), kanamepg.NewPoolTxBeginner(runtime), kanamepg.NewCatalogTypeReader(), kanamepg.NewPublicReadPublisher(), accessbindingapp.NewUnregisteredKeyWithdrawal(kanamepg.NewUnregisteredKeyStore(), source), kanamepg.NewRegistrationAudit(), kanamepg.NewRegistrationScopeReader()).WithRegistrationAuthority(authority).WithResourceTxBeginner(resourceBeginner).WithReconcile(kanamepg.NewReconcileEventEmitter()).WithObjectReconciler(rec, slog.Default())
	w.registration = internaliam.NewHandler(internaliam.NewLookupSubjectUseCase(nil), nil).WithResourceRegistrar(w.reg, authority)
	require.NoError(t, repo.ActivateAuthorityBundle(ctx, bundle))
	var phase, enforcement string
	require.NoError(t, pool.QueryRow(ctx, `SELECT a.phase,p.enforcement FROM kaname.authority_semantic_identity a CROSS JOIN kaname.authority_writer_protocol p`).Scan(&phase, &enforcement))
	require.Equal(t, "active", phase)
	require.Equal(t, "strict", enforcement)
	return &fb30CustomWorld{fb13ChildrenWorld: w, bundle: handed}
}

func (w *fb30CustomWorld) grantAt(req *iamv1.CreateAccessBindingRequest) domain.AccessBindingID {
	w.t.Helper()
	id := domain.AccessBindingID(w.createDone(asUser(w.ctx, w.usrA), req, "FB30: настоящий источник"))
	require.NoError(w.t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", string(id)))
	require.NoError(w.t, w.rec.ReconcileBinding(w.ctx, id))
	w.storedEffects(id, req)
	return id
}

// Эффект строится из действительной строки выдачи, её authored role и полного
// списка subjects на pinned bundle этой fixture. Он не заменяет writer check.
func (w *fb30CustomWorld) storedEffects(id domain.AccessBindingID, req *iamv1.CreateAccessBindingRequest) granteffect.Set {
	w.t.Helper()
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(w.t, err)
	defer func() {
		ctx, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
		defer cancel()
		_ = rd.Rollback(ctx)
	}()
	b, err := rd.AccessBindings().Get(w.ctx, id)
	require.NoError(w.t, err)
	r, err := rd.Roles().Get(w.ctx, b.RoleID)
	require.NoError(w.t, err)
	subjects, err := rd.AccessBindings().ListSubjects(w.ctx, id)
	require.NoError(w.t, err)
	require.Equal(w.t, req.GetRoleId(), string(b.RoleID))
	require.Equal(w.t, domain.AccessBindingStatusActive, b.Status)
	require.Nil(w.t, b.RevokedAt)
	require.Equal(w.t, string(w.prjA), b.ResourceID)
	require.Equal(w.t, domain.ResourceType("project"), b.ResourceType)
	require.Equal(w.t, []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(req.Subjects[0].GetId())}}, subjects)
	wantTarget := domain.AccessTarget{AllInScope: req.GetTarget().GetAllInScope() != nil}
	for _, ref := range req.GetTarget().GetResources().GetResources() {
		wantTarget.Resources = append(wantTarget.Resources, domain.ResourceRef{Type: ref.GetType(), ID: ref.GetId()})
	}
	require.Equal(w.t, wantTarget, b.Target)
	require.NoError(w.t, rd.Rollback(w.ctx))
	var version int
	require.NoError(w.t, w.pool.QueryRow(w.ctx, `SELECT grant_capability_version FROM kaname.access_bindings WHERE id=$1`, id).Scan(&version))
	require.Equal(w.t, 1, version)
	set := w.bundle.Compile(granteffect.Binding{SourceID: string(id), Role: r, Scope: domain.ScopeAnchor{Type: string(b.ResourceType), ID: b.ResourceID}, Target: b.Target, Recipient: subjects[0], Subjects: subjects, CapabilityVersion: version})
	require.True(w.t, set.Complete(), "это неизвестная импликация полных эффектов, не усечённый источник: %v", set.Obligations())
	return set
}

func TestFullBind_FB30_UnknownCustomImplicationNeedsCoverageOrKnownBind(t *testing.T) {
	for _, branch := range []string{"exact_source", "explicit_bind"} {
		t.Run(branch, func(t *testing.T) {
			w := newFB30CustomWorld(t)
			proposedRole := w.moduleRole("probemod.fb30_tag")
			proposedRequest := &iamv1.CreateAccessBindingRequest{Subjects: []*iamv1.Subject{userSubject(w.usrE)}, RoleId: string(proposedRole), ScopeType: "iam.project", ScopeId: string(w.prjA), Target: resourcesTarget(rr("probemod.tags", fb13Tag))}
			fixed := proto.Clone(proposedRequest)
			childrenRequest := w.fb13ChildrenWorld.request(w.usrD, w.osetr)
			childrenID := w.grantAt(childrenRequest)
			w.fbStructuredWorld.createCapability(userSubject(w.usrD), "project", string(w.prjA))
			actor := "user:" + string(w.usrD)
			w.noScopeAdmin(actor)
			w.capability(actor, "", "project", string(w.prjA), relverdict.Allow)
			w.capability(actor, proposedRole, "project", string(w.prjA), relverdict.Deny)
			for _, rel := range []string{"v_get", "v_list", "inspect"} {
				w.native(actor, rel, "probemod_tag", fb13Tag, relverdict.Allow)
				w.native(actor, rel, "probemod_tag", fb13OtherTag, relverdict.Deny)
				w.native("user:"+string(w.usrE), rel, "probemod_tag", fb13Tag, relverdict.Deny)
			}
			recipient := domain.Subject{Type: domain.SubjectTypeUser, ID: domain.SubjectID(w.usrE)}
			proposed := w.bundle.Compile(granteffect.Binding{SourceID: "fb30-proposed", Role: w.authored(proposedRole), Scope: domain.ScopeAnchor{Type: "project", ID: string(w.prjA)}, Target: domain.AccessTarget{Resources: []domain.ResourceRef{{Type: "probemod.tags", ID: fb13Tag}}}, Recipient: recipient, Subjects: []domain.Subject{recipient}, CapabilityVersion: 1})
			require.True(t, proposed.Complete(), "%v", proposed.Obligations())
			customPresent := false
			for _, effect := range proposed.Effects() {
				customPresent = customPresent || (effect.Type == "probemod_tag" && effect.Action.Kind == grantcoverage.Relation && effect.Action.Name == "inspect")
			}
			require.True(t, customPresent, "custom effect inspect не исчезает из предлагаемого результата")
			children := w.storedEffects(childrenID, childrenRequest)
			proof := granteffect.Prove(children, proposed)
			require.Equal(t, grantcoverage.NotProved, proof.Status)
			require.Equal(t, grantcoverage.ReasonUnsupported, proof.Reason, "parent-path импликация не подменяется несовпадением прав")
			w.fbStructuredWorld.deny(asUser(w.ctx, w.usrD), proposedRequest)
			for _, rel := range []string{"v_get", "v_list", "inspect"} {
				w.native("user:"+string(w.usrE), rel, "probemod_tag", fb13Tag, relverdict.Deny)
			}
			if branch == "exact_source" {
				sourceReq := proto.Clone(proposedRequest).(*iamv1.CreateAccessBindingRequest)
				sourceReq.Subjects = []*iamv1.Subject{userSubject(w.usrD)}
				sourceID := w.grantAt(sourceReq)
				proof = granteffect.Prove(granteffect.Union(children, w.storedEffects(sourceID, sourceReq)), proposed)
				require.Equal(t, grantcoverage.Proved, proof.Status)
				w.capability(actor, proposedRole, "project", string(w.prjA), relverdict.Deny)
			} else {
				bindRole := w.fullBindWorld.role("fb30_exact_bind", &iamv1.Rule{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{string(proposedRole)}})
				require.NoError(t, w.callbacks.awaitSetup(w.ctx, "iam.role", string(bindRole)))
				bindRequest := fbStructuredRequest(userSubject(w.usrD), bindRole, "project", string(w.prjA))
				bindID := w.grantAt(bindRequest)
				proof = granteffect.Prove(granteffect.Union(children, w.storedEffects(bindID, bindRequest)), proposed)
				require.Equal(t, grantcoverage.NotProved, proof.Status)
				require.Equal(t, grantcoverage.ReasonUnsupported, proof.Reason)
				w.capability(actor, proposedRole, "project", string(w.prjA), relverdict.Allow)
			}
			w.noScopeAdmin(actor)
			id := domain.AccessBindingID(w.createDone(asUser(w.ctx, w.usrD), proposedRequest, "FB30: независимое достаточное основание"))
			require.NoError(t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", string(id)))
			w.storedEffects(id, proposedRequest)
			require.True(t, proto.Equal(fixed, proposedRequest))
			for _, rel := range []string{"v_get", "v_list", "inspect"} {
				w.native("user:"+string(w.usrE), rel, "probemod_tag", fb13Tag, relverdict.Allow)
				w.native("user:"+string(w.usrE), rel, "probemod_tag", fb13OtherTag, relverdict.Deny)
			}
			w.materialized(id, "user:"+string(w.usrE), "v_get", "probemod_tag", fb13Tag, true)
			w.materialized(id, "user:"+string(w.usrE), "v_list", "probemod_tag", fb13Tag, true)
			w.materialized(id, "user:"+string(w.usrE), "v_get", "probemod_tag", fb13OtherTag, false)
		})
	}
}

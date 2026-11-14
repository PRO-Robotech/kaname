// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"testing"
	"time"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/corelib/ids"
	"github.com/PRO-Robotech/corelib/operations"
	accessbindingapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_binding"
	gdapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/grant_delegation"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

// Мир FB13 уже создаёт project и все generic объекты настоящими API, затем
// включает ordinary LOGIN/active/strict. Старый GD world с raw pointers не нужен.
type fbDelegationWorld struct {
	*fb13ChildrenWorld
	gd       *gdapp.Handler
	delegate string
	admin    domain.AccessBindingID
}

func newFBDelegationWorld(t *testing.T) *fbDelegationWorld {
	t.Helper()
	w := &fbDelegationWorld{fb13ChildrenWorld: newFB13ChildrenWorld(t)}
	doc, err := manifest.Load(w.doc)
	require.NoError(t, err)
	model, report, err := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{doc})
	require.NoError(t, err)
	bundle, err := w.repo.LoadAuthorityBundle(w.ctx, model, report.KeyTerms...)
	require.NoError(t, err)
	writers, err := kanamepg.NewGrantPolicyWriters(w.ctx, w.repo, bundle)
	require.NoError(t, err)
	delegated, err := kanamepg.NewGrantDelegationParticipant(w.ctx, w.repo, bundle)
	require.NoError(t, err)
	withdrawal, err := kanamepg.NewGrantDelegationRevokeParticipant(w.ctx, w.stages)
	require.NoError(t, err)
	source := catalog.Fixed{F: w.facts}
	path := accessbindingapp.NewDelegatedGrantPath(w.repo, w.door)
	create := accessbindingapp.NewCreateAccessBindingUseCase(w.repo, w.ops, source).
		WithRelationStore(w.door, slog.Default()).WithRegisteredKeys(kanamepg.NewRegisteredKeys(w.pool)).
		WithBindingDecisions(writers).WithDelegatedGrantPath(path).
		WithReconciler(&fb11SetupReconciler{SelectorReconciler: w.rec, callbacks: w.callbacks})
	revoke := accessbindingapp.NewRevokeAccessBindingUseCase(w.repo, w.ops).
		WithRelationStore(w.door, slog.Default()).WithBindingWithdrawal(w.stages).WithDelegatedGrantPath(path)
	w.ab = accessbindingapp.NewHandler(create, nil, nil, nil, nil, nil, nil).WithRevoke(revoke)
	w.gd = gdapp.NewHandler(
		gdapp.NewCreateGrantDelegationUseCase(w.repo, w.ops, source).WithRelationStore(w.door, slog.Default()).WithAuthorityWriter(delegated),
		gdapp.NewGetGrantDelegationUseCase(w.repo).WithRelationStore(w.door),
		gdapp.NewListGrantDelegationsUseCase(w.repo).WithRelationStore(w.door),
		gdapp.NewRevokeGrantDelegationUseCase(w.repo, w.ops).WithRelationStore(w.door, slog.Default()).WithRevokeAuthorityWriter(withdrawal),
	).WithUpdate(gdapp.NewUpdateGrantDelegationUseCase(w.repo, w.ops, source).WithRelationStore(w.door, slog.Default()).WithAuthorityWriter(delegated))
	// Разрешённая identity fixture: только SA, без прав, mirror или tuples.
	// Даже эта запись использует настоящий typed GLOBAL participant обычного LOGIN.
	tx, err := w.repo.ParticipantAuthorityWriter(w.ctx, kaname.AuthorityWriteIntent{Kind: kaname.AuthorityIdentity, Bundle: bundle, Plan: kaname.AuthorityFencePlan{Mode: kaname.AuthorityFenceGlobal}})
	require.NoError(t, err)
	defer func() {
		c, cancel := context.WithTimeout(context.WithoutCancel(w.ctx), 5*time.Second)
		defer cancel()
		_ = tx.Rollback(c)
	}()
	w.delegate = ids.NewID(domain.PrefixServiceAccount)
	_, err = tx.ServiceAccountsW().Insert(w.ctx, domain.ServiceAccount{ID: domain.ServiceAccountID(w.delegate), AccountID: w.accA, Name: "fb-delegate", Enabled: true, Labels: domain.Labels{}})
	require.NoError(t, err)
	require.NoError(t, tx.Commit(w.ctx))
	require.NotEqual(t, string(w.usrD), w.delegate)
	w.noUse()
	return w
}

func (w *fbDelegationWorld) noUse() {
	w.t.Helper()
	actor := "service_account:" + w.delegate
	w.noScopeAdmin(actor)
	w.capability(actor, "", "project", string(w.prjA), relverdict.Deny)
	w.capability(actor, w.osetr, "project", string(w.prjA), relverdict.Deny)
	for _, rel := range []string{"v_get", "v_list"} {
		for _, id := range []string{atcB1, atcB2} {
			w.native(actor, rel, atcBoxType, id, relverdict.Deny)
		}
		w.native(actor, rel, "probemod_tag", fb13Tag, relverdict.Deny)
	}
}

func (w *fbDelegationWorld) finish(op *operationpb.Operation, err error) {
	w.t.Helper()
	require.NoError(w.t, err)
	require.NotNil(w.t, op)
	require.NotEmpty(w.t, op.GetId())
	done := awaitOp(w.t, w.ctx, w.ops, op.GetId())
	require.Nil(w.t, done.Error, "терминальная Operation.error: %+v", done.Error)
}
func (w *fbDelegationWorld) createBinding(ctx context.Context, req *iamv1.CreateAccessBindingRequest, delegation string) domain.AccessBindingID {
	w.t.Helper()
	fixed := proto.Clone(req)
	op, err := w.ab.Create(ctx, req)
	w.finish(op, err)
	var md iamv1.CreateAccessBindingMetadata
	require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md))
	id := domain.AccessBindingID(md.GetAccessBindingId())
	require.NotEmpty(w.t, id)
	require.NoError(w.t, w.callbacks.awaitSetup(w.ctx, "iam.accessBinding", string(id)))
	require.True(w.t, proto.Equal(fixed, req))
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(w.t, err)
	b, err := rd.AccessBindings().Get(w.ctx, id)
	require.NoError(w.t, err)
	ss, err := rd.AccessBindings().ListSubjects(w.ctx, id)
	require.NoError(w.t, err)
	require.NoError(w.t, rd.Rollback(w.ctx))
	require.Equal(w.t, req.RoleId, string(b.RoleID))
	require.Equal(w.t, req.ScopeId, b.ResourceID)
	require.Equal(w.t, delegation, string(b.DelegationID))
	if delegation != "" {
		require.Empty(w.t, b.GrantedByUserID, "SA actor не переименовывается в saved creator")
	}
	require.Equal(w.t, domain.AccessBindingStatusActive, b.Status)
	require.Len(w.t, ss, 1)
	require.Equal(w.t, iamv1.SubjectType_SUBJECT_TYPE_USER, req.Subjects[0].GetType())
	require.Equal(w.t, []domain.Subject{{Type: domain.SubjectTypeUser, ID: domain.SubjectID(req.Subjects[0].GetId())}}, ss)
	require.Equal(w.t, strings.TrimPrefix(req.ScopeType, "iam."), string(b.ResourceType))
	require.Equal(w.t, req.Target.GetAllInScope() != nil, b.Target.AllInScope)
	if !b.Target.AllInScope {
		require.Equal(w.t, []domain.ResourceRef{{Type: req.Target.GetResources().GetResources()[0].GetType(), ID: req.Target.GetResources().GetResources()[0].GetId()}}, b.Target.Resources)
	}
	return id
}
func (w *fbDelegationWorld) adminOn() {
	w.t.Helper()
	w.admin = w.createBinding(asUser(w.ctx, w.usrA), fbStructuredRequest(userSubject(w.usrD), domain.RoleID(gdAdminRID), "account", string(w.accA)), "")
	w.native("user:"+string(w.usrD), "admin", "account", string(w.accA), relverdict.Allow)
}
func (w *fbDelegationWorld) revokeBinding(id domain.AccessBindingID) {
	w.t.Helper()
	op, err := w.ab.Revoke(asUser(w.ctx, w.usrA), &iamv1.RevokeAccessBindingRequest{AccessBindingId: string(id)})
	w.finish(op, err)
}
func (w *fbDelegationWorld) adminOff() {
	w.revokeBinding(w.admin)
	w.native("user:"+string(w.usrD), "admin", "account", string(w.accA), relverdict.Deny)
}
func (w *fbDelegationWorld) delegationRequest() *iamv1.CreateGrantDelegationRequest {
	return &iamv1.CreateGrantDelegationRequest{AccountId: string(w.accA), Delegate: svaSubject(w.delegate), RoleIds: []string{string(w.osetr)}, TargetTypes: []string{"probemod.boxes"}, SubjectTypes: []iamv1.SubjectType{iamv1.SubjectType_SUBJECT_TYPE_USER}}
}
func (w *fbDelegationWorld) createDelegation(ctx context.Context, req *iamv1.CreateGrantDelegationRequest) string {
	w.t.Helper()
	fixed := proto.Clone(req)
	op, err := w.gd.Create(ctx, req)
	w.finish(op, err)
	var md iamv1.CreateGrantDelegationMetadata
	require.NoError(w.t, op.GetMetadata().UnmarshalTo(&md))
	id := md.GetGrantDelegationId()
	require.NotEmpty(w.t, id)
	got := w.getDelegation(id)
	require.Equal(w.t, req.AccountId, got.GetAccountId())
	require.True(w.t, proto.Equal(req.Delegate, got.GetDelegate()), "делегат сохраняет тип и идентификатор")
	require.NotNil(w.t, got.GetDelegatedBy())
	require.Equal(w.t, operations.PrincipalFromContext(ctx).ID, got.GetDelegatedBy().GetId())
	require.NotEqual(w.t, w.delegate, got.GetDelegatedBy().GetId())
	require.ElementsMatch(w.t, req.RoleIds, got.GetRoleIds())
	require.ElementsMatch(w.t, req.TargetTypes, got.GetTargetTypes())
	require.ElementsMatch(w.t, req.SubjectTypes, got.GetSubjectTypes())
	require.True(w.t, proto.Equal(fixed, req))
	return id
}
func (w *fbDelegationWorld) getDelegation(id string) *iamv1.GrantDelegation {
	w.t.Helper()
	got, err := w.gd.Get(asUser(w.ctx, w.usrA), &iamv1.GetGrantDelegationRequest{GrantDelegationId: id})
	require.NoError(w.t, err)
	return got
}
func (w *fbDelegationWorld) snapshot() map[string]string {
	out := w.artifacts()
	for _, table := range []string{"grant_delegations", "resource_parent_edge", "resource_registration_scope", "resource_registration_pointer"} {
		var rows string
		require.NoError(w.t, w.observer.QueryRow(w.ctx, "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM kaname."+table+" r").Scan(&rows))
		out[table] = rows
	}
	return out
}
func (w *fbDelegationWorld) refuse(call func() (*operationpb.Operation, error), code codes.Code, message string) {
	w.t.Helper()
	before := w.snapshot()
	op, err := call()
	require.Nil(w.t, op)
	require.Equal(w.t, code, status.Code(err))
	require.Equal(w.t, message, status.Convert(err).Message())
	require.Equal(w.t, before, w.snapshot())
}
func (w *fbDelegationWorld) denied(req *iamv1.CreateAccessBindingRequest) {
	fixed := proto.Clone(req)
	w.noUse()
	w.refuse(func() (*operationpb.Operation, error) { return w.ab.Create(asSA(w.ctx, w.delegate), req) }, codes.PermissionDenied, "permission denied")
	require.True(w.t, proto.Equal(fixed, req))
}
func (w *fbDelegationWorld) update(ctx context.Context, req *iamv1.UpdateGrantDelegationRequest) {
	w.t.Helper()
	fixed := proto.Clone(req)
	op, err := w.gd.Update(ctx, req)
	w.finish(op, err)
	require.True(w.t, proto.Equal(fixed, req))
	got := w.getDelegation(req.GrantDelegationId)
	if len(req.RoleIds) > 0 {
		require.ElementsMatch(w.t, req.RoleIds, got.RoleIds)
	}
	if len(req.TargetTypes) > 0 {
		require.ElementsMatch(w.t, req.TargetTypes, got.TargetTypes)
	}
	if len(req.SubjectTypes) > 0 {
		require.ElementsMatch(w.t, req.SubjectTypes, got.SubjectTypes)
	}
}
func (w *fbDelegationWorld) granted(req *iamv1.CreateAccessBindingRequest, id string) domain.AccessBindingID {
	w.noUse()
	binding := w.createBinding(asSA(w.ctx, w.delegate), req, id)
	w.noUse()
	for _, rel := range []string{"v_get", "v_list"} {
		w.native("user:"+string(w.usrE), rel, atcBoxType, atcB1, relverdict.Allow)
		w.native("user:"+string(w.usrE), rel, "probemod_tag", fb13Tag, relverdict.Allow)
		w.materialized(binding, "user:"+string(w.usrE), rel, "probemod_tag", fb13Tag, true)
	}
	return binding
}

func TestFullBind_FB23_DelegatedAxesWithoutUseCoverage(t *testing.T) {
	for _, axis := range []string{"role", "target", "subject"} {
		t.Run(axis, func(t *testing.T) {
			w := newFBDelegationWorld(t)
			w.adminOn()
			dreq := w.delegationRequest()
			patch := &iamv1.UpdateGrantDelegationRequest{}
			switch axis {
			case "role":
				dreq.RoleIds = []string{string(w.partial)}
				patch.RoleIds = []string{string(w.partial), string(w.osetr)}
				patch.UpdateMask = &fieldmaskpb.FieldMask{Paths: []string{"role_ids"}}
			case "target":
				dreq.TargetTypes = []string{"probemod.tags"}
				patch.TargetTypes = []string{"probemod.tags", "probemod.boxes"}
				patch.UpdateMask = &fieldmaskpb.FieldMask{Paths: []string{"target_types"}}
			case "subject":
				dreq.SubjectTypes = []iamv1.SubjectType{iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT}
				patch.SubjectTypes = []iamv1.SubjectType{iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT, iamv1.SubjectType_SUBJECT_TYPE_USER}
				patch.UpdateMask = &fieldmaskpb.FieldMask{Paths: []string{"subject_types"}}
			}
			id := w.createDelegation(asUser(w.ctx, w.usrD), dreq)
			patch.GrantDelegationId = id
			req := w.request(w.usrE, w.osetr)
			fixed := proto.Clone(req)
			w.denied(req)
			w.update(asUser(w.ctx, w.usrD), patch)
			require.True(t, proto.Equal(fixed, req))
			w.granted(req, id)
			// Повтор того же Update — отдельный no-op: Operation есть, axes и аудит не меняются.
			prior := proto.Clone(w.getDelegation(id))
			var audits int
			require.NoError(t, w.observer.QueryRow(w.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.grant_delegation.updated'`).Scan(&audits))
			w.update(asUser(w.ctx, w.usrD), patch)
			require.True(t, proto.Equal(prior, w.getDelegation(id)))
			var after int
			require.NoError(t, w.observer.QueryRow(w.ctx, `SELECT count(*) FROM kaname.audit_outbox WHERE event_type='iam.grant_delegation.updated'`).Scan(&after))
			require.Equal(t, audits, after)
		})
	}
}

func TestFullBind_FB24_DelegationRechecksSavedCreator(t *testing.T) {
	for _, revoked := range []bool{false, true} {
		t.Run(map[bool]string{false: "creator_active", true: "creator_revoked"}[revoked], func(t *testing.T) {
			w := newFBDelegationWorld(t)
			w.adminOn()
			id := w.createDelegation(asUser(w.ctx, w.usrD), w.delegationRequest())
			req := w.request(w.usrE, w.osetr)
			if revoked {
				w.adminOff()
				w.denied(req)
			} else {
				w.granted(req, id)
			}
		})
	}
}

func TestFullBind_FB25a_DelegationCreatePreservesActorGate(t *testing.T) {
	w := newFBDelegationWorld(t)
	w.adminOn()
	w.adminOff()
	req := w.delegationRequest()
	fixed := proto.Clone(req)
	w.native("user:"+string(w.usrD), "admin", "account", string(w.accA), relverdict.Deny)
	w.refuse(func() (*operationpb.Operation, error) { return w.gd.Create(asUser(w.ctx, w.usrD), req) }, codes.PermissionDenied, "permission denied")
	w.adminOn()
	require.True(t, proto.Equal(fixed, req))
	w.createDelegation(asUser(w.ctx, w.usrD), req)
}
func TestFullBind_FB25b_DelegationUpdatePreservesActorGate(t *testing.T) {
	w := newFBDelegationWorld(t)
	id := w.createDelegation(asUser(w.ctx, w.usrA), w.delegationRequest())
	w.adminOn()
	w.adminOff()
	req := &iamv1.UpdateGrantDelegationRequest{GrantDelegationId: id, RoleIds: []string{string(w.osetr), string(w.partial)}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"role_ids"}}}
	fixed := proto.Clone(req)
	w.refuse(func() (*operationpb.Operation, error) { return w.gd.Update(asUser(w.ctx, w.usrD), req) }, codes.PermissionDenied, "permission denied")
	w.adminOn()
	require.True(t, proto.Equal(fixed, req))
	w.update(asUser(w.ctx, w.usrD), req)
}
func TestFullBind_FB25c_DelegationUpdatePreservesSavedCreatorGate(t *testing.T) {
	w := newFBDelegationWorld(t)
	w.adminOn()
	id := w.createDelegation(asUser(w.ctx, w.usrD), w.delegationRequest())
	w.adminOff()
	req := &iamv1.UpdateGrantDelegationRequest{GrantDelegationId: id, RoleIds: []string{string(w.osetr), string(w.partial)}, UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"role_ids"}}}
	fixed := proto.Clone(req)
	w.refuse(func() (*operationpb.Operation, error) { return w.gd.Update(asUser(w.ctx, w.usrA), req) }, codes.FailedPrecondition, fmt.Sprintf("grant delegation %s: delegator no longer has grant authority", id))
	w.adminOn()
	require.True(t, proto.Equal(fixed, req))
	w.update(asUser(w.ctx, w.usrA), req)
}

// Источник authority не становится условием жизни уже принятой выдачи.
func (w *fbDelegationWorld) storedBinding(id domain.AccessBindingID) domain.AccessBinding {
	rd, err := w.repo.Reader(w.ctx)
	require.NoError(w.t, err)
	defer func() { _ = rd.Rollback(w.ctx) }()
	b, err := rd.AccessBindings().Get(w.ctx, id)
	require.NoError(w.t, err)
	return b
}

// Полный образ каждой прежней выдачи включает её субъектов, цель и owned ledger.
func (w *fbDelegationWorld) bindingImage(id domain.AccessBindingID) map[string]string {
	w.t.Helper()
	out := map[string]string{}
	for _, table := range []string{"access_bindings", "access_binding_subjects", "access_binding_target_members", "access_binding_emitted_tuples"} {
		key := "binding_id"
		if table == "access_bindings" {
			key = "id"
		}
		var rows string
		require.NoError(w.t, w.observer.QueryRow(w.ctx, "SELECT coalesce(jsonb_agg(to_jsonb(r) ORDER BY to_jsonb(r)::text),'[]'::jsonb)::text FROM kaname."+table+" r WHERE "+key+"=$1", string(id)).Scan(&rows))
		out[table] = rows
	}
	return out
}
func TestFullBind_FB33a_OrdinaryAuthorityWithdrawalKeepsOldBindings(t *testing.T) {
	w := newFBDelegationWorld(t)
	w.createCapability(userSubject(w.usrD), "project", string(w.prjA))
	source := w.createBinding(asUser(w.ctx, w.usrA), fbStructuredRequest(userSubject(w.usrD), w.osetr, "project", string(w.prjA)), "")
	w.noScopeAdmin("user:" + string(w.usrD))
	w.capability("user:"+string(w.usrD), "", "project", string(w.prjA), relverdict.Allow)
	w.native("user:"+string(w.usrD), "v_get", atcBoxType, atcB2, relverdict.Allow)
	w.capability("user:"+string(w.usrD), w.osetr, "project", string(w.prjA), relverdict.Deny)
	var old []domain.AccessBinding
	images := map[domain.AccessBindingID]map[string]string{}
	req := w.request(w.usrE, w.osetr)
	for _, box := range []string{atcB1, atcB2} {
		req.Target = resourcesTarget(rr("probemod.boxes", box))
		id := w.createBinding(asUser(w.ctx, w.usrD), req, "")
		old = append(old, w.storedBinding(id))
		images[id] = w.bindingImage(id)
	}
	w.revokeBinding(source)
	w.native("user:"+string(w.usrD), "v_get", atcBoxType, atcB2, relverdict.Deny)
	fixed := proto.Clone(req)
	w.refuse(func() (*operationpb.Operation, error) { return w.ab.Create(asUser(w.ctx, w.usrD), req) }, codes.PermissionDenied, "permission denied")
	require.True(t, proto.Equal(fixed, req))
	for _, b := range old {
		require.Equal(t, b, w.storedBinding(b.ID))
		require.Equal(t, images[b.ID], w.bindingImage(b.ID))
		require.Equal(t, domain.AccessBindingStatusActive, b.Status)
	}
	for _, box := range []string{atcB1, atcB2} {
		w.native("user:"+string(w.usrE), "v_get", atcBoxType, box, relverdict.Allow)
		tag := fb13Tag
		if box == atcB2 {
			tag = fb13OtherTag
		}
		w.native("user:"+string(w.usrE), "v_get", "probemod_tag", tag, relverdict.Allow)
	}
}
func TestFullBind_FB33b_CreatorWithdrawalKeepsDelegatedBindingsUntilExplicitRevoke(t *testing.T) {
	w := newFBDelegationWorld(t)
	w.adminOn()
	id := w.createDelegation(asUser(w.ctx, w.usrD), w.delegationRequest())
	var old []domain.AccessBinding
	images := map[domain.AccessBindingID]map[string]string{}
	req := w.request(w.usrE, w.osetr)
	for _, box := range []string{atcB1, atcB2} {
		req.Target = resourcesTarget(rr("probemod.boxes", box))
		w.noUse()
		b := w.createBinding(asSA(w.ctx, w.delegate), req, id)
		old = append(old, w.storedBinding(b))
		images[b] = w.bindingImage(b)
	}
	w.adminOff()
	beforeDelegation := proto.Clone(w.getDelegation(id))
	w.denied(req)
	require.True(t, proto.Equal(beforeDelegation, w.getDelegation(id)))
	for _, b := range old {
		require.Equal(t, b, w.storedBinding(b.ID))
		require.Equal(t, images[b.ID], w.bindingImage(b.ID))
		require.Equal(t, domain.AccessBindingStatusActive, b.Status)
	}
	for _, box := range []string{atcB1, atcB2} {
		w.native("user:"+string(w.usrE), "v_get", atcBoxType, box, relverdict.Allow)
		tag := fb13Tag
		if box == atcB2 {
			tag = fb13OtherTag
		}
		w.native("user:"+string(w.usrE), "v_get", "probemod_tag", tag, relverdict.Allow)
	}
	op, err := w.gd.Revoke(asUser(w.ctx, w.usrA), &iamv1.RevokeGrantDelegationRequest{GrantDelegationId: id})
	w.finish(op, err)
	require.Equal(t, "REVOKED", w.getDelegation(id).GetStatus().String())
	for _, b := range old {
		require.Equal(t, domain.AccessBindingStatusRevoked, w.storedBinding(b.ID).Status)
	}
	for _, box := range []string{atcB1, atcB2} {
		w.native("user:"+string(w.usrE), "v_get", atcBoxType, box, relverdict.Deny)
		tag := fb13Tag
		if box == atcB2 {
			tag = fb13OtherTag
		}
		w.native("user:"+string(w.usrE), "v_get", "probemod_tag", tag, relverdict.Deny)
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

// Мир #1032. Здесь нет реализации Update: JSON проходит реальный MethodHandler.
// Живые контроли Дано предшествуют отсутствующему дескриптору. Self Check идёт
// от S/S2/M через Authorize.Check; транспортную дверь отдельно проверяет newman.
import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"testing"
	"time"

	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

const (
	gduSA    = "SUBJECT_TYPE_SERVICE_ACCOUNT"
	gduGroup = "SUBJECT_TYPE_GROUP"
	gduUser  = "SUBJECT_TYPE_USER"
	gduClass = "SUBJECT_TYPE_SYSTEM_CLASS"
	gduEvent = "iam.grant_delegation.updated"
)

type gduWorld struct {
	*gdWorld
	d, b, g    string
	original   map[string]any
	oldBinding *iamv1.AccessBinding
}

func newGDUWorld(t *testing.T, creatorE bool) *gduWorld {
	t.Helper()
	w := newGDWorld(t)
	w.requireSubject("#1032 Дано: прежние Create/Get/List/Revoke")
	u := &gduWorld{gdWorld: w}
	u.liveCatalog()
	owner := asUser(w.ctx, w.usrA)
	op, err := w.groups.Create(owner, &iamv1.CreateGroupRequest{AccountId: string(w.accA), Name: "gdu-only-m"})
	require.NoError(t, err, "Дано: штатный Group.Create")
	done := awaitOp(t, w.ctx, w.ops, op.GetId())
	require.Nil(t, done.Error)
	u.g = anyField(t, op.GetMetadata(), "groupId")
	require.NotEmpty(t, u.g)
	op, err = w.groups.AddMember(owner, &iamv1.AddGroupMemberRequest{GroupId: u.g, MemberType: "service_account", MemberId: w.svaA3})
	require.NoError(t, err, "Дано: штатный Group.AddMember(M)")
	done = awaitOp(t, w.ctx, w.ops, op.GetId())
	require.Nil(t, done.Error)
	w.pollRelation("user:"+string(w.usrA), "v_list", "iam_group:"+u.g, true, "Дано: чтение членов готово")
	members, err := w.groups.ListMembers(owner, &iamv1.ListGroupMembersRequest{GroupId: u.g})
	require.NoError(t, err)
	require.Len(t, members.GetMembers(), 1)
	require.Equal(t, w.svaA3, members.GetMembers()[0].GetMemberId())
	require.Equal(t, "service_account", members.GetMembers()[0].GetMemberType())
	require.NotEqual(t, w.svaIss, w.svaA3)
	for _, sa := range []string{w.svaA, w.svaA2, w.svaA3} {
		u.selfCheck(sa, "v_get", pcrRegType, pcrX, false)
		u.selfCheck(sa, "v_get", pcrRepoType, pcrXApp, false)
		u.selfCheck(sa, "v_update", pcrRepoType, pcrXApp, false)
	}
	creator := owner
	if creatorE {
		creator = asUser(w.ctx, w.usrE)
	}
	u.d = w.createDelegation(creator, w.delegationBody(w.accA, w.svaIss, []domain.RoleID{w.rolPuller}, []string{"registry.registries"}, []string{gduSA}), "Дано: D0")
	u.b = requireGranted(t, w.tryGrant(asSA(w.ctx, w.svaIss), u.grant("role", false)), "Дано: B0")
	w.requireDelegatedBinding(u.b, u.d, "Дано: B0 attribution")
	require.NoError(t, w.rec.ReconcileBinding(w.ctx, domain.AccessBindingID(u.b)), "Дано: штатное согласование B0")
	u.selfCheck(w.svaA, "v_get", pcrRegType, pcrX, true)
	u.original = u.get()
	u.oldBinding = proto.Clone(w.getBinding(u.b)).(*iamv1.AccessBinding)
	require.Equal(t, "registry", u.original["module"])
	require.Equal(t, "ACTIVE", u.original["status"])
	require.True(t, w.mirrorHas(pcrRepoType, pcrXApp), "Дано: Y — дочерний repository X")
	return u
}

func (u *gduWorld) subject() {
	u.t.Helper()
	d, err := protoregistry.GlobalFiles.FindDescriptorByName(gdServiceName)
	require.NoError(u.t, err)
	require.NotNil(u.t, d.(protoreflect.ServiceDescriptor).Methods().ByName("Update"), "#1032 ПРЕДМЕТА НЕТ: GrantDelegationService.Update после живых контролей Дано; behavioral Then ещё не исполнялся")
}
func (u *gduWorld) get() map[string]any {
	u.t.Helper()
	m, e := u.getDelegation(asUser(u.ctx, u.usrA), u.d)
	require.NoError(u.t, e)
	return m
}
func (u *gduWorld) selfCheck(sa, relation, typ, id string, want bool) {
	u.t.Helper()
	got, err := u.authz.Check(asSA(u.ctx, sa), &iamv1.AuthorizeCheckRequest{Subject: "service_account:" + sa, Resource: &iamv1.ResourceRef{Type: typ, Id: id}, Action: pcrAction(typ, relation), RequiredRelation: relation})
	require.NoError(u.t, err, "self Check должен дать решение, не ошибку")
	require.Equal(u.t, want, got.GetAllowed(), "self Check(%s,%s,%s:%s)", sa, relation, typ, id)
}
func (u *gduWorld) grant(axis string, expanded bool) *iamv1.CreateAccessBindingRequest {
	r := &iamv1.CreateAccessBindingRequest{Subjects: []*iamv1.Subject{svaSubject(u.svaA)}, RoleId: string(u.rolPuller), ScopeType: "iam.project", ScopeId: string(u.prjA), Target: pcrXTarget()}
	if !expanded {
		return r
	}
	switch axis {
	case "role":
		r.RoleId = string(u.rolPusher)
	case "target":
		r.Subjects = []*iamv1.Subject{svaSubject(u.svaA2)}
		r.Target = resourcesTarget(&iamv1.ResourceRef{Type: gdRepoTgt, Id: pcrXApp})
	case "subject":
		r.Subjects = []*iamv1.Subject{groupSubject(u.g)}
	case "all":
		r.RoleId = string(u.rolPusher)
		r.Subjects = []*iamv1.Subject{groupSubject(u.g)}
		r.Target = resourcesTarget(&iamv1.ResourceRef{Type: gdRepoTgt, Id: pcrXApp})
	default:
		u.t.Fatalf("неизвестная ветвь %q", axis)
	}
	return r
}
func (u *gduWorld) effect(axis string, want bool) {
	switch axis {
	case "role":
		u.selfCheck(u.svaA, "v_update", pcrRepoType, pcrXApp, want)
	case "target":
		u.selfCheck(u.svaA2, "v_get", pcrRepoType, pcrXApp, want)
	case "subject":
		u.selfCheck(u.svaA3, "v_get", pcrRegType, pcrX, want)
	case "all":
		u.selfCheck(u.svaA3, "v_update", pcrRepoType, pcrXApp, want)
	default:
		u.t.Fatalf("неизвестный effective case %q", axis)
	}
}
func (u *gduWorld) all() map[string]any {
	return map[string]any{"roleIds": []string{string(u.rolPuller), string(u.rolPusher)}, "targetTypes": []string{"registry.registries", gdRepoTgt}, "subjectTypes": []string{gduSA, gduGroup}}
}
func (u *gduWorld) currentAxes() map[string]any {
	m := u.get()
	return map[string]any{"roleIds": m["roleIds"], "targetTypes": m["targetTypes"], "subjectTypes": m["subjectTypes"]}
}
func (u *gduWorld) body(mask *string, axes map[string]any) string {
	m := map[string]any{"grantDelegationId": u.d}
	for k, v := range axes {
		m[k] = v
	}
	if mask != nil {
		m["updateMask"] = *mask
	}
	return mustJSON(u.t, m)
}
func gduMask(s string) *string { return &s }
func (u *gduWorld) call(ctx context.Context, mask *string, axes map[string]any) gdOp {
	return u.gdMutate(ctx, "Update", u.body(mask, axes))
}
func (u *gduWorld) patch(mask string, axes map[string]any) {
	u.success(asUser(u.ctx, u.usrA), gduMask(mask), axes)
}
func (u *gduWorld) success(ctx context.Context, mask *string, axes map[string]any) {
	u.t.Helper()
	_, msg, err := u.gdCall(ctx, "Update", u.body(mask, axes))
	require.NoError(u.t, err)
	op, ok := msg.(*operationpb.Operation)
	require.True(u.t, ok)
	u.finish(op)
}
func (u *gduWorld) finish(op *operationpb.Operation) {
	u.t.Helper()
	require.NotEmpty(u.t, op.GetId())
	require.NotNil(u.t, op.GetMetadata())
	require.Equal(u.t, "type.googleapis.com/kaname.cloud.iam.v1.UpdateGrantDelegationMetadata", op.GetMetadata().GetTypeUrl())
	require.Equal(u.t, u.d, anyField(u.t, op.GetMetadata(), "grantDelegationId"))
	require.Equal(u.t, string(u.accA), anyField(u.t, op.GetMetadata(), "accountId"))
	done := awaitOp(u.t, u.ctx, u.ops, op.GetId())
	require.Nil(u.t, done.Error, "Update Operation.error: %+v", done.Error)
	require.NotNil(u.t, done.Response)
	response, err := done.Response.UnmarshalNew()
	require.NoError(u.t, err)
	got := u.get()
	require.Equal(u.t, got, toJSONMap(u.t, response), "done.response = последующий Get")
	found := false
	for _, d := range u.listAllDelegations(asUser(u.ctx, u.usrA), u.accA) {
		if d["id"] == u.d {
			require.Equal(u.t, got, d)
			found = true
		}
	}
	require.True(u.t, found, "List содержит d")
	u.invariant(false)
}
func (u *gduWorld) invariant(allAxes bool) {
	u.t.Helper()
	got := u.get()
	for k, v := range u.original {
		if !allAxes && (k == "roleIds" || k == "targetTypes" || k == "subjectTypes") {
			continue
		}
		require.Equal(u.t, v, got[k], "I: поле %s", k)
	}
	require.True(u.t, proto.Equal(u.oldBinding, u.getBinding(u.b)), "I: старый B0 полностью неизменен")
	u.selfCheck(u.svaA, "v_get", pcrRegType, pcrX, true)
	require.NoError(u.t, u.rec.ReconcileBinding(u.ctx, domain.AccessBindingID(u.b)))
	require.True(u.t, proto.Equal(u.oldBinding, u.getBinding(u.b)), "I после согласования: B0")
	u.selfCheck(u.svaA, "v_get", pcrRegType, pcrX, true)
}
func (u *gduWorld) audit() []gdAuditRow { return findAudit(u.auditRows(), gduEvent, "") }
func (u *gduWorld) refuse(ctx context.Context, mask *string, axes map[string]any, code codes.Code, text, field string) {
	u.t.Helper()
	before := u.get()
	bindings := u.countDelegated(u.d)
	audits := len(u.audit())
	out := u.call(ctx, mask, axes)
	require.Empty(u.t, out.opID, "отказ синхронный, Operation не создаётся")
	st := requireRefusal(u.t, out.syncErr, code, text, "Update")
	if field != "" {
		require.Len(u.t, st.Details(), 1)
		bad, ok := st.Details()[0].(*errdetails.BadRequest)
		require.True(u.t, ok)
		require.Len(u.t, bad.FieldViolations, 1)
		require.Equal(u.t, field, bad.FieldViolations[0].Field)
		require.Equal(u.t, text, bad.FieldViolations[0].Description)
	} else {
		require.Empty(u.t, st.Details())
	}
	require.Equal(u.t, before, u.get(), "отказ атомарен по всем осям")
	require.Equal(u.t, bindings, u.countDelegated(u.d))
	require.Len(u.t, u.audit(), audits)
	u.invariant(false)
}
func (u *gduWorld) expandedGrant(axis string) string {
	id := requireGranted(u.t, u.tryGrant(asSA(u.ctx, u.svaIss), u.grant(axis, true)), "после PATCH то же тело выдачи")
	u.requireDelegatedBinding(id, u.d, "новая выдача")
	require.NoError(u.t, u.rec.ReconcileBinding(u.ctx, domain.AccessBindingID(id)))
	u.effect(axis, true)
	u.invariant(false)
	return id
}
func (u *gduWorld) revokeAdminE() {
	u.awaitRemovalRight(u.usrA, u.grantE, "E revoke readiness")
	op, err := u.revokeBinding(asUser(u.ctx, u.usrA), u.grantE)
	u.requireVerbDone(op.GetId(), err, "отзыв admin E")
	u.pollRelation("user:"+string(u.usrE), "admin", "account:"+string(u.accA), false, "E действительно потерял право")
}
func (u *gduWorld) admin(subject *iamv1.Subject) string {
	id := u.createDoneX(asUser(u.ctx, u.usrA), &iamv1.CreateAccessBindingRequest{Subjects: []*iamv1.Subject{subject}, RoleId: gdAdminRID, ScopeType: "iam.account", ScopeId: string(u.accA), Target: allInScopeTarget()}, "независимое admin")
	typ := "user"
	if subject.GetType() == iamv1.SubjectType_SUBJECT_TYPE_SERVICE_ACCOUNT {
		typ = "service_account"
	}
	u.pollRelation(typ+":"+subject.GetId(), "admin", "account:"+string(u.accA), true, "admin материализован")
	return id
}
func gduSorted(v any) []string {
	b, _ := json.Marshal(v)
	var out []string
	_ = json.Unmarshal(b, &out)
	sort.Strings(out)
	return out
}
func (u *gduWorld) axes(want map[string]any) {
	got := u.get()
	for k, v := range want {
		require.Equal(u.t, gduSorted(v), gduSorted(got[k]), k)
		require.Equal(u.t, gduSorted(got[k]), gotSlice(got[k]), "выход отсортирован: "+k)
	}
}
func gotSlice(v any) []string {
	b, _ := json.Marshal(v)
	var s []string
	_ = json.Unmarshal(b, &s)
	return s
}
func (u *gduWorld) rawMask(paths []string, axes map[string]any) {
	// protojson задаёт camelCase; эту ветвь посылаем настоящими gRPC paths.
	reg := u.gdWorld.subject.svcs[gdServiceName]
	d, e := protoregistry.GlobalFiles.FindDescriptorByName(gdServiceName)
	require.NoError(u.t, e)
	md := d.(protoreflect.ServiceDescriptor).Methods().ByName("Update")
	in := gduDynamic(u.t, md.Input(), u.body(nil, axes))
	field := in.Descriptor().Fields().ByName("update_mask")
	require.NotNil(u.t, field)
	in.Set(field, protoreflect.ValueOfMessage((&fieldmaskpb.FieldMask{Paths: paths}).ProtoReflect()))
	for _, m := range reg.desc.Methods {
		if m.MethodName == "Update" {
			out, err := m.Handler(reg.impl, asUser(u.ctx, u.usrA), func(v any) error {
				b, e := proto.Marshal(in.Interface())
				if e != nil {
					return e
				}
				return proto.Unmarshal(b, v.(proto.Message))
			}, nil)
			require.NoError(u.t, err)
			op, ok := out.(*operationpb.Operation)
			require.True(u.t, ok)
			u.finish(op)
			return
		}
	}
	u.t.Fatal("Update MethodHandler отсутствует")
}
func gduLostCreator(id string) string {
	return fmt.Sprintf("grant delegation %s: delegator no longer has grant authority", id)
}
func gduNarrow(id, axis string) string {
	return fmt.Sprintf("grant delegation %s: %s may only expand", id, axis)
}
func gduOpError(t *testing.T, u *gduWorld, op *operationpb.Operation, code codes.Code, message string) {
	t.Helper()
	done := awaitOp(t, u.ctx, u.ops, op.GetId())
	require.NotNil(t, done.Error)
	require.Equal(t, int32(code), done.Error.Code)
	require.Equal(t, message, done.Error.Message)
}

// Время используется только как верхняя граница барьера, не как порядок гонки.
const gduBarrierDeadline = 30 * time.Second

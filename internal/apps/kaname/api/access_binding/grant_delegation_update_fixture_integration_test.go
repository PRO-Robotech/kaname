// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package access_binding_test

import (
	"context"
	"fmt"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	rolerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname/role"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
	"google.golang.org/protobuf/types/dynamicpb"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

func gduDynamic(t *testing.T, md protoreflect.MessageDescriptor, body string) protoreflect.Message {
	t.Helper()
	m := dynamicpb.NewMessage(md)
	require.NoError(t, protojson.Unmarshal([]byte(body), m))
	return m.ProtoReflect()
}
func gduRefusalDetails(t *testing.T, err error, code codes.Code, message, field string) {
	t.Helper()
	s := requireRefusal(t, err, code, message, "Update raw input")
	if field == "" {
		require.Empty(t, s.Details())
		return
	}
	require.Len(t, s.Details(), 1)
	b, ok := s.Details()[0].(*errdetails.BadRequest)
	require.True(t, ok)
	require.Len(t, b.FieldViolations, 1)
	require.Equal(t, field, b.FieldViolations[0].Field)
	require.Equal(t, message, b.FieldViolations[0].Description)
}
func (u *gduWorld) rawMaskRefusal(paths []string, axes map[string]any, message, field string) {
	u.t.Helper()
	before := u.get()
	n := len(u.audit())
	reg := u.gdWorld.subject.svcs[gdServiceName]
	d, e := protoregistry.GlobalFiles.FindDescriptorByName(gdServiceName)
	require.NoError(u.t, e)
	md := d.(protoreflect.ServiceDescriptor).Methods().ByName("Update")
	in := gduDynamic(u.t, md.Input(), u.body(nil, axes))
	in.Set(in.Descriptor().Fields().ByName("update_mask"), protoreflect.ValueOfMessage((&fieldmaskpb.FieldMask{Paths: paths}).ProtoReflect()))
	for _, m := range reg.desc.Methods {
		if m.MethodName == "Update" {
			out, err := m.Handler(reg.impl, asUser(u.ctx, u.usrA), func(v any) error {
				b, e := proto.Marshal(in.Interface())
				if e != nil {
					return e
				}
				return proto.Unmarshal(b, v.(proto.Message))
			}, nil)
			require.Nil(u.t, out)
			gduRefusalDetails(u.t, err, codes.InvalidArgument, message, field)
			require.Equal(u.t, before, u.get())
			require.Len(u.t, u.audit(), n)
			u.invariant(false)
			return
		}
	}
	u.t.Fatal("обработчик Update отсутствует")
}
func gduDeadType(v string) string {
	return fmt.Sprintf("Illegal argument target_types[] %q (not a live entry of the platform resource catalog; grantable types are published by %s)", v, domain.CatalogEndpoint)
}

// Доставка 17 настоящих ключей проходит существующий Load/ApplyAll/Apply roles.
// Манифест registry сохраняет все прежние ресурсы/роли и добавляет локальные
// пустые типы и роли чтения. Ни одной бизнес-ручки эти типы не подменяют.
func (u *gduWorld) deliverBounds() ([]string, []string) {
	raw, err := publicreadfixture.Read(gdFixture)
	require.NoError(u.t, err)
	raw, err = publicreadfixture.WithWrites(raw)
	require.NoError(u.t, err)
	var resources, roles strings.Builder
	targets := []string{"registry.registries", gdRepoTgt}
	ids := []string{string(u.rolPuller), string(u.rolPusher), string(u.rolRegAdmin)}
	for i := 0; i < 15; i++ {
		name := fmt.Sprintf("gduBound%02d", i)
		targets = append(targets, "registry."+name)
		fmt.Fprintf(&resources, "\n  - name: %s\n    objectType: registry_gdu_bound_%02d\n    parents: [project]\n    producer: authored\n    verbs: [{name: get}]\n", name, i)
	}
	for i := 0; i < 14; i++ {
		fmt.Fprintf(&roles, "\n  - id: registry.gdu_bound_%02d\n    description: 'Изолированная роль чтения для границы набора Update.'\n    tier: {tierType: iam.cluster, tierId: cluster_root}\n    rules:\n      - module: registry\n        resources: [registries]\n        classes: [get]\n", i)
	}
	doc := strings.Replace(string(raw), "\nroles:", resources.String()+"\nroles:", 1) + roles.String()
	m, err := manifest.Load([]byte(doc))
	require.NoError(u.t, err, "контроль Дано 17: загрузчик")
	u.applyDelivered("GDU05: реальная доставка границы 17", m)
	u.refreshFacts()
	for i := 0; i < 14; i++ {
		ids = append(ids, string(u.roleByName(fmt.Sprintf("registry.gdu_bound_%02d", i))))
	}
	for _, typ := range targets {
		var live bool
		require.NoError(u.t, u.pool.QueryRow(u.ctx, `SELECT live FROM kaname.catalog_resource WHERE dotted=$1`, typ).Scan(&live))
		require.True(u.t, live, "Дано: тип существует и жив")
	}
	require.Len(u.t, ids, 17)
	require.Len(u.t, targets, 17)
	u.invariant(true)
	return ids, targets
}
func (u *gduWorld) liveCatalog() {
	rd := kanamepg.NewCatalogRepo(u.pool)
	halves, err := rd.ReadCatalogHalves(u.ctx)
	require.NoError(u.t, err)
	snap, err := catalog.NewSnapshot(halves, rd, nil, nil)
	require.NoError(u.t, err)
	u.updateCatalog = snap
	u.buildHandlers()
}
func (u *gduWorld) refreshFacts() {
	snap, ok := u.updateCatalog.(*catalog.Snapshot)
	require.True(u.t, ok)
	require.NoError(u.t, snap.Refresh(u.ctx))
	u.facts = snap.Facts()
	u.buildHandlers()
}

// Роли мира Д ссылаются на repositories, и БД закономерно запрещает его
// снятие. Отдельная живая цель без ссылок правил даёт законный Given снятия,
// сохраняя все роли, B0 и ограничения каталога.
const gduRetiredTarget = "registry.gduRetired"

func (u *gduWorld) retirementManifest() *manifest.Manifest {
	raw, err := publicreadfixture.Read(gdFixture)
	require.NoError(u.t, err)
	raw, err = publicreadfixture.WithWrites(raw)
	require.NoError(u.t, err)
	resource := "\n  - name: gduRetired\n    objectType: registry_gdu_retired\n    parents: [project]\n    producer: authored\n    verbs: [{name: get}]\n"
	doc := strings.Replace(string(raw), "\nroles:", resource+"\nroles:", 1)
	full, err := manifest.Load([]byte(doc))
	require.NoError(u.t, err)
	return full
}

func (u *gduWorld) deliverRetirementTarget() {
	u.applyDelivered("GDU06: отдельная живая цель без ссылок правил", u.retirementManifest())
	u.refreshFacts()
	require.True(u.t, domain.ValidTargetType(u.facts, gduRetiredTarget))
}

func (u *gduWorld) retireTarget() func() {
	full := u.retirementManifest()
	cut := *full
	cut.Resources = nil
	for _, r := range full.Resources {
		if r.Name != "gduRetired" {
			cut.Resources = append(cut.Resources, r)
		}
	}
	apply := func(m *manifest.Manifest) {
		_, e := modulecatalog.NewApplier(kanamepg.NewCatalogWriteRepo(u.pool)).ApplyAll(u.ctx, []*manifest.Manifest{m})
		require.NoError(u.t, e)
		u.refreshFacts()
	}
	apply(&cut)
	var live bool
	require.NoError(u.t, u.pool.QueryRow(u.ctx, `SELECT live FROM kaname.catalog_resource WHERE dotted=$1`, gduRetiredTarget).Scan(&live))
	require.False(u.t, live)
	return func() { apply(full) }
}

type gduBadRoleRepo struct {
	kanamerepo.Repository
	id domain.RoleID
}
type gduBadRoleReader struct {
	kanamerepo.Reader
	id domain.RoleID
}
type gduBadRolePort struct {
	rolerepo.ReaderIface
	id domain.RoleID
}

func (r *gduBadRoleRepo) Reader(ctx context.Context) (kanamerepo.Reader, error) {
	rd, e := r.Repository.Reader(ctx)
	if e != nil {
		return nil, e
	}
	return &gduBadRoleReader{Reader: rd, id: r.id}, nil
}
func (r *gduBadRoleReader) Roles() rolerepo.ReaderIface {
	return &gduBadRolePort{ReaderIface: r.Reader.Roles(), id: r.id}
}
func (r *gduBadRolePort) Get(ctx context.Context, id domain.RoleID) (domain.Role, error) {
	v, e := r.ReaderIface.Get(ctx, id)
	if e == nil && id == r.id {
		v.Rules = append(append(domain.Rules{}, v.Rules...), domain.Rule{Module: "vpc", Resources: []string{"addressPool"}, Verbs: []string{"get"}})
	}
	return v, e
}
func (u *gduWorld) foreignRoleRule() func() {
	u.updateRepo = &gduBadRoleRepo{Repository: u.repo, id: u.rolPusher}
	u.buildHandlers()
	return func() { u.updateRepo = nil; u.buildHandlers() }
}

type gduFaultDoor struct {
	clients.RelationStore
	subject string
}

func (d *gduFaultDoor) Check(ctx context.Context, s, r, o string) (bool, error) {
	if d.subject == "" || d.subject == s {
		return false, iamerr.ErrUnavailable
	}
	return d.RelationStore.Check(ctx, s, r, o)
}
func (u *gduWorld) authzFault(subject string) func() {
	u.updateDoor = &gduFaultDoor{RelationStore: u.door, subject: subject}
	u.buildHandlers()
	return func() { u.updateDoor = nil; u.buildHandlers() }
}

type gduFailCommitRepo struct{ kanamerepo.Repository }
type gduFailCommitWriter struct{ kanamerepo.Writer }

func (r *gduFailCommitRepo) Writer(ctx context.Context) (kanamerepo.Writer, error) {
	w, e := r.Repository.Writer(ctx)
	if e != nil {
		return nil, e
	}
	return &gduFailCommitWriter{Writer: w}, nil
}
func (w *gduFailCommitWriter) Commit(context.Context) error { return iamerr.ErrUnavailable }
func (u *gduWorld) failCommit() func() {
	u.updateRepo = &gduFailCommitRepo{Repository: u.repo}
	u.buildHandlers()
	return func() { u.updateRepo = nil; u.buildHandlers() }
}

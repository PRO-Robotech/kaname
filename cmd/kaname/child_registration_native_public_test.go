// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/metadata"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"
	"gopkg.in/yaml.v3"
)

// Отдельно включаемый исходный кандидат приёмки. Skip не является доказательством
// #1045: запуск требует зафиксированных native binary/migrator и отдельного
// evidence root действующего installation harness. Подмена principal запрещена.
func TestChildRegistrationNativePublicRESTAndGRPC(t *testing.T) {
	if testing.Short() || os.Getenv("KANAME_CHILD_PUBLIC_ACCEPTANCE") != "1" {
		t.Skip("child registration requires an explicit native stand")
	}
	delivery := childNativePublicDelivery(t)
	f := newInstallationNativeWorldProfile(t, 7200, "", true)
	plan := installruntime.RegistryRegistrationWriterPlan([]string{f.tenantID})
	process := f.apply(t, installruntime.DeliveryInput{RegistrationWriters: plan, Manifests: delivery, CredentialFile: f.creator.CredentialFile})
	rid09AwaitBaseRoleProjections(t, f.given.ctx, process)
	// Bearer действительно выдан ceremony после FULL запуска и принят /me.
	f.renewOperator(t, f.given.ctx)
	project := ridResponseID(t, f.ridOperation(t, http.MethodPost, "/iam/v1/projects", f.operator.Bearer(),
		map[string]any{"accountId": f.tenantID, "name": "child-public-project"}, 0))
	const parentID = "public-parent"
	const childID = parentID + "/candidate"
	moduleConn, err := f.wire.ModuleWriter(filepath.Join(f.session.Root, "pki"))
	require.NoError(t, err)
	t.Cleanup(func() { _ = moduleConn.Close() })
	module := iamv1.NewInternalIAMServiceClient(moduleConn)
	_, err = module.RegisterResource(f.given.ctx, &iamv1.RegisterResourceRequest{
		SubjectId: "project:" + project, Relation: "project", Object: "registry_child_probe_container:" + parentID,
		ParentProjectId: project, ParentAccountId: f.tenantID,
		ParentChain: []string{"project:" + project, "account:" + f.tenantID}, SourceVersion: timestamppb.Now(),
	})
	require.NoError(t, err)
	var roleID string
	for _, raw := range f.ridList(t, "/iam/v1/roles", "roles", nil) {
		var role iamv1.Role
		require.NoError(t, protojson.Unmarshal(raw, &role))
		if role.Name == "registry.child_public_registrar" {
			require.Empty(t, roleID)
			roleID = role.Id
		}
	}
	require.NotEmpty(t, roleID)
	binding := ridResponseID(t, f.ridOperation(t, http.MethodPost, "/iam/v1/accessBindings", f.operator.Bearer(), map[string]any{
		"subjectType": "user", "subjectId": f.operator.UserID(), "roleId": roleID,
		"scopeType": "iam.account", "scopeId": f.tenantID,
		"target": map[string]any{"resources": map[string]any{"resources": []any{
			map[string]any{"type": "registry.childProbeContainers", "id": parentID},
		}}},
	}, 0))
	// Ждём факт именно этой привязки. Проверка Check для cluster admin
	// может дать доступ и без материализации нового правила.
	require.EventuallyWithT(t, func(c *assert.CollectT) {
		ctx, cancel := context.WithTimeout(f.given.ctx, time.Second)
		defer cancel()
		var materialized bool
		require.NoError(c, f.given.pool.QueryRow(ctx, `SELECT EXISTS (
 SELECT 1 FROM kaname.access_binding_emitted_tuples e
 JOIN kaname.relation_fact f ON f.object_type='registry_child_probe_container'
 AND f.object_id=$2 AND f.relation=e.relation AND f.subject=e.fga_user
 WHERE e.binding_id=$1 AND e.fga_user=$3 AND e.relation='child_registrar'
 AND e.object='registry_child_probe_container:'||$2 AND e.source='member')`,
			binding, parentID, "user:"+f.operator.UserID()).Scan(&materialized))
		require.True(c, materialized, "штатный факт child_registrar должен принадлежать этой привязке")
	}, 30*time.Second, 50*time.Millisecond)
	var response json.RawMessage
	code, err := f.wire.JSON(f.given.ctx, http.MethodPost, "/iam/v1/childRegistrations:register", f.operator.Bearer(),
		map[string]any{"resourceType": "registry.childProbeChildren", "resourceId": childID}, &response)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)
	var created iamv1.RegisterChildResponse
	require.NoError(t, protojson.Unmarshal(response, &created))
	require.NotNil(t, created.GetVersion())
	require.NoError(t, created.GetVersion().CheckValid())

	// Прямой публичный gRPC предъявляет только настоящий bearer. Здесь нет
	// GatewayContext, metadata principal или допускающего interceptor-дублёра.
	publicConn := childNativePublicGRPC(t, filepath.Join(f.session.Root, "pki"))
	ctx := metadata.AppendToOutgoingContext(f.given.ctx, "authorization", "Bearer "+f.operator.Bearer())
	replayed, err := iamv1.NewChildRegistrationServiceClient(publicConn).Register(ctx,
		&iamv1.RegisterChildRequest{ResourceType: "registry.childProbeChildren", ResourceId: childID})
	require.NoError(t, err)
	require.True(t, created.Version.AsTime().Equal(replayed.GetVersion().AsTime()))
	var version time.Time
	var account, actualProject, actor string
	var chain []string
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT source_version,parent_account_id,parent_project_id,
 (SELECT array_agg(parent_type||':'||parent_id ORDER BY depth) FROM kaname.resource_parent_edge
 WHERE object_type='registry_child_probe_child' AND object_id=$1)
 FROM kaname.resource_mirror WHERE object_type='registry.childProbeChildren' AND object_id=$1`, childID).
		Scan(&version, &account, &actualProject, &chain))
	require.True(t, version.Equal(created.Version.AsTime()))
	require.Equal(t, f.tenantID, account)
	require.Equal(t, project, actualProject)
	require.Equal(t, []string{"registry_child_probe_container:" + parentID, "project:" + project, "account:" + f.tenantID}, chain)
	var scopes, facts, expectedFacts, receipts, audits int
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT
 (SELECT count(*) FROM kaname.resource_registration_scope WHERE object_type='registry_child_probe_child' AND object_id=$1 AND account_id=$2 AND project_id=$3),
 (SELECT count(*) FROM kaname.relation_fact WHERE object_type='registry_child_probe_child' AND object_id=$1),
 (SELECT count(*) FROM kaname.relation_fact WHERE object_type='registry_child_probe_child' AND object_id=$1 AND relation='parent' AND subject=$4 AND source_version=$5),
 (SELECT count(*) FROM kaname.authority_child_creation WHERE child_type='registry.childProbeChildren' AND child_id=$1 AND user_id=$6 AND source_version=$5),
 (SELECT count(*) FROM kaname.audit_outbox WHERE event_payload#>>'{object,id}'=$1),
 (SELECT event_payload->>'actor' FROM kaname.audit_outbox WHERE event_payload#>>'{object,id}'=$1 LIMIT 1)`,
		childID, f.tenantID, project, "registry_child_probe_container:"+parentID, version, f.operator.UserID()).
		Scan(&scopes, &facts, &expectedFacts, &receipts, &audits, &actor))
	require.Equal(t, 1, scopes)
	require.Equal(t, 1, facts)
	require.Equal(t, 1, expectedFacts)
	require.Equal(t, 1, receipts)
	require.Equal(t, 1, audits)
	require.Equal(t, "user:"+f.operator.UserID(), actor)
}

// Сохраняем существующий независимый registry fixture и добавляем только
// пробные типы/роль. Реальная служба svc-registry этому миру не требуется.
func childNativePublicDelivery(t *testing.T) installruntime.RIDDeliveryFixture {
	t.Helper()
	delivery := ridLifecycleDelivery(t, false)
	var doc, extra map[string]any
	require.NoError(t, yaml.Unmarshal(delivery.First, &doc))
	require.NoError(t, yaml.Unmarshal([]byte(`resources:
  - name: childProbeContainers
    objectType: registry_child_probe_container
    parents: [project]
    producer: authored
    verbs: [get]
    relations:
      - {name: child_registrar, definition: "[user]"}
  - name: childProbeChildren
    objectType: registry_child_probe_child
    parents:
      - {name: parent, type: registry_child_probe_container}
    producer: authored
    verbs: [get]
    containerVerbs:
      - {name: registerChild, parent: parent, relation: child_registrar}
    childRegistration:
      verb: registerChild
      parentSegments: 1
      maxChildren: 4
      maxCreates: 4
      windowSeconds: 60
roles:
  - id: registry.child_public_registrar
    description: Independent public child registration probe
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: registry
        resources: [childProbeContainers]
        classes: [get]
        children:
          - resources: [childProbeChildren]
            classes: [registerChild]
`), &extra))
	for _, key := range []string{"resources", "roles"} {
		base, ok := doc[key].([]any)
		require.True(t, ok)
		added, ok := extra[key].([]any)
		require.True(t, ok)
		doc[key] = append(base, added...)
	}
	var err error
	delivery.First, err = yaml.Marshal(doc)
	require.NoError(t, err)
	_, err = manifest.Load(delivery.First)
	require.NoError(t, err)
	return delivery
}

func childNativePublicGRPC(t *testing.T, pki string) *grpc.ClientConn {
	t.Helper()
	ca, err := os.ReadFile(filepath.Join(pki, "ca.crt"))
	require.NoError(t, err)
	roots := x509.NewCertPool()
	require.True(t, roots.AppendCertsFromPEM(ca))
	leaf, err := tls.LoadX509KeyPair(filepath.Join(pki, "srv.crt"), filepath.Join(pki, "srv.key"))
	require.NoError(t, err)
	conn, err := grpc.NewClient("localhost:9090", grpc.WithTransportCredentials(credentials.NewTLS(&tls.Config{
		RootCAs: roots, Certificates: []tls.Certificate{leaf}, ServerName: "localhost", MinVersion: tls.VersionTLS12,
	})))
	require.NoError(t, err)
	t.Cleanup(func() { _ = conn.Close() })
	return conn
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

type resourceBindingPredicateRow bool

func (r resourceBindingPredicateRow) Scan(dest ...any) error { *dest[0].(*bool) = bool(r); return nil }

type resourceRegistrationPrepareTx struct {
	pgx.Tx
	conn    *pgx.Conn
	refuses bool
	queries int
}

func (t *resourceRegistrationPrepareTx) Conn() *pgx.Conn { return t.conn }
func (t *resourceRegistrationPrepareTx) QueryRow(context.Context, string, ...any) pgx.Row {
	t.queries++
	return resourceBindingPredicateRow(t.refuses)
}
func resourceRegistrationPrepareFixture(t *testing.T) (*resourceParentCapture, *resourceRegistrationPrepareTx, resourceModuleIdentity, kaname.ResourceDecisionIntent) {
	t.Helper()
	c := parentCaptureFixture(t)
	tx := &resourceRegistrationPrepareTx{conn: c.source.conn}
	c.tx = tx
	c.source.stageTX = tx
	parentCaptureObject(t, c, "object", "key", "project-old", domain.WritePolicy{Pointers: []domain.ParentPointer{{Name: "parent", Type: "project"}}})
	parentCaptureProject(t, c, "project-old", "account-old")
	parentCaptureProject(t, c, "project-new", "account-new")
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourceRegistrationScopes, typ: "object", id: "key"}, map[string]any{"project_id": "project-old", "account_id": "account-old"})
	module := resourceModuleIdentity{serviceName: "example", catalogModule: "example", actor: authzguard.ServiceAccountIDForService("example")}
	in := kaname.ResourceDecisionIntent{Action: kaname.ResourceDecisionRegister, Tuple: service.RelationTuple{User: "project:project-new", Relation: "parent", Object: "object:key"}, Mirror: service.ResourceMirrorRow{ObjectType: "object", ObjectID: "key"}}
	return c, tx, module, in
}
func TestResourceRegistrationPrepareRequiresBothOwnersWithoutActorHome(t *testing.T) {
	c, _, module, in := resourceRegistrationPrepareFixture(t)
	prepared, err := prepareResourceRegistration(context.Background(), c, module, in)
	require.NoError(t, err)
	fence, err := prepared.footprint.local()
	require.NoError(t, err)
	require.Equal(t, []domain.AccountID{"account-new", "account-old"}, fence.registration)
	require.Equal(t, []domain.AccountID{"account-new", "account-old"}, fence.plan.Accounts)
	require.Empty(t, prepared.row.ParentProjectID, "подготовка не дописывает claims из derived scope")
	require.Empty(t, prepared.row.ParentAccountID)
	require.Equal(t, "example.object", prepared.row.ObjectType)
}
func TestResourceRegistrationPreparePolicyDenialPrecedesHierarchyAndBinding(t *testing.T) {
	c, tx, module, in := resourceRegistrationPrepareFixture(t)
	c.catalogs["object"].rows[0].policy.Pointers = nil
	tx.refuses = true
	_, err := prepareResourceRegistration(context.Background(), c, module, in)
	require.Equal(t, codes.PermissionDenied, status.Code(err))
	require.Zero(t, tx.queries, "чужая тройка не узнаёт состояние project binding")
}
func TestResourceRegistrationPreparePreservesBindingRefusalPriority(t *testing.T) {
	c, tx, module, in := resourceRegistrationPrepareFixture(t)
	tx.refuses = true
	in.Mirror.ParentProjectID = "conflicting-claim"
	_, err := prepareResourceRegistration(context.Background(), c, module, in)
	require.ErrorIs(t, err, iamerr.ErrObjectBoundToOtherProject)
	refused, ok := iamerr.RefusedObjectOf(err)
	require.True(t, ok)
	require.Equal(t, "object", refused.ResourceType)
	require.Equal(t, "key", refused.ResourceID)
}
func TestResourceRegistrationPrepareRetiredPolicyCannotRegister(t *testing.T) {
	c, tx, module, in := resourceRegistrationPrepareFixture(t)
	c.catalogs["object"].rows[0].live = false
	_, err := prepareResourceRegistration(context.Background(), c, module, in)
	var field *kaname.ResourceDecisionFieldError
	require.ErrorAs(t, err, &field)
	require.Equal(t, "object", field.Field)
	require.Zero(t, tx.queries)
	in.Action = kaname.ResourceDecisionUnregister
	prepared, err := prepareResourceRegistration(context.Background(), c, module, in)
	require.NoError(t, err, "снятие использует сохранённый owner, а не live write policy")
	require.Equal(t, []domain.ContainerScope{{Registered: true, ProjectID: "project-old", AccountID: "account-old"}}, prepared.oldScopes)
	require.Empty(t, prepared.newScopes)
}
func TestResourceRegistrationPrepareUnknownOldScopeDoesNotAuthorizeMove(t *testing.T) {
	c, _, module, in := resourceRegistrationPrepareFixture(t)
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourceRegistrationScopes, typ: "object", id: "key"})
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourceProject, typ: "project", id: "project-old"})
	_, err := prepareResourceRegistration(context.Background(), c, module, in)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed, "живое зеркало с утраченным OLD owner не подменяется NEW account")
}

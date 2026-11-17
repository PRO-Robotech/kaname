// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Эти пробы проверяют канонический вывод, а не native allow. Все строки заданы
// как завершённый RR capture; отсутствующий fixture-ключ не вызывает fake SQL.
func parentCaptureFixture(t *testing.T) *resourceParentCapture {
	t.Helper()
	tx := &resourceInstallationTx{conn: new(pgx.Conn)}
	lifetime, err := newResourceAttemptLifetime(tx.conn, nativeBoundaryBundle(t))
	require.NoError(t, err)
	source, err := newResourceSourceCapture(tx, &relverdict.AdministrativeReadBudget{}, lifetime)
	require.NoError(t, err)
	parent, err := newResourceParentCapture(tx, source)
	require.NoError(t, err)
	return parent
}
func parentCaptureRows(t *testing.T, c *resourceParentCapture, k resourceSourceKey, values ...any) {
	t.Helper()
	rows := make([]resourceSourceRow, 0, len(values))
	for _, value := range values {
		raw, err := json.Marshal(value)
		require.NoError(t, err)
		rows = append(rows, resourceSourceRow{state: string(raw), value: raw})
	}
	c.source.entries[k] = rows
}
func parentCaptureObject(t *testing.T, c *resourceParentCapture, typ, id, project string, policy domain.WritePolicy) {
	t.Helper()
	policy.ObjectType = typ
	dotted := "example." + typ
	c.catalogs[typ] = &resourceCatalogCapture{input: typ, rows: []resourceCatalogRow{{identity: domain.CatalogTypeIdentity{Dotted: dotted, Module: "example", ObjectType: typ}, live: true, policy: policy}}}
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourceMirror, typ: dotted, id: id}, map[string]any{"parent_project_id": project})
	for _, kind := range []resourceSourceKind{resourceSourceParentEdges, resourceSourceRegistrationScopes, resourceSourceProjectBinding, resourceSourcePointerFacts} {
		parentCaptureRows(t, c, resourceSourceKey{kind: kind, typ: typ, id: id})
	}
}
func parentCaptureProject(t *testing.T, c *resourceParentCapture, id, account string) {
	t.Helper()
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourceProject, typ: "project", id: id}, map[string]any{"id": id, "account_id": account})
}
func TestResourceParentCaptureOmittedProjectionKeepsCanonicalAuthority(t *testing.T) {
	c := parentCaptureFixture(t)
	parentCaptureObject(t, c, "folder", "container", "", domain.WritePolicy{})
	parentCaptureProject(t, c, "project-a", "account-a")
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourceRegistrationScopes, typ: "folder", id: "container"}, map[string]any{"project_id": "project-a", "account_id": "old-account-claim"})
	policy := domain.WritePolicy{ObjectType: "object", Pointers: []domain.ParentPointer{{Name: "folder", Type: "folder"}}}
	hs, scopes, err := c.derive(context.Background(), "folder:container", "folder", "object:key", policy, domain.ParentClaim{})
	require.NoError(t, err)
	require.Equal(t, []domain.ParentHierarchy{{Links: []string{"folder:container"}}}, hs, "saved authority не дописывает пропущенную иерархию")
	require.Equal(t, []domain.ContainerScope{{Registered: true, ProjectID: "project-a", AccountID: "account-a"}}, scopes, "аккаунт берётся из текущей строки проекта, не сохранённой claim колонки")
	_, _, err = c.derive(context.Background(), "folder:container", "folder", "object:key", policy, domain.ParentClaim{ProjectID: "project-a"})
	require.Error(t, err, "пустая проекция контейнера не принимает утверждение о проекте")
}
func TestResourceParentCaptureKeepsOldAndNewOwnerAccounts(t *testing.T) {
	c := parentCaptureFixture(t)
	parentCaptureObject(t, c, "object", "key", "project-old", domain.WritePolicy{})
	parentCaptureProject(t, c, "project-old", "account-old")
	parentCaptureProject(t, c, "project-new", "account-new")
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourceRegistrationScopes, typ: "object", id: "key"}, map[string]any{"project_id": "project-old", "account_id": "account-old"})
	old, err := c.savedScopes(context.Background(), "object", "key")
	require.NoError(t, err)
	policy := domain.WritePolicy{ObjectType: "object", Pointers: []domain.ParentPointer{{Name: "parent", Type: "project"}}}
	_, current, err := c.derive(context.Background(), "project:project-new", "parent", "object:key", policy, domain.ParentClaim{})
	require.NoError(t, err)
	footprint := newResourceFootprint()
	require.NoError(t, footprint.addRegistrationScopes(old))
	require.NoError(t, footprint.addRegistrationScopes(current))
	require.NoError(t, footprint.addObject(domain.ResourceRef{Type: "example.object", ID: "key"}))
	require.NoError(t, footprint.addCarrier("binding", "binding-foreign", []domain.AccountID{"account-carrier"}))
	frozen, err := footprint.local()
	require.NoError(t, err)
	require.Equal(t, []domain.AccountID{"account-new", "account-old"}, frozen.registration)
	require.Equal(t, []domain.AccountID{"account-carrier", "account-new", "account-old"}, frozen.plan.Accounts)
}
func TestResourceParentCaptureLegacyCycleRetainsReachableProject(t *testing.T) {
	c := parentCaptureFixture(t)
	policy := domain.WritePolicy{Pointers: []domain.ParentPointer{{Name: "parent", Type: "folder"}, {Name: "project", Type: "project"}}}
	parentCaptureObject(t, c, "folder", "one", "", policy)
	parentCaptureObject(t, c, "folder", "two", "", policy)
	parentCaptureProject(t, c, "project-a", "account-a")
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourcePointerFacts, typ: "folder", id: "one"}, map[string]any{"subject": "folder:two", "relation": "parent"})
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourcePointerFacts, typ: "folder", id: "two"}, map[string]any{"subject": "folder:one", "relation": "parent"}, map[string]any{"subject": "project:project-a", "relation": "project"}, map[string]any{"subject": "project:foreign", "relation": "parent"})
	scopes, err := c.savedScopes(context.Background(), "folder", "one")
	require.NoError(t, err)
	require.Equal(t, []domain.ContainerScope{{Registered: true, ProjectID: "project-a", AccountID: "account-a"}}, scopes)
	_, readForeign := c.source.entries[resourceSourceKey{kind: resourceSourceProject, typ: "project", id: "foreign"}]
	require.False(t, readForeign, "тип указателя обязан совпасть с каталогом; foreign claim не читается как authority")
}
func TestResourceParentCaptureMissingProjectNeverBorrowsStoredAccount(t *testing.T) {
	c := parentCaptureFixture(t)
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourceRegistrationScopes, typ: "object", id: "key"}, map[string]any{"project_id": "gone", "account_id": "account-a"})
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourceProject, typ: "project", id: "gone"})
	scopes, err := c.savedScopes(context.Background(), "object", "key")
	require.NoError(t, err)
	require.ErrorIs(t, newResourceFootprint().addRegistrationScopes(scopes), kaname.ErrSourceUnconfirmed)
	require.Empty(t, scopes[0].AccountID)
}

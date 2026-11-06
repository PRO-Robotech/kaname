// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
	_ "github.com/PRO-Robotech/kaname/internal/dto/toproto"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type rid09PrimaryRow map[string]json.RawMessage

// Замкнутая перепись уровня исходников не выводится из случайно видимых публичных
// ответов. Каждая таблица читается без фильтров в одной первичной транзакции RR.
type rid09NewmanProjection struct {
	Accounts        []map[string]any            `json:"accounts"`
	ServiceAccounts []map[string]any            `json:"serviceAccounts"`
	Groups          []map[string]any            `json:"groups"`
	Members         map[string][]map[string]any `json:"members"`
	Roles           []map[string]any            `json:"roles"`
	Bindings        []map[string]any            `json:"bindings"`
	Delegations     []map[string]any            `json:"delegations"`
	Catalog         map[string]any              `json:"catalog"`
	Materialization string                      `json:"-"`
}

func rid09PrimaryValue[T any](t *testing.T, r rid09PrimaryRow, key string) T {
	t.Helper()
	require.Contains(t, r, key, "primary schema missing required field")
	var v T
	require.NoError(t, json.Unmarshal(r[key], &v))
	return v
}
func rid09PrimaryRows(t *testing.T, ctx context.Context, tx pgx.Tx, table string) []rid09PrimaryRow {
	t.Helper()
	rows, err := tx.Query(ctx, "SELECT to_jsonb(r) FROM "+pgx.Identifier{"kaname", table}.Sanitize()+" r ORDER BY to_jsonb(r)::text")
	require.NoError(t, err)
	defer rows.Close()
	out := []rid09PrimaryRow{}
	for rows.Next() {
		var raw []byte
		require.NoError(t, rows.Scan(&raw))
		var r rid09PrimaryRow
		require.NoError(t, json.Unmarshal(raw, &r))
		out = append(out, r)
	}
	require.NoError(t, rows.Err())
	return out
}
func rid09PrimaryJSON(t *testing.T, m proto.Message) map[string]any {
	t.Helper()
	// Штатный JSONPb grpc-gateway выдаёт незаполненные поля без признака optional. Это
	// сериализация независимо прочитанных первичных доменных значений, без обработчика.
	raw, err := (protojson.MarshalOptions{EmitUnpopulated: true}).Marshal(m)
	require.NoError(t, err)
	var out map[string]any
	require.NoError(t, json.Unmarshal(raw, &out))
	return out
}
func rid09ReadNewmanProjection(t *testing.T, f *installationNativeWorld) rid09NewmanProjection {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.given.ctx, 30*time.Second)
	defer cancel()
	return rid09ReadNewmanProjectionContext(t, ctx, f)
}

// Точка входа с контекстом для принадлежащего вызывающему общего бюджета наблюдения.
// Существующие вызывающие RID09 сохраняют исходную обёртку 30s. Весь SQL/преобразование
// общие; внутренний контекст не сбрасывает и не продлевает срок вызывающего.
func rid09ReadNewmanProjectionContext(t *testing.T, ctx context.Context, f *installationNativeWorld) rid09NewmanProjection {
	t.Helper()
	require.NoError(t, ctx.Err(), "primary projection caller context expired")
	tx, err := f.given.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() {
		cctx, c := context.WithTimeout(context.Background(), time.Second)
		defer c()
		_ = tx.Rollback(cctx)
	}()
	var recovery bool
	require.NoError(t, tx.QueryRow(ctx, "SELECT pg_is_in_recovery()").Scan(&recovery))
	require.False(t, recovery)
	e := rid09NewmanProjection{Accounts: []map[string]any{}, ServiceAccounts: []map[string]any{}, Groups: []map[string]any{}, Members: map[string][]map[string]any{}, Roles: []map[string]any{}, Bindings: []map[string]any{}, Delegations: []map[string]any{}}
	for _, r := range rid09PrimaryRows(t, ctx, tx, "accounts") {
		d := domain.Account{ID: rid09PrimaryValue[domain.AccountID](t, r, "id"), Name: rid09PrimaryValue[domain.AccountName](t, r, "name"), Description: rid09PrimaryValue[domain.Description](t, r, "description"), Labels: rid09PrimaryValue[domain.Labels](t, r, "labels"), OwnerUserID: rid09PrimaryValue[domain.UserID](t, r, "owner_user_id"), CreatedAt: rid09PrimaryValue[time.Time](t, r, "created_at")}
		var pb *iamv1.Account
		require.NoError(t, dto.Transfer(dto.FromTo(d, &pb)))
		e.Accounts = append(e.Accounts, rid09PrimaryJSON(t, pb))
	}
	for _, r := range rid09PrimaryRows(t, ctx, tx, "service_accounts") {
		d := domain.ServiceAccount{ID: rid09PrimaryValue[domain.ServiceAccountID](t, r, "id"), AccountID: rid09PrimaryValue[domain.AccountID](t, r, "account_id"), Name: rid09PrimaryValue[domain.SvcAccountName](t, r, "name"), Description: rid09PrimaryValue[domain.Description](t, r, "description"), Labels: rid09PrimaryValue[domain.Labels](t, r, "labels"), CreatedAt: rid09PrimaryValue[time.Time](t, r, "created_at"), Enabled: rid09PrimaryValue[bool](t, r, "enabled")}
		var pb *iamv1.ServiceAccount
		require.NoError(t, dto.Transfer(dto.FromTo(d, &pb)))
		e.ServiceAccounts = append(e.ServiceAccounts, rid09PrimaryJSON(t, pb))
	}
	for _, r := range rid09PrimaryRows(t, ctx, tx, "groups") {
		d := domain.Group{ID: rid09PrimaryValue[domain.GroupID](t, r, "id"), AccountID: rid09PrimaryValue[domain.AccountID](t, r, "account_id"), Name: rid09PrimaryValue[domain.GroupName](t, r, "name"), Description: rid09PrimaryValue[domain.Description](t, r, "description"), Labels: rid09PrimaryValue[domain.Labels](t, r, "labels"), CreatedAt: rid09PrimaryValue[time.Time](t, r, "created_at")}
		var pb *iamv1.Group
		require.NoError(t, dto.Transfer(dto.FromTo(d, &pb)))
		e.Groups = append(e.Groups, rid09PrimaryJSON(t, pb))
		e.Members[string(d.ID)] = []map[string]any{}
	}
	for _, r := range rid09PrimaryRows(t, ctx, tx, "group_members") {
		d := domain.GroupMember{GroupID: rid09PrimaryValue[domain.GroupID](t, r, "group_id"), MemberType: rid09PrimaryValue[domain.SubjectType](t, r, "member_type"), MemberID: rid09PrimaryValue[domain.SubjectID](t, r, "member_id"), AddedAt: rid09PrimaryValue[time.Time](t, r, "added_at")}
		require.Contains(t, e.Members, string(d.GroupID))
		var pb *iamv1.GroupMember
		require.NoError(t, dto.Transfer(dto.FromTo(d, &pb)))
		e.Members[string(d.GroupID)] = append(e.Members[string(d.GroupID)], rid09PrimaryJSON(t, pb))
	}
	facts := rid09PrimaryCatalog(t, ctx, tx, &e)
	e.Roles = rid09PrimaryRoles(t, ctx, tx, facts)
	e.Bindings = rid09PrimaryBindings(t, ctx, tx)
	for _, r := range rid09PrimaryRows(t, ctx, tx, "grant_delegations") {
		d := domain.GrantDelegation{ID: rid09PrimaryValue[domain.GrantDelegationID](t, r, "id"), AccountID: rid09PrimaryValue[domain.AccountID](t, r, "account_id"), DelegateID: rid09PrimaryValue[domain.ServiceAccountID](t, r, "delegate_id"), RoleIDs: rid09PrimaryValue[[]domain.RoleID](t, r, "role_ids"), TargetTypes: rid09PrimaryValue[[]string](t, r, "target_types"), SubjectTypes: rid09PrimaryValue[[]domain.SubjectType](t, r, "subject_types"), Module: rid09PrimaryValue[string](t, r, "module"), Status: rid09PrimaryValue[domain.GrantDelegationStatus](t, r, "status"), CreatedAt: rid09PrimaryValue[time.Time](t, r, "created_at"), RevokedAt: rid09PrimaryValue[*time.Time](t, r, "revoked_at"), DelegatedBy: domain.GrantDelegationActor{Type: rid09PrimaryValue[string](t, r, "delegated_by_type"), ID: rid09PrimaryValue[string](t, r, "delegated_by_id")}}
		if kind := rid09PrimaryValue[*string](t, r, "revoked_by_type"); kind != nil {
			d.RevokedBy = &domain.GrantDelegationActor{Type: *kind, ID: rid09PrimaryValue[string](t, r, "revoked_by_id")}
		}
		var pb *iamv1.GrantDelegation
		require.NoError(t, dto.Transfer(dto.FromTo(d, &pb)))
		e.Delegations = append(e.Delegations, rid09PrimaryJSON(t, pb))
	}
	// Сохраняем полный безопасный журнал, включая нематериализованных членов. Движущееся
	// обогащение нельзя скрыть заменой MaterializedAt нулевым значением.
	e.Materialization = ridWholeDigest(t, rid09PrimaryRows(t, ctx, tx, "access_binding_target_members"))
	require.NoError(t, tx.Commit(ctx))
	require.NoError(t, ctx.Err(), "primary projection caller context expired before return")
	return e
}

func rid09PrimaryCatalog(t *testing.T, ctx context.Context, tx pgx.Tx, e *rid09NewmanProjection) *catalog.Facts {
	t.Helper()
	halves := catalog.Halves{}
	for _, r := range rid09PrimaryRows(t, ctx, tx, "catalog_module") {
		half := &halves.Live
		if !rid09PrimaryValue[bool](t, r, "live") {
			half = &halves.Retired
		}
		half.Modules = append(half.Modules, rid09PrimaryValue[string](t, r, "module"))
	}
	for _, r := range rid09PrimaryRows(t, ctx, tx, "catalog_resource") {
		d := catalog.ResourceRow{Module: rid09PrimaryValue[string](t, r, "module"), Resource: rid09PrimaryValue[string](t, r, "resource"), ObjectType: rid09PrimaryValue[string](t, r, "object_type")}
		half := &halves.Live
		if rid09PrimaryValue[bool](t, r, "live") {
			d.ParentTypes = rid09PrimaryValue[[]string](t, r, "parent_types")
			d.ParentNames = rid09PrimaryValue[[]string](t, r, "parent_names")
			d.Writes = rid09PrimaryValue[[]string](t, r, "writes")
			d.PublicReadToChildren = rid09PrimaryValue[bool](t, r, "public_read_to_children")
			d.PermanentProject = rid09PrimaryValue[bool](t, r, "permanent_project")
		} else {
			half = &halves.Retired
			d.SupersededBy = rid09PrimaryValue[string](t, r, "superseded_by")
		}
		half.Resources = append(half.Resources, d)
	}
	for _, r := range rid09PrimaryRows(t, ctx, tx, "catalog_verb") {
		d := catalog.VerbRow{Module: rid09PrimaryValue[string](t, r, "module"), Resource: rid09PrimaryValue[string](t, r, "resource"), Verb: rid09PrimaryValue[string](t, r, "verb"), PerObject: rid09PrimaryValue[bool](t, r, "per_object"), ContainerParent: rid09PrimaryValue[string](t, r, "container_parent"), ContainerRelation: rid09PrimaryValue[string](t, r, "container_relation")}
		half := &halves.Live
		if !rid09PrimaryValue[bool](t, r, "live") {
			half = &halves.Retired
		}
		half.Verbs = append(half.Verbs, d)
	}
	facts, err := catalog.NewFacts(halves)
	require.NoError(t, err)
	pb := &iamv1.ListPermissionCatalogResponse{Modules: []*iamv1.CatalogModule{}, RetiredResources: []*iamv1.RetiredResource{}, ClosedVerbs: domain.OrderVerbsForDisplay(facts.CommonVerbVocabulary()), WildcardPolicy: &iamv1.WildcardPolicy{VerbWildcardAllowedCustom: true, ModuleResourceWildcardSystemOnly: true}}
	for _, r := range facts.Resources() {
		if len(pb.Modules) == 0 || pb.Modules[len(pb.Modules)-1].Module != r.Module {
			pb.Modules = append(pb.Modules, &iamv1.CatalogModule{Module: r.Module})
		}
		verbs := facts.VerbsOfType(r.ObjectType)
		m := pb.Modules[len(pb.Modules)-1]
		m.Resources = append(m.Resources, &iamv1.CatalogResource{Resource: r.Resource, HasVerbRelations: len(verbs) > 0, HasListEndpoint: r.Module+"."+r.Resource != "vpc.addressPool", LabelSelectable: domain.IsLabelSelectableType(r.Module + "." + r.Resource), Verbs: domain.OrderVerbsForDisplay(verbs)})
	}
	for _, r := range facts.RetiredResources() {
		pb.RetiredResources = append(pb.RetiredResources, &iamv1.RetiredResource{Resource: r.Module + "." + r.Resource, SupersededBy: r.SupersededBy})
	}
	e.Catalog = rid09PrimaryJSON(t, pb)
	return facts
}

func rid09PrimaryBindings(t *testing.T, ctx context.Context, tx pgx.Tx) []map[string]any {
	t.Helper()
	out := []map[string]any{}
	subjects := map[string][]domain.Subject{}
	rows, err := tx.Query(ctx, `SELECT binding_id,subject_type,subject_id FROM kaname.access_binding_subjects ORDER BY binding_id,ordinal,subject_type,subject_id`)
	require.NoError(t, err)
	for rows.Next() {
		var id string
		var s domain.Subject
		require.NoError(t, rows.Scan(&id, (*string)(&s.Type), (*string)(&s.ID)))
		subjects[id] = append(subjects[id], s)
	}
	require.NoError(t, rows.Err())
	rows.Close()
	material := map[string]time.Time{}
	var observed time.Time
	require.NoError(t, tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&observed))
	rows, err = tx.Query(ctx, `SELECT binding_id,MAX(updated_at) FROM kaname.access_binding_target_members WHERE verification_status='ACTIVE' GROUP BY binding_id`)
	require.NoError(t, err)
	for rows.Next() {
		var id string
		var at time.Time
		require.NoError(t, rows.Scan(&id, &at))
		material[id] = at
	}
	require.NoError(t, rows.Err())
	rows.Close()
	for _, r := range rid09PrimaryRows(t, ctx, tx, "access_bindings") {
		d := domain.AccessBinding{ID: rid09PrimaryValue[domain.AccessBindingID](t, r, "id"), SubjectType: rid09PrimaryValue[domain.SubjectType](t, r, "subject_type"), SubjectID: rid09PrimaryValue[domain.SubjectID](t, r, "subject_id"), RoleID: rid09PrimaryValue[domain.RoleID](t, r, "role_id"), ResourceType: rid09PrimaryValue[domain.ResourceType](t, r, "resource_type"), ResourceID: rid09PrimaryValue[string](t, r, "resource_id"), Scope: rid09PrimaryValue[domain.Scope](t, r, "scope"), Status: rid09PrimaryValue[domain.AccessBindingStatus](t, r, "status"), ExpiresAt: rid09PrimaryValue[*time.Time](t, r, "expires_at"), GrantedByUserID: rid09PrimaryValue[domain.UserID](t, r, "granted_by_user_id"), RevokedAt: rid09PrimaryValue[*time.Time](t, r, "revoked_at"), RevokedByUserID: rid09PrimaryValue[*domain.UserID](t, r, "revoked_by_user_id"), CreatedAt: rid09PrimaryValue[time.Time](t, r, "created_at"), DeletionProtection: rid09PrimaryValue[bool](t, r, "deletion_protection"), Labels: rid09PrimaryValue[domain.Labels](t, r, "labels"), GrantedRelation: rid09PrimaryValue[string](t, r, "granted_relation"), System: rid09PrimaryValue[bool](t, r, "is_system"), RevocationReason: rid09PrimaryValue[domain.RevocationReason](t, r, "revocation_reason"), DelegationID: rid09PrimaryValue[domain.GrantDelegationID](t, r, "delegation_id")}
		d.Target, err = relverdict.DecodeTarget(r["target"])
		require.NoError(t, err)
		require.NotEmpty(t, subjects[string(d.ID)], "persisted complete subject set mandatory")
		d.Subjects = subjects[string(d.ID)]
		d.MaterializedAt = material[string(d.ID)]
		if !d.MaterializedAt.IsZero() {
			require.False(t, d.MaterializedAt.Before(d.CreatedAt))
			require.False(t, d.MaterializedAt.After(observed), "primary materialization cannot be in the future")
		}
		var pb *iamv1.AccessBinding
		require.NoError(t, dto.Transfer(dto.FromTo(d, &pb)))
		out = append(out, rid09PrimaryJSON(t, pb))
	}
	return out
}

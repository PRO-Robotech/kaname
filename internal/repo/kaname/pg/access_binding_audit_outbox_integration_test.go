// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// access_binding_audit_outbox_integration_test.go — интеграционные пробы контракта
// записи аудита audit_outbox в транзакции писателя access_bindings.
//
// Требование аудита P0: управляющий контур IAM ДОЛЖЕН надёжно сохранять,
// «кто, кому, какую роль, на какой ресурс и когда выдал» — наиболее значимый
// для безопасности факт системы управления доступом. До этой правки транзакция
// писателя выдачи/отзыва AccessBinding записывала только fga_outbox (синхронизация ReBAC) +
// subject_change_outbox (инвалидация кэша); ни один из них не служит надёжным
// журналом аудита. Этот файл закрепляет новое поведение:
//
//   - GRANT-EMIT: AccessBindingsW().Insert + EmitAuditEvent(granted) + Commit
//     оставляет ровно одну строку audit_outbox (event_type='iam.access_binding.granted')
//     с полями actor / subject / resource / role_id / binding_id в полезной нагрузке.
//   - REVOKE-EMIT: AccessBindingsW().Delete + EmitAuditEvent(revoked) + Commit
//     оставляет ровно одну строку audit_outbox (event_type='iam.access_binding.revoked').
//   - ROLLBACK: откат транзакции писателя удаляет и строку audit_outbox
//     (запрет #10 — атомарная запись в транзакции, без осиротевших строк аудита).

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"

	coredb "github.com/PRO-Robotech/corelib/db"
	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	repoab "github.com/PRO-Robotech/kaname/internal/repo/kaname/access_binding"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/PRO-Robotech/kaname/internal/testsupport/bindingset"
)

// countAuditRows возвращает число строк audit_outbox, у которых binding_id
// в полезной нагрузке совпадает с переданным id выдачи (ограничивает проверки
// строкой пробы, исключая любые строки аудита начального посева).
func countAuditRows(ctx context.Context, t *testing.T, pool *pgxpool.Pool, bindingID string) int {
	t.Helper()
	var n int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.audit_outbox WHERE event_payload->>'binding_id' = $1`,
		bindingID).Scan(&n))
	return n
}

func TestAB_AuditOutboxTx_GrantEmitsGrantedRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "aud01g")
	acc := seedAccount(t, ctx, repo, "acc-aud01-grant", uid)

	bindingID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	binding := domain.AccessBinding{
		ID:              bindingID,
		SubjectType:     domain.SubjectTypeUser,
		SubjectID:       domain.SubjectID(uid),
		RoleID:          domain.SystemViewerRoleID,
		ResourceType:    "account",
		ResourceID:      string(acc.ID),
		GrantedByUserID: uid,
	}
	ev := repoab.AuditEvent{
		EventType:       repoab.AuditEventTypeGranted,
		Actor:           string(uid),
		SubjectType:     string(binding.SubjectType),
		SubjectID:       string(binding.SubjectID),
		ResourceType:    string(binding.ResourceType),
		ResourceID:      binding.ResourceID,
		RoleID:          string(binding.RoleID),
		BindingID:       string(binding.ID),
		TenantAccountID: string(acc.ID),
	}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = bindingset.Insert(ctx, w.AccessBindingsW(), binding)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().EmitAuditEvent(ctx, ev))
	require.NoError(t, w.Commit(ctx))

	// Ровно одна строка аудита для этой выдачи.
	require.Equal(t, 1, countAuditRows(ctx, t, pool, string(bindingID)),
		"grant must emit exactly one audit_outbox row")

	var (
		eventType  string
		tenant     string
		payloadRaw string
		status     string
	)
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type, tenant_account_id, event_payload::text, status
		   FROM kaname.audit_outbox
		  WHERE event_payload->>'binding_id' = $1`, string(bindingID)).
		Scan(&eventType, &tenant, &payloadRaw, &status))

	require.Equal(t, "iam.access_binding.granted", eventType)
	require.Equal(t, string(acc.ID), tenant, "tenant_account_id carried for compliance scoping")
	require.Equal(t, "pending", status, "fresh audit row starts pending for the drainer")

	var payload map[string]string
	require.NoError(t, json.Unmarshal([]byte(payloadRaw), &payload))
	require.Equal(t, string(uid), payload["actor"])
	require.Equal(t, string(uid), payload["subject_id"])
	require.Equal(t, "user", payload["subject_type"])
	require.Equal(t, "account", payload["resource_type"])
	require.Equal(t, string(acc.ID), payload["resource_id"])
	require.Equal(t, domain.SystemViewerRoleID, payload["role_id"])
	require.Equal(t, string(bindingID), payload["binding_id"])
}

func TestAB_AuditOutboxTx_RevokeEmitsRevokedRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "aud02r")
	acc := seedAccount(t, ctx, repo, "acc-aud02-revoke", uid)
	binding := insertAB(t, ctx, repo, domain.AccessBinding{
		SubjectType:     domain.SubjectTypeUser,
		SubjectID:       domain.SubjectID(uid),
		RoleID:          domain.SystemViewerRoleID,
		ResourceType:    "account",
		ResourceID:      string(acc.ID),
		GrantedByUserID: uid,
	})

	ev := repoab.AuditEvent{
		EventType:       repoab.AuditEventTypeRevoked,
		Actor:           string(uid),
		SubjectType:     string(binding.SubjectType),
		SubjectID:       string(binding.SubjectID),
		ResourceType:    string(binding.ResourceType),
		ResourceID:      binding.ResourceID,
		RoleID:          string(binding.RoleID),
		BindingID:       string(binding.ID),
		TenantAccountID: string(acc.ID),
	}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().Delete(ctx, binding.ID))
	require.NoError(t, w.AccessBindingsW().EmitAuditEvent(ctx, ev))
	require.NoError(t, w.Commit(ctx))

	require.Equal(t, 1, countAuditRows(ctx, t, pool, string(binding.ID)),
		"revoke must emit exactly one audit_outbox row")

	var eventType string
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT event_type FROM kaname.audit_outbox
		  WHERE event_payload->>'binding_id' = $1`, string(binding.ID)).Scan(&eventType))
	require.Equal(t, "iam.access_binding.revoked", eventType)
}

// TestAB_AuditOutboxTx_RollbackDiscardsAuditRow — запрет #10:
// откат транзакции писателя ДОЛЖЕН удалять и записанную строку audit_outbox.
// Подтверждает атомарность события аудита с доменным изменением (при откате
// выдачи ни одна строка аудита не утверждает, что выдача состоялась).
func TestAB_AuditOutboxTx_RollbackDiscardsAuditRow(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping integration test")
	}
	ctx := context.Background()
	dsn := setupTestDB(t)
	pool, err := coredb.NewPool(ctx, dsn)
	require.NoError(t, err)
	defer pool.Close()
	repo := kanamepg.New(pool, nil)

	uid := mustSeedUser(t, ctx, pool, "aud03rb")
	acc := seedAccount(t, ctx, repo, "acc-aud03-rollback", uid)

	bindingID := domain.AccessBindingID(ids.NewID(domain.PrefixAccessBinding))
	binding := domain.AccessBinding{
		ID:              bindingID,
		SubjectType:     domain.SubjectTypeUser,
		SubjectID:       domain.SubjectID(uid),
		RoleID:          domain.SystemViewerRoleID,
		ResourceType:    "account",
		ResourceID:      string(acc.ID),
		GrantedByUserID: uid,
	}
	ev := repoab.AuditEvent{
		EventType:       repoab.AuditEventTypeGranted,
		Actor:           string(uid),
		SubjectType:     string(binding.SubjectType),
		SubjectID:       string(binding.SubjectID),
		ResourceType:    string(binding.ResourceType),
		ResourceID:      binding.ResourceID,
		RoleID:          string(binding.RoleID),
		BindingID:       string(binding.ID),
		TenantAccountID: string(acc.ID),
	}

	w, err := repo.Writer(ctx)
	require.NoError(t, err)
	_, err = bindingset.Insert(ctx, w.AccessBindingsW(), binding)
	require.NoError(t, err)
	require.NoError(t, w.AccessBindingsW().EmitAuditEvent(ctx, ev))
	require.NoError(t, w.Rollback(ctx)) // явный откат

	// Ни строка выдачи, ни строка audit_outbox не должны быть видимы.
	var bindingCount int
	require.NoError(t, pool.QueryRow(ctx,
		`SELECT count(*) FROM kaname.access_bindings WHERE id = $1`,
		string(bindingID)).Scan(&bindingCount))
	require.Equal(t, 0, bindingCount, "binding row must be rolled back")

	require.Equal(t, 0, countAuditRows(ctx, t, pool, string(bindingID)),
		"audit_outbox row must be rolled back atomically with the binding row")
}

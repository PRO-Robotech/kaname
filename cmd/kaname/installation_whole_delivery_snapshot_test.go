// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"sort"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/stretchr/testify/require"
)

// Every physical kaname table is discovered from the primary, not a selected
// account or live-only subset. Complete canonical rows are hashed in memory:
// receipts must not persist private key/token/session material from auth tables.
// The precise permitted bookkeeping separation is recorded, never silently lost.
type ridWholeTable struct {
	Columns []string `json:"columns"`
	Rows    []string `json:"rowSHA256"`
}

// Raw includes stated_at, all original columns and complete row fingerprints.
// Semantic removes ONLY stated_at; unknown future fields remain in its digest.
type ridWholeOwnCeilings struct {
	Raw      ridWholeTable        `json:"raw"`
	Semantic map[string]string    `json:"semanticRowSHA256ByKind"`
	StatedAt map[string]time.Time `json:"statedAtByKind"`
}
type ridWholeDeliverySnapshot struct {
	PrimaryStartedAt  time.Time                `json:"primaryStartedAt"`
	PrimaryFinishedAt time.Time                `json:"primaryFinishedAt"`
	OwnCeilings       ridWholeOwnCeilings      `json:"ownCeilings"`
	Delivery          map[string]ridWholeTable `json:"delivery"`
	Bookkeeping       map[string]ridWholeTable `json:"bookkeeping"`
	Separation        map[string]string        `json:"separation"`
}

var ridWholeBookkeeping = map[string]string{
	"audit_outbox":                "audit delivery/retention is not installation domain state",
	"client_assertion_replay":     "normal assertion replay admission",
	"access_tokens":               "normal issued access-token bookkeeping",
	"authorization_codes":         "ordinary O code exchange",
	"refresh_tokens":              "ordinary O refresh issuance",
	"token_families":              "ordinary O token-family bookkeeping",
	"human_sessions":              "normal presented-session activity",
	"human_first_authentications": "normal authentication bookkeeping",
	"login_failures":              "normal authentication refusal bookkeeping",
	"operations":                  "normal Operation ledger; installation Operations checked separately",
}

func ridReadWholeDelivery(t *testing.T, f *installationNativeWorld) ridWholeDeliverySnapshot {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.given.ctx, 20*time.Second)
	defer cancel()
	tx, err := f.given.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.RepeatableRead, AccessMode: pgx.ReadOnly})
	require.NoError(t, err)
	defer func() {
		closeCtx, c := context.WithTimeout(context.Background(), time.Second)
		defer c()
		_ = tx.Rollback(closeCtx)
	}()
	var recovery bool
	var started time.Time
	require.NoError(t, tx.QueryRow(ctx, "SELECT pg_is_in_recovery(),clock_timestamp()").Scan(&recovery, &started))
	require.False(t, recovery, "whole-delivery oracle is PRIMARY")
	rs, err := tx.Query(ctx, `SELECT c.relname FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND c.relkind IN ('r','p') ORDER BY c.relname`)
	require.NoError(t, err)
	var tables []string
	for rs.Next() {
		var name string
		require.NoError(t, rs.Scan(&name))
		tables = append(tables, name)
	}
	require.NoError(t, rs.Err())
	rs.Close()
	out := ridWholeDeliverySnapshot{PrimaryStartedAt: started, OwnCeilings: ridWholeOwnCeilings{Semantic: map[string]string{}, StatedAt: map[string]time.Time{}}, Delivery: map[string]ridWholeTable{}, Bookkeeping: map[string]ridWholeTable{}, Separation: map[string]string{}}
	for _, table := range tables {
		col, err := tx.Query(ctx, `SELECT a.attname FROM pg_attribute a JOIN pg_class c ON c.oid=a.attrelid JOIN pg_namespace n ON n.oid=c.relnamespace WHERE n.nspname='kaname' AND c.relname=$1 AND a.attnum>0 AND NOT a.attisdropped ORDER BY a.attnum`, table)
		require.NoError(t, err)
		entry := ridWholeTable{Columns: []string{}, Rows: []string{}}
		for col.Next() {
			var name string
			require.NoError(t, col.Scan(&name))
			entry.Columns = append(entry.Columns, name)
		}
		require.NoError(t, col.Err())
		col.Close()
		require.NotEmpty(t, entry.Columns)
		// Identifier quoting is driven by actual catalog names; no predicate filters
		// account, status, live/retired rows, seed origin, creator, or module.
		rows, err := tx.Query(ctx, `SELECT to_jsonb(r)::text FROM `+pgx.Identifier{"kaname", table}.Sanitize()+` r ORDER BY to_jsonb(r)::text`)
		require.NoError(t, err)
		for rows.Next() {
			var raw []byte
			require.NoError(t, rows.Scan(&raw))
			sum := sha256.Sum256(raw)
			entry.Rows = append(entry.Rows, hex.EncodeToString(sum[:]))
			if table == "own_ceilings" {
				var fields map[string]json.RawMessage
				require.NoError(t, json.Unmarshal(raw, &fields))
				var kind *string
				var limit *int64
				var stated *time.Time
				require.NoError(t, json.Unmarshal(fields["kind"], &kind))
				require.NotNil(t, kind)
				require.NotEmpty(t, *kind)
				require.NoError(t, json.Unmarshal(fields["limit_value"], &limit))
				require.NotNil(t, limit)
				require.GreaterOrEqual(t, *limit, int64(0))
				require.NoError(t, json.Unmarshal(fields["stated_at"], &stated))
				require.NotNil(t, stated)
				require.False(t, stated.IsZero())
				require.NotContains(t, out.OwnCeilings.Semantic, *kind)
				out.OwnCeilings.StatedAt[*kind] = *stated
				delete(fields, "stated_at") // sole approved diagnostic-only boot timestamp
				semantic, err := json.Marshal(fields)
				require.NoError(t, err)
				digest := sha256.Sum256(semantic)
				out.OwnCeilings.Semantic[*kind] = hex.EncodeToString(digest[:])
			}
		}
		require.NoError(t, rows.Err())
		rows.Close()
		sort.Strings(entry.Rows)
		if table == "own_ceilings" {
			out.OwnCeilings.Raw = entry
		} else if reason, ok := ridWholeBookkeeping[table]; ok {
			out.Bookkeeping[table] = entry
			out.Separation[table] = reason
		} else {
			out.Delivery[table] = entry
		}
	}
	// Producer inventory: catalog_writer, role_repo/withdrawal, module_seed_writer,
	// ordinary SA/group/AB/GD/admin/account writers and their projection ledgers.
	// New tables are INCLUDED by default; removal of a required table fails.
	for _, table := range []string{"catalog_module", "catalog_resource", "catalog_verb", "roles", "role_rule_ref", "role_rule_selectors", "role_selector_verbs_pending", "role_verb", "role_grant_orphan", "role_selector_prune", "service_accounts", "service_account_oauth_clients", "groups", "group_members", "access_bindings", "access_binding_subjects", "access_binding_target_members", "access_binding_emitted_tuples", "grant_delegations", "cluster_admin_grants", "account_admission_rate_limits", "accounts", "users", "memberships", "relation_fact", "resource_mirror", "resource_parent_edge", "resource_journal", "public_read_publication", "fga_outbox", "resource_reconcile_outbox", "subject_change_outbox"} {
		require.Contains(t, out.Delivery, table)
	}
	require.Contains(t, out.Bookkeeping, "operations")
	require.NotEmpty(t, out.OwnCeilings.Semantic, "boot policy must not disappear from the census")
	require.Len(t, out.OwnCeilings.Raw.Rows, len(out.OwnCeilings.Semantic))
	require.Contains(t, out.OwnCeilings.Raw.Columns, "kind")
	require.Contains(t, out.OwnCeilings.Raw.Columns, "limit_value")
	require.Contains(t, out.OwnCeilings.Raw.Columns, "stated_at")
	require.NoError(t, tx.QueryRow(ctx, "SELECT clock_timestamp()").Scan(&out.PrimaryFinishedAt))
	require.False(t, out.PrimaryFinishedAt.Before(out.PrimaryStartedAt))
	require.NoError(t, tx.Commit(ctx))
	require.NoError(t, ctx.Err())
	return out
}
func ridRequireWholeDeliveryUnchanged(t *testing.T, before, after ridWholeDeliverySnapshot) {
	t.Helper()
	ridRequireOwnCeilingsPreserved(t, before, after)
	require.Equal(t, before.Separation, after.Separation, "bookkeeping partition cannot silently change")
	require.Equal(t, before.Delivery, after.Delivery, "all primary delivery tables/columns/rows, including retired/history rows and every account, must remain exact")
}

// Apply projects the same posture at every boot, including a rejected manifest
// delivery. It changes stated_at only. Both bounds are actual PRIMARY DB clocks,
// surrounding the tested startup; no host clock/tolerance or dropped policy row.
func ridRequireOwnCeilingsPreserved(t *testing.T, before, after ridWholeDeliverySnapshot) {
	t.Helper()
	require.Equal(t, before.OwnCeilings.Raw.Columns, after.OwnCeilings.Raw.Columns, "complete boot policy schema remains exact")
	require.Equal(t, before.OwnCeilings.Semantic, after.OwnCeilings.Semantic, "all fields except stated_at, including unknown future columns, remain exact")
	require.NotEmpty(t, before.OwnCeilings.Semantic)
	require.Len(t, after.OwnCeilings.Raw.Rows, len(before.OwnCeilings.Raw.Rows))
	require.Len(t, after.OwnCeilings.StatedAt, len(before.OwnCeilings.StatedAt))
	require.False(t, after.PrimaryStartedAt.Before(before.PrimaryFinishedAt))
	for kind, stated := range after.OwnCeilings.StatedAt {
		require.Contains(t, before.OwnCeilings.Semantic, kind)
		require.False(t, stated.Before(before.PrimaryFinishedAt), "actual after stated_at must follow the stopped-base snapshot for %s", kind)
		require.False(t, stated.After(after.PrimaryStartedAt), "actual after stated_at must precede the post-startup PRIMARY snapshot for %s", kind)
	}
}
func ridWholeDigest(t *testing.T, v any) string {
	t.Helper()
	raw, err := json.Marshal(v)
	require.NoError(t, err)
	if text, ok := v.(string); ok {
		raw = []byte(text)
	} // manifest SHA covers exact bytes, not JSON quoting
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

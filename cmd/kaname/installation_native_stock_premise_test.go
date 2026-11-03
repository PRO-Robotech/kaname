// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/servicemanifest"
	"github.com/stretchr/testify/require"
)

// Stock catalog rows are image/migration state, not evidence of module delivery.
// Capture every column and every live/retired row; no live-only/count shortcut.
type ridStockPremise struct {
	Catalog         json.RawMessage `json:"catalog"`
	Issuers         int             `json:"deliveredIssuers"`
	Writers         int             `json:"deliveredWriters"`
	Delegations     int             `json:"delegations"`
	Creators        int             `json:"fixtureCreators"`
	ServiceAccounts int             `json:"totalServiceAccounts"`
	AdminGrants     int             `json:"totalAdminGrants"`
}

func readRIDStockPremise(t *testing.T, w *ceremonyWorld) ridStockPremise {
	t.Helper()
	var p ridStockPremise
	var catalog []byte
	require.NoError(t, w.pool.QueryRow(w.ctx, `SELECT jsonb_build_object(
 'modules',COALESCE((SELECT jsonb_agg(to_jsonb(m) ORDER BY module) FROM kaname.catalog_module m),'[]'::jsonb),
 'resources',COALESCE((SELECT jsonb_agg(to_jsonb(r) ORDER BY module,resource) FROM kaname.catalog_resource r),'[]'::jsonb),
 'verbs',COALESCE((SELECT jsonb_agg(to_jsonb(v) ORDER BY module,resource,verb) FROM kaname.catalog_verb v),'[]'::jsonb)),
 (SELECT count(*) FROM kaname.service_accounts WHERE name IN ('rid-public-issuer','svc-ridfirst','svc-ridsecond')),
 (SELECT count(*) FROM kaname.service_accounts WHERE name='kacho-registry'),
 (SELECT count(*) FROM kaname.grant_delegations),
 (SELECT count(*) FROM kaname.service_accounts WHERE name='rid-native-standing-creator'),
 (SELECT count(*) FROM kaname.service_accounts),
 (SELECT count(*) FROM kaname.cluster_admin_grants)`).Scan(&catalog, &p.Issuers, &p.Writers, &p.Delegations, &p.Creators, &p.ServiceAccounts, &p.AdminGrants))
	p.Catalog = catalog
	return p
}
func writeRIDStockPremise(t *testing.T, root, phase string, p ridStockPremise, startup map[string][]map[string]json.RawMessage) {
	t.Helper()
	raw, err := json.Marshal(map[string]any{"phase": phase, "premise": p, "startup": startup})
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, "stock-premise-"+phase+".json"), raw, 0600))
}
func requireRIDNoDeliveredIdentities(t *testing.T, p ridStockPremise, creators int) {
	t.Helper()
	// The entire coordinate receipt was written BEFORE any of these assertions.
	require.Zero(t, p.Issuers, "no delivered I before full serve")
	require.Zero(t, p.Writers, "W is introduced by first full delivery, not F0")
	require.Zero(t, p.Delegations, "no GD before full serve")
	require.Equal(t, creators, p.Creators, "explicit C provisioning phase")
	require.Equal(t, 2+creators, p.ServiceAccounts, "only stock SAs and explicitly provisioned C")
}

// Only these startup producer messages/fields are retained; no arbitrary log
// record or secret-bearing response is copied to a premise receipt.
var ridBaseReceiptFields = map[string][]string{
	"доставка манифестов модулей не объявлена посадкой": {"required"},
	"перепись композиции модели прав":                   {"manifests_seen", "resources_seen", "canon_types", "composed", "reaffirmed", "prior_edition", "public_read_key_terms"},
	"перепись шага модели доступа против каталога":      {"not_applied", "composed_types", "refused_modules"},
	"перепись каталога модуля":                          {"anchor_modules", "anchor_resources", "anchor_verbs", "row_modules", "row_resources", "row_verbs", "retired_modules", "retired_resources", "retired_verbs", "missing", "withdrawn", "extra", "anchor_added_by_delivery"},
	"перепись применения посева":                        {"own_applied", "delivered", "seeding", "declared_rows", "written_rows"},
}

func readRIDBaseReceipts(t *testing.T, path string) map[string][]map[string]json.RawMessage {
	t.Helper()
	raw, err := os.ReadFile(path)
	require.NoError(t, err)
	out := map[string][]map[string]json.RawMessage{}
	// Ignore only an unfinished trailing line from an unrelated concurrent log
	// write; every required startup receipt must exist as a complete record.
	lines := strings.Split(string(raw), "\n")
	for _, line := range lines[:len(lines)-1] {
		if strings.TrimSpace(line) == "" {
			continue
		}
		var record map[string]json.RawMessage
		require.NoError(t, json.Unmarshal([]byte(line), &record), "base stdout must remain structured JSON")
		var msg string
		require.NoError(t, json.Unmarshal(record["msg"], &msg))
		keys, ok := ridBaseReceiptFields[msg]
		if !ok {
			continue
		}
		selected := map[string]json.RawMessage{}
		for _, key := range keys {
			if value, exists := record[key]; exists {
				selected[key] = value
			}
		}
		out[msg] = append(out[msg], selected)
	}
	return out
}
func (f *installationNativeWorld) requireRIDBasePremise(t *testing.T, phase string, creators int) {
	t.Helper()
	p := readRIDStockPremise(t, f.given)
	receipts := readRIDBaseReceipts(t, f.base.StdoutPath)
	writeRIDStockPremise(t, f.session.Root, phase, p, receipts)
	require.NotEmpty(t, f.stockCatalog, "post-migration stock snapshot required")
	require.JSONEq(t, string(f.stockCatalog), string(p.Catalog), "full live+retired stock catalog preserved without delivery")
	requireRIDNoDeliveredIdentities(t, p, creators)
	// Existing stock identity/admin row preservation assertions are retained in
	// the constructor. Here record the phase explicitly: stock + O [+ C].
	require.Equal(t, 2+creators, p.AdminGrants)
	for msg, fields := range ridBaseReceiptFields {
		rows := receipts[msg]
		require.Len(t, rows, 1, "one actual base startup receipt: %s", msg)
		for _, field := range fields {
			require.Contains(t, rows[0], field, "startup producer field %s", field)
		}
	}
	zero := func(msg string, keys ...string) {
		for _, key := range keys {
			value := ridRequiredReceiptScalar[int](t, receipts[msg][0], key)
			require.Zero(t, value, "actual startup %s: %s", msg, key)
		}
	}
	required := ridRequiredReceiptScalar[bool](t, receipts["доставка манифестов модулей не объявлена посадкой"][0], "required")
	require.False(t, required)
	compose := "перепись композиции модели прав"
	zero(compose, "manifests_seen", "resources_seen", "public_read_key_terms")
	canonicalTypes := ridRequiredReceiptScalar[int](t, receipts[compose][0], "canon_types")
	require.Positive(t, canonicalTypes, "the stock compiled model remains present")
	for _, key := range []string{"composed", "reaffirmed", "prior_edition"} {
		var entries []json.RawMessage
		require.NoError(t, json.Unmarshal(receipts[compose][0][key], &entries))
		require.Empty(t, entries, "no model change introduced by delivery")
	}
	zero("перепись шага модели доступа против каталога", "not_applied", "composed_types", "refused_modules")
	zero("перепись каталога модуля", "missing", "withdrawn", "extra", "anchor_added_by_delivery")
	zero("перепись применения посева", "delivered", "seeding", "written_rows")
	seedReceipt := receipts["перепись применения посева"][0]
	ownApplied := ridRequiredReceiptScalar[bool](t, seedReceipt, "own_applied")
	require.True(t, ownApplied, "normal own seed must run in F0")
	own, err := servicemanifest.Load()
	require.NoError(t, err)
	require.NotNil(t, own.Seed, "normal own manifest must declare its seed")
	declared := len(own.Seed.ServiceAccounts) + len(own.Seed.Groups) + len(own.Seed.Joins) + len(own.Seed.AccessBindings)
	require.Positive(t, declared, "independent own manifest seed is nonempty")
	require.Equal(t, declared, ridRequiredReceiptScalar[int](t, seedReceipt, "declared_rows"))
	// Count the actual full post-migration snapshot, independently of the
	// startup census being judged. Exact full snapshot equality was checked above.
	var stock map[string][]map[string]json.RawMessage
	require.NoError(t, json.Unmarshal(f.stockCatalog, &stock))
	catalogReceipt := receipts["перепись каталога модуля"][0]
	for _, kind := range []string{"modules", "resources", "verbs"} {
		require.Contains(t, stock, kind)
		require.NotEmpty(t, stock[kind], "stock %s rows must exist", kind)
		live, retired := 0, 0
		for _, row := range stock[kind] {
			if ridRequiredReceiptScalar[bool](t, row, "live") {
				live++
			} else {
				retired++
			}
		}
		require.Positive(t, live, "stock live %s must exist", kind)
		require.Equal(t, live, ridRequiredReceiptScalar[int](t, catalogReceipt, "row_"+kind))
		require.Equal(t, retired, ridRequiredReceiptScalar[int](t, catalogReceipt, "retired_"+kind))
		// Empty delivery must report the same stock live image anchor, without
		// adding or dropping rows; retired rows are counted separately above.
		require.Equal(t, live, ridRequiredReceiptScalar[int](t, catalogReceipt, "anchor_"+kind))
	}
}

// Pointer decoding distinguishes a legitimate zero/false from JSON null.
// Missing fields, wrong scalar types and null all fail before dereference.
// Slice fields deliberately keep their normal JSON-null representation.
func ridRequiredReceiptScalar[T int | bool](t *testing.T, record map[string]json.RawMessage, key string) T {
	t.Helper()
	raw, exists := record[key]
	require.True(t, exists, "required scalar field %s", key)
	var value *T
	require.NoError(t, json.Unmarshal(raw, &value), "scalar type for field %s", key)
	require.NotNil(t, value, "scalar field %s must not be null", key)
	return *value
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type rid06RevokeProof struct {
	CaseID, OperationID, DelegationID, Actor string
	PrimaryLower, PrimaryUpper               time.Time
	ChangedRows, AddedRows, RemovedRows      map[string]int
	ExpectedEmitted, ActualEmitted           []rid03EvidenceTuple
	Producers                                []rid03ProducerEvidence
	RemovedFacts                             []rid03FactEvidence
	BeforeRawSHA256, AfterRawSHA256          string
	BusinessAuditCount                       int
	WholeDoDAccepted                         bool
}

func rid06RevokeRow(old, now rid09PrimaryRow, changes map[string]any, clockFields []string, start, end time.Time) bool {
	if len(old) != len(now) {
		return false
	}
	expected := rid09PrimaryRow{}
	for k, v := range old {
		expected[k] = v
	}
	for key, value := range changes {
		if _, ok := old[key]; !ok {
			return false
		}
		raw, err := json.Marshal(value)
		if err != nil {
			return false
		}
		expected[key] = raw
	}
	for _, key := range clockFields {
		if _, ok := old[key]; !ok {
			return false
		}
		at, ok := rid03Cell[time.Time](now, key)
		if !ok || at.Before(start) || at.After(end) {
			return false
		}
		expected[key] = now[key]
	}
	return reflect.DeepEqual(expected, now)
}
func rid06AuditDelta(a, b []rid09PrimaryRow, expected map[string]int, start, end time.Time) (int, bool) {
	fresh, ok := rid03NewEvidenceRows(a, b)
	if !ok {
		return 0, false
	}
	counts := map[string]int{}
	seen := map[string]bool{}
	for _, row := range fresh {
		at, ok := rid03Cell[time.Time](row, "created_at")
		id := rid03S(row, "id")
		if !ok || at.Before(start) || at.After(end) || !rid03Columns(row, "id event_type tenant_account_id event_payload created_at") || !rid03AuditIDPattern.MatchString(id) || seen[id] {
			return 0, false
		}
		seen[id] = true
		var payload any
		if json.Unmarshal(row["event_payload"], &payload) != nil {
			return 0, false
		}
		key := rid03EvidenceHash([]any{rid03S(row, "event_type"), rid03S(row, "tenant_account_id"), payload})
		counts[key]++
	}
	return len(fresh), reflect.DeepEqual(counts, expected)
}
func rid06RevokeRawDelta(a, b rid03NewmanSnapshot, gdID, actor string) (rid06RevokeProof, bool) {
	proof := rid06RevokeProof{DelegationID: gdID, Actor: actor, PrimaryLower: a.Whole.PrimaryFinishedAt, PrimaryUpper: b.Whole.PrimaryStartedAt, ChangedRows: map[string]int{}, AddedRows: map[string]int{}, RemovedRows: map[string]int{}, Producers: []rid03ProducerEvidence{}, RemovedFacts: []rid03FactEvidence{}, BeforeRawSHA256: rid03EvidenceHash(a.Raw), AfterRawSHA256: rid03EvidenceHash(b.Raw)}
	if len(a.Raw) != len(b.Raw) {
		return proof, false
	}
	start, end := proof.PrimaryLower, proof.PrimaryUpper
	gdRows := map[string]rid09PrimaryRow{}
	afterGD := map[string]rid09PrimaryRow{}
	for _, r := range a.Raw["grant_delegations"] {
		gdRows[rid03S(r, "id")] = r
	}
	for _, r := range b.Raw["grant_delegations"] {
		afterGD[rid03S(r, "id")] = r
	}
	gd, found := gdRows[gdID]
	if !found || rid03S(gd, "status") != "ACTIVE" || !rid03SameCell(gd, "revoked_at", nil) {
		return proof, false
	}
	nowGD := afterGD[gdID]
	at, atOK := rid03Cell[time.Time](nowGD, "revoked_at")
	if !atOK || !at.Equal(at.Truncate(time.Second)) || at.Before(start.Truncate(time.Second)) || at.After(end) {
		return proof, false
	}
	if !rid06RevokeRow(gd, nowGD, map[string]any{"status": "REVOKED", "active_delegate_id": nil, "revoked_by_type": "user", "revoked_by_id": actor}, []string{"revoked_at"}, start.Truncate(time.Second), end) {
		return proof, false
	}
	account := rid03S(gd, "account_id")
	bindings := map[string]rid09PrimaryRow{}
	allBindings := map[string]rid09PrimaryRow{}
	for _, r := range a.Raw["access_bindings"] {
		id := rid03S(r, "id")
		allBindings[id] = r
		if rid03S(r, "delegation_id") == gdID && rid03SameCell(r, "revoked_at", nil) {
			bindings[id] = r
		}
	}
	if len(bindings) == 0 {
		return proof, false
	}
	expectedTuples := map[rid03Tuple]bool{}
	held := map[rid03Tuple]bool{}
	active := map[string]bool{}
	for _, r := range a.Raw["access_bindings"] {
		active[rid03S(r, "id")] = rid03S(r, "status") == "ACTIVE"
	}
	for _, r := range a.Raw["access_binding_emitted_tuples"] {
		obj := strings.SplitN(rid03S(r, "object"), ":", 2)
		if len(obj) != 2 {
			return proof, false
		}
		tuple := rid03Tuple{rid03S(r, "fga_user"), rid03S(r, "relation"), obj[0], obj[1]}
		id := rid03S(r, "binding_id")
		if bindings[id] != nil {
			expectedTuples[tuple] = true
		} else if active[id] {
			held[tuple] = true
		}
	}
	for _, r := range a.Raw["cluster_admin_grants"] {
		untilLive := rid03SameCell(r, "granted_until", nil)
		if !untilLive {
			until, ok := rid03Cell[time.Time](r, "granted_until")
			untilLive = ok && until.After(end)
		}
		if untilLive {
			held[rid03Tuple{rid03S(r, "subject_type") + ":" + rid03S(r, "subject_id"), "system_admin", "cluster", rid03S(r, "cluster_id")}] = true
		}
	}
	subjectEvents := map[string]int{}
	expectedAudit := map[string]int{}
	addAudit := func(event string, payload map[string]any) {
		expectedAudit[rid03EvidenceHash([]any{event, account, payload})]++
	}
	addAudit("iam.grant_delegation.revoked", map[string]any{"actor": actor, "delegation_id": gdID, "account_id": account, "revoked_binding_count": len(bindings)})
	for id, g := range bindings {
		subjects := []rid09PrimaryRow{}
		for _, r := range a.Raw["access_binding_subjects"] {
			if rid03S(r, "binding_id") == id {
				subjects = append(subjects, r)
			}
		}
		if len(subjects) == 0 {
			subjects = []rid09PrimaryRow{g}
		}
		for _, r := range subjects {
			kind, subject := rid03S(r, "subject_type"), rid03S(r, "subject_id")
			if kind == "" || subject == "" {
				return proof, false
			}
			payload := map[string]any{"subject_id": subject, "subject_type": kind, "op": "binding_delete", "event_type": "binding_revoke"}
			subjectEvents[rid03EvidenceHash(payload)]++
			addAudit("iam.access_binding.delegation_revoked", map[string]any{"actor": actor, "subject_type": kind, "subject_id": subject, "resource_type": rid03S(g, "resource_type"), "resource_id": rid03S(g, "resource_id"), "role_id": rid03S(g, "role_id"), "binding_id": id, "delegation_id": gdID, "revocation_reason": "delegation_revoked"})
		}
	}
	actualTuples := map[rid03Tuple]bool{}
	subjectSeen := map[string]int{}
	journalSeen := map[string]int{}
	deleted := []rid09PrimaryRow{}
	for table, oldRows := range a.Raw {
		now, present := b.Raw[table]
		if !present {
			return proof, false
		}
		if table == "operations" {
			continue
		}
		wanted := []rid09PrimaryRow{}
		if table == "grant_delegations" {
			for _, r := range oldRows {
				if rid03S(r, "id") == gdID {
					wanted = append(wanted, nowGD)
					proof.ChangedRows[table]++
				} else {
					wanted = append(wanted, r)
				}
			}
		} else if table == "access_bindings" {
			for _, r := range oldRows {
				id := rid03S(r, "id")
				if bindings[id] == nil {
					wanted = append(wanted, r)
					continue
				}
				var current rid09PrimaryRow
				for _, row := range now {
					if rid03S(row, "id") == id {
						current = row
					}
				}
				changes := map[string]any{"revoked_by_user_id": actor, "revocation_reason": "DELEGATION_REVOKED"}
				if _, hasStatus := r["status"]; hasStatus {
					changes["status"] = "REVOKED"
				}
				if !rid06RevokeRow(r, current, changes, []string{"revoked_at"}, start, end) {
					return proof, false
				}
				gAt, ok := rid03Cell[time.Time](current, "revoked_at")
				if !ok || !gAt.Truncate(time.Second).Equal(at) {
					return proof, false
				}
				wanted = append(wanted, current)
				proof.ChangedRows[table]++
			}
		} else if table == "relation_fact" {
			for _, r := range oldRows {
				tuple := rid03Tuple{rid03S(r, "subject"), rid03S(r, "relation"), rid03S(r, "object_type"), rid03S(r, "object_id")}
				if expectedTuples[tuple] && !held[tuple] && !strings.HasPrefix(tuple.Relation, "v_") {
					deleted = append(deleted, r)
					proof.RemovedRows[table]++
				} else {
					wanted = append(wanted, r)
				}
			}
		} else {
			wanted = append(wanted, oldRows...)
		}
		fresh, ok := rid03NewEvidenceRows(wanted, now)
		if !ok {
			return proof, false
		}
		for _, r := range fresh {
			proof.AddedRows[table]++
			clock, ok := rid03Cell[time.Time](r, "created_at")
			if !ok || clock.Before(start) || clock.After(end) {
				return proof, false
			}
			switch table {
			case "fga_outbox":
				tuples, ok := rid05DeletePayload(r, expectedTuples, start, end)
				if !ok {
					return proof, false
				}
				id, _ := rid03Cell[int64](r, "id")
				shape := "singleton"
				if len(tuples) > 1 {
					shape = "grouped"
				}
				entry := rid03ProducerEvidence{ID: id, Event: "fga.tuple.delete", CreatedAt: clock, PayloadShape: shape, Tuples: []rid03EvidenceTuple{}, FullRowSHA256: rid03EvidenceHash(r)}
				for _, t := range tuples {
					actualTuples[t] = true
					entry.Tuples = append(entry.Tuples, rid03EvidenceTupleOf(t))
				}
				proof.Producers = append(proof.Producers, entry)
			case "subject_change_outbox":
				var payload any
				if json.Unmarshal(r["payload"], &payload) != nil || !rid03Columns(r, "id subject_id op created_at event_type payload") || rid03S(r, "op") != "binding_delete" || rid03S(r, "event_type") != "binding_revoke" {
					return proof, false
				}
				key := rid03EvidenceHash(payload)
				var p map[string]any
				if json.Unmarshal(r["payload"], &p) != nil || p["subject_id"] != rid03S(r, "subject_id") || subjectEvents[key] == 0 {
					return proof, false
				}
				subjectSeen[key]++
			case "resource_journal":
				id := rid03S(r, "resource_id")
				g := bindings[id]
				if g == nil || rid03S(g, "resource_type") != "account" || !rid03Columns(r, "sequence_no resource_kind resource_id project_id scope event_type payload created_at") || rid03S(r, "resource_kind") != "iam_access_binding" || rid03S(r, "event_type") != "UPDATED" || rid03S(r, "project_id") != "" || !rid03SameCell(r, "scope", []any{map[string]any{"type": "account", "id": rid03S(g, "resource_id")}}) || !rid03SameCell(r, "payload", map[string]any{"id": id}) {
					return proof, false
				}
				journalSeen[id]++
			default:
				return proof, false
			}
		}
	}
	if !reflect.DeepEqual(actualTuples, expectedTuples) || !reflect.DeepEqual(subjectSeen, subjectEvents) || len(journalSeen) != len(bindings) {
		return proof, false
	}
	for id := range bindings {
		if journalSeen[id] != 1 {
			return proof, false
		}
	}
	for _, r := range deleted {
		tuple := rid03Tuple{rid03S(r, "subject"), rid03S(r, "relation"), rid03S(r, "object_type"), rid03S(r, "object_id")}
		version, vOK := rid03Cell[time.Time](r, "source_version")
		created, cOK := rid03Cell[time.Time](r, "created_at")
		if !vOK || !cOK {
			return proof, false
		}
		clocks := []time.Time{}
		for _, p := range proof.Producers {
			for _, t := range p.Tuples {
				if t == rid03EvidenceTupleOf(tuple) {
					if p.CreatedAt.Before(version) {
						return proof, false
					}
					clocks = append(clocks, p.CreatedAt)
				}
			}
		}
		if len(clocks) == 0 {
			return proof, false
		}
		proof.RemovedFacts = append(proof.RemovedFacts, rid03FactEvidence{Tuple: rid03EvidenceTupleOf(tuple), SourceVersion: version, CreatedAt: created, MatchingProducerClocks: clocks, FullRowSHA256: rid03EvidenceHash(r)})
	}
	count, ok := rid06AuditDelta(a.BusinessAudit, b.BusinessAudit, expectedAudit, start, end)
	if !ok {
		return proof, false
	}
	proof.BusinessAuditCount = count
	proof.ExpectedEmitted = rid03OrderedEvidenceTuples(expectedTuples)
	proof.ActualEmitted = rid03OrderedEvidenceTuples(actualTuples)
	expectedProjection := a.Projection
	expectedProjection.Delegations = []map[string]any{}
	expectedProjection.Bindings = []map[string]any{}
	wireAt, ok := rid05CanonicalMaterializedAt(at)
	if !ok {
		return proof, false
	}
	for _, r := range a.Projection.Delegations {
		copy := map[string]any{}
		for k, v := range r {
			copy[k] = v
		}
		if r["id"] == gdID {
			copy["status"] = "REVOKED"
			copy["revokedAt"] = wireAt
			copy["revokedBy"] = map[string]any{"type": "user", "id": actor}
		}
		expectedProjection.Delegations = append(expectedProjection.Delegations, copy)
	}
	for _, r := range a.Projection.Bindings {
		copy := map[string]any{}
		for k, v := range r {
			copy[k] = v
		}
		if id, _ := r["id"].(string); bindings[id] != nil {
			copy["status"] = "REVOKED"
			copy["revokedAt"] = wireAt
			copy["revokedByUserId"] = actor
			copy["revocationReason"] = "REVOCATION_REASON_DELEGATION_REVOKED"
		}
		expectedProjection.Bindings = append(expectedProjection.Bindings, copy)
	}
	return proof, reflect.DeepEqual(expectedProjection, b.Projection) && reflect.DeepEqual(a.Whole.OwnCeilings, b.Whole.OwnCeilings)
}
func rid06RequireRevokeDelta(t *testing.T, w *ridLifecycleWorld, e rid06PublicExpectation, a, b rid03NewmanSnapshot) (*operations.Operation, rid06RevokeProof) {
	rid03WriteRawDeltaCensus(t, w.f, e.CaseID, a, b)
	proof, ok := rid06RevokeRawDelta(a, b, e.OldGD, w.f.operator.UserID())
	require.True(t, ok, "closed BEFORE-derived Revoke delta required; safe full raw hash census retained")
	old, now := rid03RowsByID(t, a.Raw["operations"]), rid03RowsByID(t, b.Raw["operations"])
	require.Equal(t, len(old)+1, len(now))
	id := ""
	for k, r := range old {
		require.True(t, reflect.DeepEqual(r, now[k]), "every full old Operation, including paused installer attempt, must be unchanged during Revoke")
	}
	for k := range now {
		if old[k] == nil {
			require.Empty(t, id)
			id = k
		}
	}
	require.NotEmpty(t, id)
	require.True(t, rid03Columns(now[id], "id description created_at created_by principal_type principal_id principal_display_name modified_at done metadata_type metadata_data resource_id error_code error_message error_details response_type response_data account_id"))
	ctx, cancel := context.WithTimeout(w.f.given.ctx, 15*time.Second)
	defer cancel()
	op, err := operations.NewRepo(w.f.given.pool, "kaname").Get(ctx, id)
	require.True(t, err == nil && op != nil, "typed primary Revoke Operation read failed")
	require.True(t, op.Done && op.Error == nil && op.Metadata != nil && op.Response != nil)
	require.True(t, op.Principal == (operations.Principal{Type: "user", ID: w.f.operator.UserID(), DisplayName: w.f.operator.UserID()}))
	require.True(t, rid06RevokeCreatorValid(op, now[id], w.f.operator.UserID()), "typed/raw Revoke creator and separate principal must be the actual O")
	var meta iamv1.RevokeGrantDelegationMetadata
	require.True(t, op.Metadata.UnmarshalTo(&meta) == nil)
	want := &iamv1.RevokeGrantDelegationMetadata{GrantDelegationId: e.OldGD, AccountId: w.f.tenantID}
	anyMeta, err := anypb.New(want)
	require.True(t, err == nil && op.Metadata.TypeUrl == anyMeta.TypeUrl && proto.Equal(&meta, want))
	var response, primary iamv1.GrantDelegation
	require.True(t, op.Response.UnmarshalTo(&response) == nil)
	resource := rid03ProjectionRows(t, b.Projection.Delegations)[e.OldGD]
	raw, err := json.Marshal(resource)
	require.True(t, err == nil && protojson.Unmarshal(raw, &primary) == nil)
	expectedAny, err := anypb.New(&primary)
	require.True(t, err == nil && op.Response.TypeUrl == expectedAny.TypeUrl && proto.Equal(&response, &primary))
	require.True(t, rid03S(now[id], "resource_id") == e.OldGD && rid03S(now[id], "account_id") == w.f.tenantID && rid03S(now[id], "description") == "Revoke grant delegation "+e.OldGD)
	for _, key := range []string{"created_at", "modified_at"} {
		clock, ok := rid03Cell[time.Time](now[id], key)
		require.True(t, ok && !clock.Before(a.Whole.PrimaryFinishedAt) && !clock.After(b.Whole.PrimaryStartedAt))
	}
	require.NoError(t, ctx.Err())
	proof.CaseID = e.CaseID
	proof.OperationID = id
	return op, proof
}

func rid06RevokeCreatorValid(op *operations.Operation, raw rid09PrimaryRow, operator string) bool {
	creator, ok := rid03Cell[string](raw, "created_by")
	return operator != "" && op != nil && ok && creator == operator && string(op.CreatedBy) == operator && op.Principal == (operations.Principal{Type: "user", ID: operator, DisplayName: operator})
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/operations/operationspb"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/dto"
	_ "github.com/PRO-Robotech/kaname/internal/dto/toproto"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
	"reflect"
	"strings"
	"testing"
	"time"
)

type rid05DeleteProof struct {
	CaseID                     string `json:"caseId"`
	OperationID                string `json:"operationId"`
	OldCreatorID               string `json:"oldCreatorId"`
	Failed                     bool   `json:"failed"`
	PrimaryLower, PrimaryUpper time.Time
	RemovedRows                map[string]int          `json:"removedRows"`
	AddedRows                  map[string]int          `json:"addedRows"`
	ExpectedRemovedTupleUnion  []rid03EvidenceTuple    `json:"expectedRemovedTupleUnion"`
	ActualRemovedTupleUnion    []rid03EvidenceTuple    `json:"actualRemovedTupleUnion"`
	DeleteIntents              []rid03ProducerEvidence `json:"deleteIntents"`
	DeletedFactClocks          []rid03FactEvidence     `json:"deletedFactClocks"`
	BeforeSHA, AfterSHA        string
	NewDeleteAuditID           string `json:"newDeleteAuditId"`
	WholeDoDAccepted           bool   `json:"wholeDoDAccepted"`
}

func rid05DeletePayload(row rid09PrimaryRow, expected map[rid03Tuple]bool, start, end time.Time) ([]rid03Tuple, bool) {
	id, ok := rid03Cell[int64](row, "id")
	at, timeOK := rid03Cell[time.Time](row, "created_at")
	if !ok || id <= 0 || !timeOK || at.Before(start) || at.After(end) || !rid03Columns(row, "id event_type payload created_at") || rid03S(row, "event_type") != "fga.tuple.delete" {
		return nil, false
	}
	var payload rid09PrimaryRow
	if json.Unmarshal(row["payload"], &payload) != nil {
		return nil, false
	}
	obj := strings.SplitN(rid03S(payload, "object"), ":", 2)
	if len(obj) != 2 {
		return nil, false
	}
	var relations []string
	if rid03Columns(payload, "user object relation") {
		one, valid := rid03Cell[string](payload, "relation")
		if !valid || one == "" {
			return nil, false
		}
		relations = []string{one}
	} else if rid03Columns(payload, "user object relations") {
		var valid bool
		relations, valid = rid03Cell[[]string](payload, "relations")
		if !valid || len(relations) < 2 {
			return nil, false
		}
	} else {
		return nil, false
	}
	tuples := []rid03Tuple{}
	for i, r := range relations {
		if r == "" || (i > 0 && relations[i-1] >= r) {
			return nil, false
		}
		tuple := rid03Tuple{rid03S(payload, "user"), r, obj[0], obj[1]}
		if !expected[tuple] {
			return nil, false
		}
		tuples = append(tuples, tuple)
	}
	return tuples, true
}
func rid05DeleteAuditDelta(before, after []rid09PrimaryRow, creator, account, actor string, start, end time.Time, failed bool) (string, bool) {
	fresh, ok := rid03NewEvidenceRows(before, after)
	if !ok {
		return "", false
	}
	if failed {
		return "", len(fresh) == 0
	}
	if len(fresh) != 1 {
		return "", false
	}
	row := fresh[0]
	at, ok := rid03Cell[time.Time](row, "created_at")
	return rid03S(row, "id"), ok && !at.Before(start) && !at.After(end) && rid03Columns(row, "id event_type tenant_account_id event_payload created_at") && rid03AuditIDPattern.MatchString(rid03S(row, "id")) && rid03S(row, "event_type") == "iam.service_account.deleted" && rid03S(row, "tenant_account_id") == account && rid03SameCell(row, "event_payload", map[string]any{"actor": actor, "resource_type": "service_account", "resource_id": creator, "account_id": account})
}

// Only exact BEFORE coordinates of the object being deleted authorize cleanup.
// No recursive ID search and no unknown table/column exemptions.
func rid05DeleteRawDelta(a, b rid03NewmanSnapshot, creator, account string, failed bool) (rid05DeleteProof, bool) {
	proof := rid05DeleteProof{OldCreatorID: creator, Failed: failed, PrimaryLower: a.Whole.PrimaryFinishedAt, PrimaryUpper: b.Whole.PrimaryStartedAt, RemovedRows: map[string]int{}, AddedRows: map[string]int{}, DeleteIntents: []rid03ProducerEvidence{}, DeletedFactClocks: []rid03FactEvidence{}, BeforeSHA: rid03EvidenceHash(a.Raw), AfterSHA: rid03EvidenceHash(b.Raw)}
	expected := map[rid03Tuple]bool{}
	members := map[rid03Member]bool{}
	for _, row := range a.Raw["access_binding_target_members"] {
		if rid03S(row, "object_type") == "iam.serviceAccount" && rid03S(row, "object_id") == creator {
			members[rid03Member{rid03S(row, "binding_id"), rid03S(row, "role_id"), rid03S(row, "rule_fp"), "iam.serviceAccount", creator}] = true
		}
	}
	for _, row := range a.Raw["access_binding_emitted_tuples"] {
		if rid03S(row, "member_object_type") == "iam.serviceAccount" && rid03S(row, "member_object_id") == creator && rid03S(row, "source") == "member" {
			object := strings.SplitN(rid03S(row, "object"), ":", 2)
			if len(object) != 2 || object[0] != "iam_service_account" || object[1] != creator {
				return proof, false
			}
			expected[rid03Tuple{rid03S(row, "fga_user"), rid03S(row, "relation"), object[0], object[1]}] = true
		}
	}
	expectedRemoval := func(table string, row rid09PrimaryRow) bool {
		if failed {
			return false
		}
		switch table {
		case "service_accounts":
			return rid03S(row, "id") == creator && rid03S(row, "account_id") == account
		case "project_resource_quotas":
			return rid03S(row, "carrier_type") == "iam.serviceAccount" && rid03S(row, "carrier_id") == creator && rid03S(row, "kind") == "iam.serviceAccount.credential"
		case "access_binding_target_members":
			return members[rid03Member{rid03S(row, "binding_id"), rid03S(row, "role_id"), rid03S(row, "rule_fp"), rid03S(row, "object_type"), rid03S(row, "object_id")}]
		case "access_binding_emitted_tuples":
			return rid03S(row, "member_object_type") == "iam.serviceAccount" && rid03S(row, "member_object_id") == creator && rid03S(row, "source") == "member"
		case "relation_fact":
			return expected[rid03Tuple{rid03S(row, "subject"), rid03S(row, "relation"), rid03S(row, "object_type"), rid03S(row, "object_id")}]
		}
		return false
	}
	actualUnion := map[rid03Tuple]bool{}
	deletedFacts := []rid09PrimaryRow{}
	if len(a.Raw) != len(b.Raw) {
		return proof, false
	}
	for table, old := range a.Raw {
		if table == "operations" {
			continue
		}
		current, present := b.Raw[table]
		if !present {
			return proof, false
		}
		wanted := []rid09PrimaryRow{}
		for _, row := range old {
			if expectedRemoval(table, row) {
				proof.RemovedRows[table]++
				if table == "relation_fact" {
					deletedFacts = append(deletedFacts, row)
				}
				continue
			}
			wanted = append(wanted, row)
		}
		fresh, ok := rid03NewEvidenceRows(wanted, current)
		if !ok {
			return proof, false
		}
		// Every expected removed full old row MUST actually be absent.
		for _, row := range current {
			if expectedRemoval(table, row) {
				return proof, false
			}
		}
		for _, row := range fresh {
			if failed {
				return proof, false
			}
			proof.AddedRows[table]++
			at, ok := rid03Cell[time.Time](row, "created_at")
			if !ok || at.Before(proof.PrimaryLower) || at.After(proof.PrimaryUpper) {
				return proof, false
			}
			switch table {
			case "fga_outbox":
				tuples, ok := rid05DeletePayload(row, expected, proof.PrimaryLower, proof.PrimaryUpper)
				if !ok {
					return proof, false
				}
				id, _ := rid03Cell[int64](row, "id")
				entry := rid03ProducerEvidence{ID: id, Event: "fga.tuple.delete", CreatedAt: at, PayloadShape: "singleton", Tuples: []rid03EvidenceTuple{}, FullRowSHA256: rid03EvidenceHash(row)}
				var payload rid09PrimaryRow
				_ = json.Unmarshal(row["payload"], &payload)
				if _, set := payload["relations"]; set {
					entry.PayloadShape = "grouped-delete"
				} else {
					entry.ScalarEcho = rid03S(payload, "relation")
				}
				for _, tuple := range tuples {
					actualUnion[tuple] = true
					entry.Tuples = append(entry.Tuples, rid03EvidenceTupleOf(tuple))
				}
				proof.DeleteIntents = append(proof.DeleteIntents, entry)
			case "resource_reconcile_outbox":
				sent, sentOK := rid03Cell[time.Time](row, "sent_at")
				if !rid03Columns(row, "id object_type object_id event_type created_at sent_at last_error attempt_count") || rid03S(row, "object_type") != "iam.serviceAccount" || rid03S(row, "object_id") != creator || rid03S(row, "event_type") != "mirror.delete" || !rid03SameCell(row, "last_error", nil) || !rid03SameCell(row, "attempt_count", 0) || !sentOK || sent.Before(proof.PrimaryLower) || sent.After(proof.PrimaryUpper) {
					return proof, false
				}
			case "resource_journal":
				if !rid03Columns(row, "sequence_no resource_kind resource_id project_id scope event_type payload created_at") || rid03S(row, "resource_kind") != "iam_service_account" || rid03S(row, "resource_id") != creator || rid03S(row, "project_id") != "" || rid03S(row, "event_type") != "DELETED" || !rid03SameCell(row, "scope", []any{map[string]any{"type": "account", "id": account}}) || !rid03SameCell(row, "payload", map[string]any{"id": creator}) {
					return proof, false
				}
			default:
				return proof, false
			}
		}
	}
	if failed {
		return proof, true
	}
	if proof.RemovedRows["service_accounts"] != 1 || proof.AddedRows["resource_journal"] != 1 || proof.AddedRows["resource_reconcile_outbox"] != 1 || !reflect.DeepEqual(expected, actualUnion) {
		return proof, false
	}
	for _, fact := range deletedFacts {
		tuple := rid03Tuple{rid03S(fact, "subject"), rid03S(fact, "relation"), rid03S(fact, "object_type"), rid03S(fact, "object_id")}
		version, vok := rid03Cell[time.Time](fact, "source_version")
		created, cok := rid03Cell[time.Time](fact, "created_at")
		if !vok || !cok {
			return proof, false
		}
		clocks := []time.Time{}
		for _, row := range proof.DeleteIntents {
			for _, other := range row.Tuples {
				if other == rid03EvidenceTupleOf(tuple) {
					if row.CreatedAt.Before(version) {
						return proof, false
					}
					clocks = append(clocks, row.CreatedAt)
				}
			}
		}
		if len(clocks) == 0 {
			return proof, false
		}
		proof.DeletedFactClocks = append(proof.DeletedFactClocks, rid03FactEvidence{Tuple: rid03EvidenceTupleOf(tuple), SourceVersion: version, CreatedAt: created, MatchingProducerClocks: clocks, FullRowSHA256: rid03EvidenceHash(fact)})
	}
	proof.ExpectedRemovedTupleUnion = rid03OrderedEvidenceTuples(expected)
	proof.ActualRemovedTupleUnion = rid03OrderedEvidenceTuples(actualUnion)
	return proof, true
}
func rid05DeleteProjectionValid(a, b rid03NewmanSnapshot, creator string, failed bool) bool {
	if failed {
		return reflect.DeepEqual(a.Projection, b.Projection)
	}
	expected, valid := rid05DeleteProjectionExpected(a, creator)
	return valid && reflect.DeepEqual(expected, b.Projection)
}

// Compute the entire expected projection solely from BEFORE primary state.
// The internal materialization fence is part of that projection, not an
// unchanged public field: exact authorized member removal changes its digest.
func rid05DeleteProjectionExpected(a rid03NewmanSnapshot, creator string) (rid09NewmanProjection, bool) {
	expected := a.Projection
	members, present := a.Raw["access_binding_target_members"]
	if !present || a.Projection.Materialization != rid03EvidenceHash(members) {
		return expected, false
	}
	remaining := []rid09PrimaryRow{}
	for _, member := range members {
		binding, bindingOK := rid03Cell[string](member, "binding_id")
		typ, typeOK := rid03Cell[string](member, "object_type")
		id, idOK := rid03Cell[string](member, "object_id")
		status, statusOK := rid03Cell[string](member, "verification_status")
		_, timeOK := rid03Cell[time.Time](member, "updated_at")
		if !bindingOK || binding == "" || !typeOK || typ == "" || !idOK || id == "" || !statusOK || status == "" || !timeOK || strings.TrimSpace(string(member["updated_at"])) == "null" {
			return expected, false
		}
		if typ == "iam.serviceAccount" && id == creator {
			continue
		}
		remaining = append(remaining, member)
	}
	// rid09PrimaryRows orders by to_jsonb(row)::text. Removing a subset retains
	// exactly that canonical relative ordering, all columns and subsecond clocks.
	// rid03EvidenceHash and ridWholeDigest both SHA256 json.Marshal for row slices.
	expected.Materialization = rid03EvidenceHash(remaining)
	expected.ServiceAccounts = []map[string]any{}
	removed := 0
	for _, sa := range a.Projection.ServiceAccounts {
		if sa["id"] == creator {
			removed++
			continue
		}
		expected.ServiceAccounts = append(expected.ServiceAccounts, sa)
	}
	if removed != 1 {
		return expected, false
	}
	affected := map[string]bool{}
	for _, member := range a.Raw["access_binding_target_members"] {
		if rid03S(member, "object_type") == "iam.serviceAccount" && rid03S(member, "object_id") == creator {
			affected[rid03S(member, "binding_id")] = true
		}
	}
	expected.Bindings = []map[string]any{}
	for _, binding := range a.Projection.Bindings {
		copy := map[string]any{}
		for key, value := range binding {
			copy[key] = value
		}
		id, _ := binding["id"].(string)
		if affected[id] {
			var latest time.Time
			for _, member := range a.Raw["access_binding_target_members"] {
				if rid03S(member, "binding_id") != id || rid03S(member, "verification_status") != "ACTIVE" || (rid03S(member, "object_type") == "iam.serviceAccount" && rid03S(member, "object_id") == creator) {
					continue
				}
				at, ok := rid03Cell[time.Time](member, "updated_at")
				if !ok {
					return expected, false
				}
				if at.After(latest) {
					latest = at
				}
			}
			value, valid := rid05CanonicalMaterializedAt(latest)
			if !valid {
				return expected, false
			}
			copy["materializedAt"] = value
		}
		expected.Bindings = append(expected.Bindings, copy)
	}
	return expected, true
}
func (p *rid05PublicContext) deleteAction(t *testing.T, w *ridLifecycleWorld, scenario, blocking string, failed bool) ridLifecycleOperation {
	a := rid05SnapshotRead(t, w, true)
	p.premise(t, w, a, true, "ACTIVE")
	active := []string{}
	for _, gd := range a.Core.Raw["grant_delegations"] {
		if rid03S(gd, "active_delegate_id") == w.f.creator.ID {
			active = append(active, rid03S(gd, "id"))
		}
	}
	if failed {
		require.Equal(t, []string{blocking}, active)
	} else {
		require.Empty(t, active)
	}
	e := p.expect(t, w, scenario+"-ACT", a, true, "ACTIVE")
	e.Actor = w.f.operator.UserID()
	e.Path = "/iam/v1/serviceAccounts/" + w.f.creator.ID
	e.BlockingDelegationID = blocking
	e.Denied = failed
	var contractOK bool
	e.DeleteContract, contractOK = rid05DeleteWireContractBefore(e.CaseID, w.f.creator.ID, w.f.creator.AccountID, w.f.operator.UserID(), a.Core.Whole.PrimaryFinishedAt, failed, blocking)
	require.True(t, contractOK, "closed BEFORE-derived typed Delete wire contract required")
	var b rid05Snapshot
	var receipt ridNewmanReceipt
	var adapted ridLifecycleOperation
	func() {
		defer func() {
			b = rid05SnapshotRead(t, w, true)
			rid05RequireDeleteProjection(t, w, a.Core, b.Core, failed, "public-delete")
			require.True(t, reflect.DeepEqual(a.Core.Whole.OwnCeilings, b.Core.Whole.OwnCeilings), "public Delete cannot change own ceilings")
			op := rid05RequireDeleteOperation(t, w, a, b, failed, blocking)
			adapted = rid05LifecycleOperation(t, op)
			require.True(t, reflect.DeepEqual(a.Core.BusinessAudit, b.Core.BusinessAudit), "Delete cannot emit AB/GD business events")
			auditID, ok := rid05DeleteAuditDelta(a.DeletedAudit, b.DeletedAudit, w.f.creator.ID, w.f.creator.AccountID, w.f.operator.UserID(), a.Core.Whole.PrimaryFinishedAt, b.Core.Whole.PrimaryStartedAt, failed)
			require.True(t, ok, "exact immutable Delete business audit delta required")
			proof, ok := rid05DeleteRawDelta(a.Core, b.Core, w.f.creator.ID, w.f.creator.AccountID, failed)
			require.True(t, ok, "closed BEFORE-derived delete cleanup delta required")
			proof.CaseID = e.CaseID
			proof.OperationID = op.ID
			proof.NewDeleteAuditID = auditID
			require.True(t, receipt.OK)
			rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(e.CaseID)+"-primary-delete-proof", proof)
			e.Operation = rid09PrimaryJSON(t, operationspb.ToProto(op))
			e.Snapshot = b.Core
		}()
		receipt = ridRunNewmanPhase(t, w.f, "registry-installation-rid05", e.CaseID, strings.ToLower(e.CaseID), map[string]any{"rid05Expected": e})
		require.True(t, receipt.OK)
	}()
	e.CaseID = strings.TrimSuffix(e.CaseID, "-ACT") + "-VERIFY"
	e.Phase = "VERIFY"
	e.CreatorPresent = failed
	e.DeleteContract = nil
	var verify ridNewmanReceipt
	func() {
		defer func() {
			end := rid05SnapshotRead(t, w, false)
			require.True(t, rid05Equal(b, end), "full Delete VERIFY ledger changed")
			require.True(t, verify.OK)
			rid08Write(t, w.f.session.Root, "newman-"+strings.ToLower(e.CaseID)+"-primary-bracket", map[string]any{"caseId": e.CaseID, "fullPrimaryUnchanged": true, "wholeDoDAccepted": false})
		}()
		verify = ridRunNewmanPhase(t, w.f, "registry-installation-rid05", e.CaseID, strings.ToLower(e.CaseID), map[string]any{"rid05Expected": e})
		require.True(t, verify.OK)
	}()
	return adapted
}
func (p *rid05PublicContext) guardedDelete(t *testing.T, w *ridLifecycleWorld, blocking string) {
	if p != nil {
		p.deleteAction(t, w, "ACTIVE-DELEGATE-DELETE", blocking, true)
	}
}
func (p *rid05PublicContext) deleteTwin(t *testing.T, w *ridLifecycleWorld, blocking string) ridLifecycleOperation {
	return p.deleteAction(t, w, "REVOKE-ONLY-DELETE-TWIN", blocking, false)
}
func rid05RequireDeleteOperation(t *testing.T, w *ridLifecycleWorld, a, b rid05Snapshot, failed bool, blocking string) *operations.Operation {
	t.Helper()
	old, now := rid03RowsByID(t, a.Core.Raw["operations"]), rid03RowsByID(t, b.Core.Raw["operations"])
	require.Equal(t, len(old)+1, len(now))
	id := ""
	for previous, row := range old {
		require.True(t, reflect.DeepEqual(row, now[previous]), "every old Operation raw field/history must remain exact")
	}
	for added := range now {
		if old[added] == nil {
			require.Empty(t, id)
			id = added
		}
	}
	require.NotEmpty(t, id)
	require.True(t, rid03Columns(now[id], "id description created_at created_by principal_type principal_id principal_display_name modified_at done metadata_type metadata_data resource_id error_code error_message error_details response_type response_data account_id"), "closed full Operation schema required")
	ctx, cancel := context.WithTimeout(w.f.given.ctx, 30*time.Second)
	defer cancel()
	op, err := operations.NewRepo(w.f.given.pool, "kaname").Get(ctx, id)
	require.True(t, err == nil, "typed Operation read failed")
	require.NotNil(t, op)
	require.True(t, rid05TypedDeleteValid(op, w.f.creator.ID, w.f.creator.AccountID, w.f.operator.UserID(), failed, blocking), "full normal typed Delete Operation identity required")
	require.True(t, rid03S(now[id], "account_id") == w.f.creator.AccountID && rid03S(now[id], "resource_id") == w.f.creator.ID && rid03S(now[id], "description") == "Delete service account "+w.f.creator.ID)
	for _, key := range []string{"created_at", "modified_at"} {
		at, ok := rid03Cell[time.Time](now[id], key)
		require.True(t, ok && !at.Before(a.Core.Whole.PrimaryFinishedAt) && !at.After(b.Core.Whole.PrimaryStartedAt), "Operation primary clocks outside actual phase")
	}
	require.NoError(t, ctx.Err())
	return op
}

// No typed secret-bearing Any is ever formatted in assertion failures.
func rid05TypedDeleteValid(op *operations.Operation, creator, account, actor string, failed bool, blocking string) bool {
	if op == nil || !op.Done || op.Principal != (operations.Principal{Type: "user", ID: actor, DisplayName: actor}) || op.Metadata == nil {
		return false
	}
	wantMeta, err := anypb.New(&iamv1.DeleteServiceAccountMetadata{ServiceAccountId: creator, AccountId: account})
	if err != nil {
		return false
	}
	var meta iamv1.DeleteServiceAccountMetadata
	if op.Metadata.TypeUrl != wantMeta.TypeUrl || op.Metadata.UnmarshalTo(&meta) != nil || !proto.Equal(&meta, &iamv1.DeleteServiceAccountMetadata{ServiceAccountId: creator, AccountId: account}) {
		return false
	}
	if failed {
		return op.Response == nil && op.Error != nil && len(op.Error.Details) == 0 && op.Error.Code == 9 && op.Error.Message == "service account "+creator+" holds an active grant delegation "+blocking+"; revoke it first"
	}
	if op.Error != nil || op.Response == nil {
		return false
	}
	empty, err := anypb.New(&emptypb.Empty{})
	if err != nil || op.Response.TypeUrl != empty.TypeUrl {
		return false
	}
	var got emptypb.Empty
	return op.Response.UnmarshalTo(&got) == nil && proto.Equal(&got, &emptypb.Empty{})
}

// Native DELETE remains an ordinary API request in the three deletion setup
// worlds. This independent checkpoint preserves full evidence across that real
// mutation, without incrementing the public phase counter or substituting RPC.
func (p *rid05PublicContext) beforeNativeDelete(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	s := rid05SnapshotRead(t, w, true)
	p.beforeNativeDeletion = &s
}
func (p *rid05PublicContext) nativeDeleted(t *testing.T, w *ridLifecycleWorld) {
	if p == nil {
		return
	}
	require.NotNil(t, p.beforeNativeDeletion)
	a := *p.beforeNativeDeletion
	b := rid05SnapshotRead(t, w, true)
	rid05RequireDeleteProjection(t, w, a.Core, b.Core, false, "native-delete")
	require.True(t, reflect.DeepEqual(a.Core.Whole.OwnCeilings, b.Core.Whole.OwnCeilings))
	op := rid05RequireDeleteOperation(t, w, a, b, false, "")
	require.True(t, reflect.DeepEqual(a.Core.BusinessAudit, b.Core.BusinessAudit), "native Delete adds no AB/GD audit")
	auditID, ok := rid05DeleteAuditDelta(a.DeletedAudit, b.DeletedAudit, w.f.creator.ID, w.f.creator.AccountID, w.f.operator.UserID(), a.Core.Whole.PrimaryFinishedAt, b.Core.Whole.PrimaryStartedAt, false)
	require.True(t, ok, "native Delete exact business audit required")
	proof, ok := rid05DeleteRawDelta(a.Core, b.Core, w.f.creator.ID, w.f.creator.AccountID, false)
	require.True(t, ok, "native Delete closed full raw cleanup required")
	proof.OperationID = op.ID
	proof.NewDeleteAuditID = auditID
	rid08Write(t, w.f.session.Root, "rid05-"+p.owner+"-"+rid03Mode(t, w)+"-native-delete-proof", map[string]any{"integrationOnly": true, "actualNewmanExecuted": false, "proof": proof, "wholeDoDAccepted": false})
}

// Canonical data-only domain→DTO→protojson projection, exactly as RID09's SQL
// oracle. No REST/usecase/AFTER value participates; zero emits JSON null.
func rid05CanonicalMaterializedAt(at time.Time) (any, bool) {
	var pb *iamv1.AccessBinding
	if dto.Transfer(dto.FromTo(domain.AccessBinding{MaterializedAt: at}, &pb)) != nil {
		return nil, false
	}
	raw, err := (protojson.MarshalOptions{EmitUnpopulated: true}).Marshal(pb)
	if err != nil {
		return nil, false
	}
	var fields map[string]any
	if json.Unmarshal(raw, &fields) != nil {
		return nil, false
	}
	value, present := fields["materializedAt"]
	return value, present
}

// Failure evidence is a closed nonsecret field/hash census. In particular no
// raw Operation, credential, arbitrary bookkeeping payload or response is logged.
func rid05RequireDeleteProjection(t *testing.T, w *ridLifecycleWorld, a, b rid03NewmanSnapshot, failed bool, label string) {
	expected, valid := a.Projection, true
	if !failed {
		expected, valid = rid05DeleteProjectionExpected(a, w.f.creator.ID)
	}
	fields := func(p rid09NewmanProjection) map[string]any {
		return map[string]any{"accounts": p.Accounts, "serviceAccounts": p.ServiceAccounts, "groups": p.Groups, "members": p.Members, "roles": p.Roles, "bindings": p.Bindings, "delegations": p.Delegations, "catalog": p.Catalog, "materializationLedger": p.Materialization}
	}
	before, want, actual := fields(a.Projection), fields(expected), fields(b.Projection)
	census := map[string]any{}
	for key, value := range want {
		census[key] = map[string]any{"beforeSHA256": rid03EvidenceHash(before[key]), "expectedSHA256": rid03EvidenceHash(value), "actualSHA256": rid03EvidenceHash(actual[key]), "equal": reflect.DeepEqual(value, actual[key])}
	}
	removed := []map[string]string{}
	for _, m := range a.Raw["access_binding_target_members"] {
		if rid03S(m, "object_type") == "iam.serviceAccount" && rid03S(m, "object_id") == w.f.creator.ID {
			removed = append(removed, map[string]string{"bindingId": rid03S(m, "binding_id"), "roleId": rid03S(m, "role_id"), "ruleFp": rid03S(m, "rule_fp"), "objectType": "iam.serviceAccount", "objectId": w.f.creator.ID})
		}
	}
	rid08Write(t, w.f.session.Root, "rid05-"+label+"-projection-census", map[string]any{"beforeExpectedConsistent": valid, "expectedRemovedMemberCoordinates": removed, "projectionFields": census, "wholeDoDAccepted": false})
	require.True(t, valid, "FIXTURE_NOT_ACCEPTED: BEFORE primary member rows and materialization fence inconsistent")
	require.True(t, reflect.DeepEqual(expected, b.Projection), "full Delete projection differs from independent BEFORE-derived expectation; safe field/hash census retained")
}

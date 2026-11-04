// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/operations/operationspb"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	statuspb "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
	"google.golang.org/protobuf/types/known/emptypb"
)

// Этот несекретный контракт строится до ACT, без возвращённого ID/тела или снимка
// AFTER. Полная первичная типизированная проверка и точный VERIFY остаются отдельными.
type rid05DeleteWireContract struct {
	CaseID     string         `json:"caseId"`
	ResourceID string         `json:"resourceId"`
	AccountID  string         `json:"accountId"`
	OperatorID string         `json:"operatorId"`
	NotBefore  time.Time      `json:"notBefore"`
	NotAfter   time.Time      `json:"notAfter"`
	Operation  map[string]any `json:"operation"`
}

func rid05DeleteWireContractBefore(caseID, creator, account, actor string, lower time.Time, failed bool, blocking string) (*rid05DeleteWireContract, bool) {
	expectedFailure := false
	switch caseID {
	case "registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-ACT", "registry-installation-rid05-S2-ACTIVE-DELEGATE-DELETE-ACT":
		expectedFailure = true
	case "registry-installation-rid05-S1-REVOKE-ONLY-DELETE-TWIN-ACT", "registry-installation-rid05-S2-REVOKE-ONLY-DELETE-TWIN-ACT":
	default:
		return nil, false
	}
	if failed != expectedFailure || creator == "" || account == "" || actor == "" || lower.IsZero() || (failed && blocking == "") {
		return nil, false
	}
	meta, err := anypb.New(&iamv1.DeleteServiceAccountMetadata{ServiceAccountId: creator, AccountId: account})
	if err != nil {
		return nil, false
	}
	op := &operations.Operation{Done: true, Description: "Delete service account " + creator, CreatedBy: actor, Principal: operations.Principal{Type: "user", ID: actor, DisplayName: actor}, Metadata: meta}
	if failed {
		op.Error = &statuspb.Status{Code: 9, Message: "service account " + creator + " holds an active grant delegation " + blocking + "; revoke it first"}
	} else {
		op.Response, err = anypb.New(&emptypb.Empty{})
		if err != nil {
			return nil, false
		}
	}
	// В protobufv1.36.11 Empty имеет особый JSON: Any содержит @type И value:{}.
	// Выводим единственную каноническую форму из закреплённой реализации, а не
	// из допускающей варианты пары вручную написанных кодировок.
	raw, err := (protojson.MarshalOptions{EmitUnpopulated: true}).Marshal(operationspb.ToProto(op))
	if err != nil {
		return nil, false
	}
	var wire map[string]any
	if json.Unmarshal(raw, &wire) != nil {
		return nil, false
	}
	return &rid05DeleteWireContract{CaseID: caseID, ResourceID: creator, AccountID: account, OperatorID: actor, NotBefore: lower.UTC().Truncate(time.Second), NotAfter: lower.UTC().Add(120 * time.Second), Operation: wire}, true
}
func TestRID05DeleteWireCanonicalAny(t *testing.T) {
	for _, name := range []string{"success-S1", "success-S2", "guard-S1", "guard-S2"} {
		t.Run(name, func(t *testing.T) {
			mode := "S1"
			if strings.HasSuffix(name, "S2") {
				mode = "S2"
			}
			failed := strings.HasPrefix(name, "guard")
			suffix := "REVOKE-ONLY-DELETE-TWIN-ACT"
			if failed {
				suffix = "ACTIVE-DELEGATE-DELETE-ACT"
			}
			c, ok := rid05DeleteWireContractBefore("registry-installation-rid05-"+mode+"-"+suffix, "C", "SYS", "O", time.Date(2026, 11, 3, 12, 0, 0, 987654321, time.UTC), failed, "D")
			require.True(t, ok)
			require.Equal(t, "O", c.Operation["principalId"])
			require.Equal(t, "user", c.Operation["principalType"])
			require.Equal(t, "O", c.Operation["createdBy"])
			require.Equal(t, map[string]any{"@type": "type.googleapis.com/kaname.cloud.iam.v1.DeleteServiceAccountMetadata", "serviceAccountId": "C", "accountId": "SYS"}, c.Operation["metadata"])
			if failed {
				require.Equal(t, map[string]any{"code": float64(9), "message": "service account C holds an active grant delegation D; revoke it first", "details": []any{}}, c.Operation["error"])
			} else {
				require.Equal(t, map[string]any{"@type": "type.googleapis.com/google.protobuf.Empty", "value": map[string]any{}}, c.Operation["response"])
			}
			require.Zero(t, c.NotBefore.Nanosecond())
			require.Equal(t, 120*time.Second+987654321*time.Nanosecond, c.NotAfter.Sub(c.NotBefore))
		})
	}
}
func TestRID05DeleteWireRejectsInvalidInput(t *testing.T) {
	for _, name := range []string{"unknown-case", "VERIFY-case", "other-mode", "wrong-outcome", "empty-resource", "empty-account", "empty-actor", "zero-clock", "missing-guard-GD"} {
		t.Run(name, func(t *testing.T) {
			id := "registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-ACT"
			resource, account, actor, blocking := "C", "SYS", "O", "D"
			lower := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
			failed := true
			switch name {
			case "unknown-case":
				id = "registry-installation-rid05-S1-OTHER"
			case "VERIFY-case":
				id = "registry-installation-rid05-S1-ACTIVE-DELEGATE-DELETE-VERIFY"
			case "other-mode":
				id = "registry-installation-rid05-S3-ACTIVE-DELEGATE-DELETE-ACT"
			case "wrong-outcome":
				failed = false
			case "empty-resource":
				resource = ""
			case "empty-account":
				account = ""
			case "empty-actor":
				actor = ""
			case "zero-clock":
				lower = time.Time{}
			case "missing-guard-GD":
				blocking = ""
			}
			_, ok := rid05DeleteWireContractBefore(id, resource, account, actor, lower, failed, blocking)
			require.False(t, ok)
		})
	}
}

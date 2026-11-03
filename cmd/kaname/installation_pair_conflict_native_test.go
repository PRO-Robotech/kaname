// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

type rid07Observation struct {
	Axis, Mode, Before, After            string
	OldPair, NewPair, OldGrant, NewGrant string
}

// Each negative/twin starts from an independent full F0→O→C→delivery world.
// Revoke/Create below is explicit Given construction, never convergence repair.
// Its revoked history is included in the frozen snapshot before tested apply.
func rid07Matrix(t *testing.T, exact bool) []rid07Observation {
	return rid07MatrixWithPublic(t, exact, nil)
}

func rid07MatrixWithPublic(t *testing.T, exact bool, consumer rid07LivePublicConsumer) []rid07Observation {
	t.Helper()
	var records []rid07Observation
	for _, axis := range []string{"role", "target", "subject", "creator"} {
		for _, mode := range []string{"S1", "S2"} {
			t.Run(axis+"/"+mode, func(t *testing.T) {
				w := newRIDLifecycleWorld(t, mode, false)
				f := w.f
				oldPair := proto.Clone(w.gd).(*iamv1.GrantDelegation)
				firstSubject := f.ridSA(t, f.tenantID, "rid07-old-grantee")
				oldGrant := w.grant(t, w.bindingInput("service_account", firstSubject, w.pull, "registry.registries", w.object))
				f.ridOperation(t, "POST", "/iam/v1/grantDelegations/"+oldPair.Id+":revoke", f.operator.Bearer(), map[string]any{}, 0)
				var oldRevoked iamv1.GrantDelegation
				f.publicRead(t, "/iam/v1/grantDelegations/"+oldPair.Id, &oldRevoked)
				require.Equal(t, iamv1.GrantDelegation_REVOKED, oldRevoked.Status)
				require.True(t, proto.Equal(oldPair.CreatedAt, oldRevoked.CreatedAt))
				require.Equal(t, oldPair.RoleIds, oldRevoked.RoleIds)
				require.Equal(t, oldPair.TargetTypes, oldRevoked.TargetTypes)
				require.Equal(t, oldPair.SubjectTypes, oldRevoked.SubjectTypes)
				require.True(t, proto.Equal(oldPair.DelegatedBy, oldRevoked.DelegatedBy))
				var revokedGrant iamv1.AccessBinding
				f.publicRead(t, "/iam/v1/accessBindings/"+oldGrant.Id, &revokedGrant)
				require.Equal(t, iamv1.AccessBinding_REVOKED, revokedGrant.Status)
				require.Equal(t, iamv1.AccessBinding_REVOCATION_REASON_DELEGATION_REVOKED, revokedGrant.GetRevocationReason())

				body := w.gdCreateBody(f.tenantID, w.issuer.ID)
				creator := f.creator.ID
				credential := f.creator
				if axis == "creator" {
					// BOTH worlds provision C-other identically. Only the caller used for
					// ordinary Create changes; installer always presents original C.
					other := f.ridSA(t, f.creator.AccountID, "rid07-other-creator")
					f.ridAdmin(t, other, true)
					f.ridAuthorityMaterialized(t, other, true)
					key := f.ridKey(t, other, f.creator.AccountID, "other-creator")
					if !exact {
						creator, credential = other, key
					}
				}
				if !exact {
					switch axis {
					case "role":
						body["roleIds"] = []string{w.push}
					case "target":
						body["targetTypes"] = []string{"registry.repositories"}
					case "subject":
						body["subjectTypes"] = []string{"SUBJECT_TYPE_USER"}
					}
				}
				token := f.ridToken(t, credential)
				beforeBindings, beforeOps := w.grantIdentityCensus(t)
				created := f.ridOperation(t, "POST", "/iam/v1/grantDelegations", token, body, 0)
				require.NotContains(t, beforeOps, created.ID)
				newID := ridResponseID(t, created)
				require.NotEqual(t, oldPair.Id, newID)
				var given iamv1.GrantDelegation
				f.publicRead(t, "/iam/v1/grantDelegations/"+newID, &given)
				requireNativeInstallationOperation(t, f.given.ctx, f.given.pool, created.ID, f.tenantID, creator, newID)
				var creationResponse anypb.Any
				require.NoError(t, protojson.Unmarshal(created.Response, &creationResponse))
				var responseGD iamv1.GrantDelegation
				require.NoError(t, creationResponse.UnmarshalTo(&responseGD))
				require.True(t, proto.Equal(&responseGD, &given), "ordinary GD Create response equals public Get")
				f.ridAuthorityMaterialized(t, f.creator.ID, true)

				rawBody, err := json.Marshal(body)
				require.NoError(t, err)
				var request iamv1.CreateGrantDelegationRequest
				require.NoError(t, protojson.Unmarshal(rawBody, &request))
				require.Equal(t, request.AccountId, given.AccountId)
				require.True(t, proto.Equal(request.Delegate, given.Delegate))
				require.ElementsMatch(t, request.RoleIds, given.RoleIds)
				require.ElementsMatch(t, request.TargetTypes, given.TargetTypes)
				require.ElementsMatch(t, request.SubjectTypes, given.SubjectTypes)
				require.Equal(t, "service_account", given.DelegatedBy.Type)
				require.Equal(t, creator, given.DelegatedBy.Id)
				require.Equal(t, iamv1.GrantDelegation_ACTIVE, given.Status)
				require.NotNil(t, given.CreatedAt)
				afterBindings, afterOps := w.grantIdentityCensus(t)
				require.ElementsMatch(t, beforeBindings, afterBindings)
				require.ElementsMatch(t, append(beforeOps, created.ID), afterOps)
				w.gd = &given
				subject := f.ridSA(t, f.tenantID, "rid07-active-grantee")
				grantBody := w.bindingInput("service_account", subject, w.pull, "registry.registries", w.object)
				if !exact {
					switch axis {
					case "role":
						grantBody["roleId"] = w.push
					case "target":
						grantBody["target"] = w.bindingInput("service_account", subject, w.pull, "registry.repositories", w.repository)["target"]
					case "subject":
						grantBody["subjectType"], grantBody["subjectId"] = "user", f.operator.UserID()
					}
				}
				newGrant := w.grant(t, grantBody)
				require.NotEqual(t, oldGrant.Id, newGrant.Id)
				// Lawfulness is demonstrated by ordinary Create and a successful actual I
				// grant under this GD before freezing the Given; shape alone is insufficient.
				history := w.snapshot(t)
				publicPairs := map[string]*iamv1.GrantDelegation{}
				for _, account := range w.accounts {
					for _, gd := range w.delegations(t, account) {
						publicPairs[gd.Id] = proto.Clone(gd).(*iamv1.GrantDelegation)
					}
				}
				require.Len(t, publicPairs, len(w.accounts)+1)
				receipt, err := json.Marshal(map[string]any{"axis": axis, "exactTwin": exact, "mode": mode, "oldPair": oldPair.Id, "activePair": newID, "oldGrant": oldGrant.Id, "activeGrant": newGrant.Id, "creator": creator, "setupCreateOperation": created.ID, "snapshot": json.RawMessage(history)})
				require.NoError(t, err)
				require.NoError(t, os.WriteFile(filepath.Join(f.session.Root, "rid07-given.json"), receipt, 0600))
				_, operationsBefore := w.grantIdentityCensus(t)
				publicInput := rid07NewmanInput{Axis: axis, Mode: mode, Exact: exact, OldPair: oldPair.Id, ActivePair: newID, OldGrant: oldGrant.Id, ActiveGrant: newGrant.Id}
				publicConsumer := consumer
				if publicConsumer == nil {
					publicConsumer = rid07DefaultNewmanConsumer(t, w, publicInput)
				}
				if publicConsumer != nil {
					publicConsumer(t, w, publicInput, "before")
				}
				if exact {
					requireNativeOK(t, f.apply(t, w.delivery), len(w.accounts))
					f.renewOperator(t, f.given.ctx)
				} else {
					completed := 0
					for i, account := range w.accounts {
						if account == f.tenantID {
							completed = i
						}
					}
					w.refusedApply(t, installationResult{Stage: "delegation", Code: "FAILED_PRECONDITION", AccountID: f.tenantID, DelegateID: w.issuer.ID, CompletedPairs: completed})
				}
				require.Equal(t, history, w.snapshot(t), "no setup repair or historical mutation during apply")
				rid07CheckApplyOperations(t, w, operationsBefore, exact)
				gotPairs := map[string]*iamv1.GrantDelegation{}
				for _, account := range w.accounts {
					for _, gd := range w.delegations(t, account) {
						gotPairs[gd.Id] = gd
					}
				}
				require.Len(t, gotPairs, len(publicPairs))
				for id, previous := range publicPairs {
					require.True(t, proto.Equal(previous, gotPairs[id]), "entire public pair history must remain unchanged")
				}
				rid07BindingUnchanged(t, w, &revokedGrant)
				rid07BindingUnchanged(t, w, newGrant)
				if publicConsumer != nil {
					publicConsumer(t, w, publicInput, "after")
				}
				records = append(records, rid07Observation{Axis: axis, Mode: mode, Before: history, After: w.snapshot(t), OldPair: oldPair.Id, NewPair: newID, OldGrant: oldGrant.Id, NewGrant: newGrant.Id})
			})
		}
	}
	return records
}

func rid07CheckApplyOperations(t *testing.T, w *ridLifecycleWorld, before []string, exact bool) {
	t.Helper()
	_, after := w.grantIdentityCensus(t)
	old := map[string]bool{}
	for _, id := range before {
		old[id] = true
	}
	expected := len(w.accounts)
	if !exact {
		for i, a := range w.accounts {
			if a == w.f.tenantID {
				expected = i + 1
			}
		}
	}
	count := 0
	failed := 0
	seenAccounts := map[string]bool{}
	for _, id := range after {
		if old[id] {
			continue
		}
		count++
		op, err := operations.NewRepo(w.f.given.pool, "kaname").Get(w.f.given.ctx, id)
		require.NoError(t, err)
		require.True(t, op.Done)
		require.Equal(t, operations.Principal{Type: "service_account", ID: w.f.creator.ID, DisplayName: w.f.creator.ID}, op.Principal)
		require.NotNil(t, op.Metadata)
		var meta iamv1.CreateGrantDelegationMetadata
		require.NoError(t, op.Metadata.UnmarshalTo(&meta))
		require.False(t, seenAccounts[meta.AccountId])
		seenAccounts[meta.AccountId] = true
		if op.Error == nil {
			require.True(t, exact || meta.AccountId != w.f.tenantID)
			var active string
			require.NoError(t, w.f.given.pool.QueryRow(w.f.given.ctx, `SELECT id FROM kaname.grant_delegations WHERE account_id=$1 AND delegate_id=$2 AND status='ACTIVE'`, meta.AccountId, w.issuer.ID).Scan(&active))
			requireNativeInstallationOperation(t, w.f.given.ctx, w.f.given.pool, id, meta.AccountId, w.f.creator.ID, active)
		} else {
			failed++
			require.False(t, exact)
			require.Equal(t, int32(9), op.Error.Code)
			require.Equal(t, w.f.tenantID, meta.AccountId)
			require.Nil(t, op.Response)
			var mt, resource, account string
			var data []byte
			require.NoError(t, w.f.given.pool.QueryRow(w.f.given.ctx, `SELECT metadata_type,metadata_data,resource_id,account_id FROM kaname.operations WHERE id=$1`, id).Scan(&mt, &data, &resource, &account))
			require.Equal(t, op.Metadata.TypeUrl, mt)
			require.Equal(t, op.Metadata.Value, data)
			require.Equal(t, meta.GrantDelegationId, resource)
			require.Equal(t, meta.AccountId, account)
			require.NotEqual(t, w.gd.Id, resource)
			var decoded iamv1.CreateGrantDelegationMetadata
			require.NoError(t, (&anypb.Any{TypeUrl: mt, Value: data}).UnmarshalTo(&decoded))
			require.True(t, proto.Equal(&meta, &decoded))
		}
	}
	require.Equal(t, expected, count)
	if exact {
		require.Zero(t, failed)
	} else {
		require.Equal(t, 1, failed)
	}
}

func rid07BindingUnchanged(t *testing.T, w *ridLifecycleWorld, before *iamv1.AccessBinding) {
	t.Helper()
	ctx, cancel := context.WithTimeout(w.f.given.ctx, 5*time.Second)
	defer cancel()
	for {
		first := w.primaryBindingMaterializedAt(t, ctx, before.Id)
		var raw json.RawMessage
		code, err := w.f.wire.JSON(ctx, http.MethodGet, "/iam/v1/accessBindings/"+before.Id, w.f.operator.Bearer(), nil, &raw)
		require.NoError(t, err)
		require.Equal(t, http.StatusOK, code)
		var got iamv1.AccessBinding
		require.NoError(t, protojson.Unmarshal(raw, &got))
		last := w.primaryBindingMaterializedAt(t, ctx, before.Id)
		require.NoError(t, ctx.Err())
		if proto.Equal(first, last) {
			expected := proto.Clone(before).(*iamv1.AccessBinding)
			expected.MaterializedAt = last
			require.True(t, proto.Equal(expected, &got), "entire binding unchanged except independently observed temporal projection")
			return
		}
		timer := time.NewTimer(25 * time.Millisecond)
		select {
		case <-ctx.Done():
			timer.Stop()
			require.NoError(t, ctx.Err())
		case <-timer.C:
		}
	}
}

func requireRID07Preserved(t *testing.T, records []rid07Observation) {
	t.Helper()
	require.Len(t, records, 8)
	seen := map[string]bool{}
	for _, r := range records {
		key := r.Axis + "/" + r.Mode
		require.False(t, seen[key])
		seen[key] = true
		require.NotEmpty(t, r.Before)
		require.Equal(t, r.Before, r.After)
		require.NotEmpty(t, r.OldPair)
		require.NotEmpty(t, r.NewPair)
		require.NotEqual(t, r.OldPair, r.NewPair)
		require.NotEmpty(t, r.OldGrant)
		require.NotEmpty(t, r.NewGrant)
		require.NotEqual(t, r.OldGrant, r.NewGrant)
	}
}

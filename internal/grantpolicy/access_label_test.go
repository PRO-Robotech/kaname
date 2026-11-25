// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package grantpolicy

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

type accessLabelPolicyWriter struct {
	metadataPolicyWriter
	questions []string
	failure   error
}

func (w *accessLabelPolicyWriter) SemanticRelationChecker() kaname.RelationChecker { return w }
func (w *accessLabelPolicyWriter) Check(_ context.Context, _ string, relation, object string) (bool, error) {
	w.questions = append(w.questions, relation+" "+object)
	if relation == grantcapability.ApplyAccessLabelRelation && w.failure != nil {
		return false, w.failure
	}
	return w.allow[relation+" "+object], nil
}

func TestProposedAccessLabelRequiresExactWitnessBeforeShortcuts(t *testing.T) {
	ctx := context.Background()
	bundle, err := granteffect.NewBundle(ctx, authzmodel.DSL, catalog.Halves{Live: catalog.Rows{
		Modules: []string{"iam"},
		Resources: []catalog.ResourceRow{
			{Module: "iam", Resource: "accessLabel", ObjectType: grantcapability.AccessLabelObjectType},
			{Module: "iam", Resource: "accessBinding", ObjectType: "iam_access_binding"},
			{Module: "iam", Resource: "role", ObjectType: "iam_role"},
		},
		Verbs: []catalog.VerbRow{
			{Module: "iam", Resource: "accessLabel", Verb: "apply"},
			{Module: "iam", Resource: "accessBinding", Verb: "create"},
			{Module: "iam", Resource: "role", Verb: "bind"},
		},
	}}, granteffect.ProjectorVersion)
	require.NoError(t, err)
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_actor"}
	const definition = "3d9cd5bf-906f-4bbe-8a8b-234ba2efa54a"
	const sibling = "4d9cd5bf-906f-4bbe-8a8b-234ba2efa54a"
	proposed := metadataPolicyBinding("proposed", actor, nil)
	proposed.Role.Rules = domain.Rules{{Module: "iam", Resources: []string{"accessLabel"}, Verbs: []string{"apply"}, ResourceNames: []string{definition}}}
	exact := bundle.Compile(proposed)
	require.True(t, exact.Complete(), "%+v", exact.Obligations())
	otherDefinition := proposed
	otherDefinition.Role.Rules = domain.Rules{{Module: "iam", Resources: []string{"accessLabel"}, Verbs: []string{"apply"}, ResourceNames: []string{sibling}}}
	otherScope := proposed
	otherScope.Scope = domain.ScopeAnchor{Type: "account", ID: "acc_other"}
	controls := proposed
	controls.Role.Rules = domain.Rules{
		{Module: "iam", Resources: []string{"accessBinding"}, Verbs: []string{"create"}},
		{Module: "iam", Resources: []string{"role"}, Verbs: []string{"bind"}, ResourceNames: []string{string(proposed.Role.ID)}},
	}
	controlEffects := bundle.Compile(controls)
	require.True(t, controlEffects.Complete(), "%+v", controlEffects.Obligations())
	question := func(kind domain.GrantCapabilityKind, role domain.RoleID, id domain.AccessLabelDefinitionID) string {
		ref, err := grantcapability.Encode(grantcapability.Coordinate{Kind: kind, Anchor: proposed.Scope, RoleID: role, DefinitionID: id})
		require.NoError(t, err)
		return ref.Relation + " " + ref.Object()
	}
	applyQuestion := question(domain.GrantCapabilityApplyAccessLabel, "", definition)
	createQuestion := question(domain.GrantCapabilityCreateBinding, "", "")
	bindQuestion := question(domain.GrantCapabilityBindRole, proposed.Role.ID, "")
	adminQuestion := "system_admin cluster:" + domain.ClusterSingletonID
	nativeFailure := errors.New("native apply unavailable")
	for _, gate := range []string{"role-content", "binding"} {
		for _, tc := range []struct {
			name       string
			effects    granteffect.Set
			allowApply bool
			stale      bool
			noApply    bool
			multiApply bool
			noAdmin    bool
			failure    error
			wantErr    error
			questions  []string
		}{
			{name: "exact", effects: exact, allowApply: true, questions: []string{applyQuestion, adminQuestion}},
			{name: "native-alone", effects: controlEffects, allowApply: true, wantErr: iamerr.ErrPermissionDenied},
			{name: "other-definition", effects: bundle.Compile(otherDefinition), allowApply: true, wantErr: iamerr.ErrPermissionDenied},
			{name: "other-scope", effects: bundle.Compile(otherScope), allowApply: true, wantErr: iamerr.ErrPermissionDenied},
			{name: "incomplete", allowApply: true, wantErr: iamerr.ErrUnavailable},
			{name: "stale", effects: exact, allowApply: true, stale: true, wantErr: iamerr.ErrUnavailable},
			{name: "native-denial", effects: exact, wantErr: iamerr.ErrPermissionDenied, questions: []string{applyQuestion}},
			{name: "native-error", effects: exact, failure: nativeFailure, wantErr: nativeFailure, questions: []string{applyQuestion}},
			{name: "every-definition", effects: exact, allowApply: true, multiApply: true, wantErr: iamerr.ErrPermissionDenied, questions: []string{applyQuestion}},
			{name: "create-and-bind-alone", effects: controlEffects, allowApply: true, noAdmin: true, wantErr: iamerr.ErrPermissionDenied},
			{name: "legacy-no-apply", noApply: true, questions: []string{adminQuestion}},
		} {
			t.Run(gate+"/"+tc.name, func(t *testing.T) {
				w := &accessLabelPolicyWriter{metadataPolicyWriter: metadataPolicyWriter{bundle: bundle, at: time.Now().UTC(), allow: map[string]bool{
					applyQuestion: tc.allowApply, adminQuestion: true, createQuestion: true, bindQuestion: true,
				}}, failure: tc.failure}
				proof := WitnessedLowerBound{bundle: bundle, at: w.at, effects: tc.effects}
				proof.census.Actor, proof.census.Identity = actor, bundle.Identity()
				if !tc.noAdmin {
					proof.census.Structural.Direct = []kaname.CanonicalDirectSource{{SourceKind: kaname.CanonicalClusterAdmin}}
				}
				if tc.stale {
					proof.at = proof.at.Add(-time.Nanosecond)
				}
				wanted := proposed
				if tc.noApply {
					wanted = controls
				}
				if tc.multiApply {
					wanted.Role.Rules = append(append(domain.Rules{}, proposed.Role.Rules...), otherDefinition.Role.Rules...)
				}
				var err error
				if gate == "binding" {
					err = requireBinding(ctx, w, proof, wanted)
				} else {
					err = requireRoleContent(ctx, w, proof, wanted)
				}
				if tc.wantErr == nil {
					require.NoError(t, err)
				} else {
					require.ErrorIs(t, err, tc.wantErr)
				}
				// Отказ должен предшествовать admin/create/bind и любому чтению scope.
				require.Equal(t, tc.questions, w.questions)
			})
		}
	}
}

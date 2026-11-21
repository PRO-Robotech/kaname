// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/stretchr/testify/require"
)

func TestResourceRefusalCaptureUsesSavedAuditScopeWithoutNewAdmission(t *testing.T) {
	c := parentCaptureFixture(t)
	parentCaptureObject(t, c, "tag", "tag-a", "", domain.WritePolicy{Pointers: []domain.ParentPointer{{Name: "item", Type: "item"}}})
	parentCaptureObject(t, c, "item", "item-a", "project-a", domain.WritePolicy{})
	parentCaptureProject(t, c, "project-a", "account-a")
	parentCaptureRows(t, c, resourceSourceKey{kind: resourceSourcePointerFacts, typ: "tag", id: "tag-a"}, map[string]any{"subject": "item:item-a", "relation": "item"})
	ctx := grpcsrv.WithCertIdentityIn(context.Background(), grpcsrv.NewTrustDomain("kaname.test"), "spiffe://kaname.test/ns/modules/sa/kacho-vpc", true)
	in := kaname.ResourceDecisionIntent{Action: kaname.ResourceDecisionRecordRefusal, Tuple: service.RelationTuple{User: "project:forged", Relation: "owner", Object: "tag:tag-a"}, Mirror: service.ResourceMirrorRow{ParentAccountID: "forged", ParentProjectID: "forged", ParentChain: []string{"project:forged"}}, RefusalOutcome: kaname.ResourceRefusalPermissionDenied}
	p, err := prepareResourceRefusal(ctx, c, in)
	require.NoError(t, err)
	require.Equal(t, "account-a", p.audit.row.ParentAccountID)
	require.Equal(t, "example.tag", p.audit.row.ObjectType)
	require.Equal(t, []string{"item:item-a", "project:project-a", "account:account-a"}, p.audit.hierarchies[0].Links)
	require.Nil(t, p.audit.footprint, "audit не получает registration authority plan")
	require.Empty(t, p.audit.newScopes)
	event := p.audit.registrationAudit(ctx, "iam.resource_registration.registered", string(in.RefusalOutcome))
	require.Equal(t, "permission_denied", event.Payload["outcome"])
	require.Equal(t, "account-a", event.TenantAccountID)
	_, _, err = c.hierarchies(ctx, "item:item-a")
	require.ErrorIs(t, err, domain.ErrParentHierarchyIncomplete, "неполный новый parent graph не препятствует аудиту отказа")
}

func TestResourceRefusalCaptureDoesNotForgeSuccessOrUnverifiedActor(t *testing.T) {
	c := parentCaptureFixture(t)
	in := kaname.ResourceDecisionIntent{Action: kaname.ResourceDecisionRecordRefusal, RefusalOutcome: kaname.ResourceRefusalOutcome("registered")}
	_, err := prepareResourceRefusal(context.Background(), c, in)
	require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
	in.RefusalOutcome = kaname.ResourceRefusalPermissionDenied
	_, err = prepareResourceRefusal(context.Background(), c, in)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	require.Empty(t, c.source.entries)
}

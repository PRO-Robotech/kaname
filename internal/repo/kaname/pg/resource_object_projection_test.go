// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func TestResourceObjectProjectionPersonUsesAllMembershipsNotLegacyHome(t *testing.T) {
	p := parentCaptureFixture(t)
	parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceIAMObject, typ: "iam.user", id: "person"}, map[string]any{"id": "person", "account_id": "legacy-home", "labels": map[string]string{"team": "blue"}})
	parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceUserMemberships, typ: "iam.user", id: "person"}, map[string]any{"user_id": "person", "account_id": "account-b", "status": "PENDING"}, map[string]any{"user_id": "person", "account_id": "account-a", "status": "ACTIVE"})
	object, present, err := p.captureObjectProjection(context.Background(), "iam.user", "person")
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, []string{"account-a", "account-b"}, object.ParentAccountIDs)
	require.NotContains(t, object.ParentAccountIDs, "legacy-home")
	require.Equal(t, map[string]string{"team": "blue"}, object.Labels)
}

func TestResourceObjectProjectionKeepsCreatorAndProjectAccountSemantics(t *testing.T) {
	p := parentCaptureFixture(t)
	parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceIAMObject, typ: "iam.serviceAccount", id: "child"}, map[string]any{"id": "child", "account_id": "account", "created_by_type": "service_account", "created_by_id": "creator"})
	object, present, err := p.captureObjectProjection(context.Background(), "iam.serviceAccount", "child")
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, "service_account:creator", object.CreatedBy)
	require.Equal(t, []string{"account"}, object.ParentAccountIDs)
	parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceIAMObject, typ: "iam.role", id: "role"}, map[string]any{"id": "role", "project_id": "project", "account_id": nil})
	parentCaptureProject(t, p, "project", "current-account")
	object, present, err = p.captureObjectProjection(context.Background(), "iam.role", "role")
	require.NoError(t, err)
	require.True(t, present)
	require.Equal(t, domain.MirrorObject{ObjectType: "iam.role", ObjectID: "role", ParentProjectID: "project", ParentAccountIDs: []string{"current-account"}}, object)
}

func TestResourceObjectProjectionMissingAndForeignCapturedRows(t *testing.T) {
	p := parentCaptureFixture(t)
	parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceMirror, typ: "vpc.network", id: "gone"})
	_, present, err := p.captureObjectProjection(context.Background(), "vpc.network", "gone")
	require.NoError(t, err)
	require.False(t, present)
	parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceIAMObject, typ: "iam.account", id: "wanted"}, map[string]any{"id": "different"})
	_, _, err = p.captureObjectProjection(context.Background(), "iam.account", "wanted")
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

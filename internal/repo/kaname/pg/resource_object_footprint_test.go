// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestResourceObjectFootprintKeepsRetainedOldAccountWithoutProjectLookup(t *testing.T) {
	for _, present := range []bool{false, true} {
		name := "deleted"
		if present {
			name = "moved"
		}
		t.Run(name, func(t *testing.T) {
			p := parentCaptureFixture(t)
			key := resourceSourceKey{kind: resourceSourceMirror, typ: "vpc.network", id: "net"}
			if present {
				parentCaptureRows(t, p, key, map[string]any{"object_type": "vpc.network", "object_id": "net", "parent_account_id": "new-account"})
			} else {
				parentCaptureRows(t, p, key)
			}
			parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceRegistrationScopes, typ: "network", id: "net"}, map[string]any{"object_type": "network", "object_id": "net", "project_id": "deleted-project", "account_id": "old-account"})
			parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceAccount, typ: "account", id: "old-account"}, map[string]any{"id": "old-account"})
			if present {
				parentCaptureRows(t, p, resourceSourceKey{kind: resourceSourceAccount, typ: "account", id: "new-account"}, map[string]any{"id": "new-account"})
			}
			output := &resourceOutputCapture{object: domain.ResourceRef{Type: "vpc.network", ID: "net"}, modelType: "network"}
			footprint := newResourceFootprint()
			require.NoError(t, footprint.addObject(output.object))
			require.NoError(t, output.addObjectScopes(context.Background(), p, footprint))
			plan, err := footprint.local()
			require.NoError(t, err)
			expected := []domain.AccountID{"old-account"}
			if present {
				expected = []domain.AccountID{"new-account", "old-account"}
			}
			require.Equal(t, expected, plan.plan.Accounts)
			require.Empty(t, plan.registration, "foreign OUTPUT scope не создаёт installation-требование")
			_, readProject := p.source.entries[resourceSourceKey{kind: resourceSourceProject, typ: "project", id: "deleted-project"}]
			require.False(t, readProject, "retained OLD account не заменяется текущим владельцем исчезнувшего project")
		})
	}
}

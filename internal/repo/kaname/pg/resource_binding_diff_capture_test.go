// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func TestResourceBindingDiffCoordinatesRetainsOrphanAndStructuralLedger(t *testing.T) {
	members := []resourceSourceRow{{value: json.RawMessage(`{"binding_id":"abn_one","object_type":"vpc.subnet","object_id":"shared-id"}`)}}
	ledger := []resourceSourceRow{
		{value: json.RawMessage(`{"binding_id":"abn_one","member_object_type":"vpc.network","member_object_id":"shared-id","fga_user":"user:usr_one","relation":"viewer","object":"network:shared-id"}`)},
		{value: json.RawMessage(`{"binding_id":"abn_one","member_object_type":"","member_object_id":"","fga_user":"user:usr_one","relation":"member","object":"access_binding:abn_one"}`)},
	}
	coordinates, rows, err := resourceBindingDiffCoordinates("abn_one", members, ledger)
	require.NoError(t, err)
	require.Equal(t, map[domain.ResourceRef]bool{{Type: "vpc.subnet", ID: "shared-id"}: true, {Type: "vpc.network", ID: "shared-id"}: true}, coordinates)
	require.Len(t, rows, 2)
	require.Empty(t, rows[1].Member.ObjectType)
	require.Equal(t, "access_binding:abn_one", rows[1].Tuple.Object)
	// Исчезновение member не теряет его последний ledger-источник отзыва.
	delete(coordinates, domain.ResourceRef{Type: "vpc.subnet", ID: "shared-id"})
	orphan, again, err := resourceBindingDiffCoordinates("abn_one", nil, ledger)
	require.NoError(t, err)
	require.Equal(t, coordinates, orphan)
	require.Equal(t, rows, again)
}

func TestResourceBindingDiffCoordinatesRejectsCrossBindingAndPartialKeys(t *testing.T) {
	for name, raw := range map[string]string{
		"foreign carrier": `{"binding_id":"abn_other","member_object_type":"vpc.subnet","member_object_id":"sub_one","fga_user":"user:usr_one","relation":"viewer","object":"subnet:sub_one"}`,
		"half structural": `{"binding_id":"abn_one","member_object_type":"","member_object_id":"sub_one","fga_user":"user:usr_one","relation":"viewer","object":"subnet:sub_one"}`,
		"missing tuple":   `{"binding_id":"abn_one","member_object_type":"vpc.subnet","member_object_id":"sub_one","fga_user":"user:usr_one","relation":"viewer","object":""}`,
	} {
		t.Run(name, func(t *testing.T) {
			_, _, err := resourceBindingDiffCoordinates("abn_one", nil, []resourceSourceRow{{value: json.RawMessage(raw)}})
			require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
		})
	}
}

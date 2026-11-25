// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func TestPreparedMetadataPatchKeepsLabelNamespacesIndependent(t *testing.T) {
	base := metadataMutation{kind: "account", table: "accounts", typ: "account",
		name: "current", labels: domain.Labels{"team": "ordinary"}, accessLabels: domain.Labels{"team": "protected"}}
	for _, tc := range []struct {
		name string
		mode metadataMutationMode
		mask []string
		want string
	}{
		{"legacy_patch", metadataMutationOrdinary, nil, `{"description":"","labels":{"team":"ordinary"},"name":"current"}`},
		{"only_protected", metadataMutationAccessLabels, []string{"access_labels"}, `{"access_labels":{"team":"protected"}}`},
		{"both_maps", metadataMutationAccessLabels, []string{"labels", "access_labels"}, `{"access_labels":{"team":"protected"},"labels":{"team":"ordinary"}}`},
		{"empty_description", metadataMutationOrdinary, []string{"description"}, `{"description":""}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			req := base
			req.mode, req.mask = tc.mode, tc.mask
			patch, err := prepareMetadataMutationPatch(req)
			require.NoError(t, err)
			raw, err := json.Marshal(patch)
			require.NoError(t, err)
			require.Equal(t, tc.want, string(raw))
		})
	}
	base.mask = []string{"access_labels"}
	_, err := prepareMetadataMutationPatch(base)
	require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
	base.mode = metadataMutationAccessLabels
	base.accessLabels = nil
	patch, err := prepareMetadataMutationPatch(base)
	require.NoError(t, err)
	require.Equal(t, json.RawMessage(`{}`), patch.AccessLabels)
	require.Nil(t, patch.Labels)
}

func TestProtectedMetadataUpdateKeepsExactPreparedFields(t *testing.T) {
	request := metadataMutation{kind: "project", table: "projects", typ: "project", id: "prj1",
		mode: metadataMutationAccessLabels, accessLabels: domain.Labels{"team": "a"}}
	for _, mask := range [][]string{{"access_labels"}, {"access_labels", "description"}} {
		request.mask = mask
		patch, err := prepareMetadataMutationPatch(request)
		require.NoError(t, err)
		encoded, err := json.Marshal(patch)
		require.NoError(t, err)
		command := &metadataProtectedWrite{root: request.catalogRef(), patch: encoded}
		ordinary, err := command.ordinaryMask(request)
		require.NoError(t, err)
		require.Equal(t, mask[1:], ordinary)
		require.Equal(t, "access_labels", mask[0])

		other := request
		other.id = "prj2"
		_, err = command.ordinaryMask(other)
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
		other = request
		other.accessLabels = domain.Labels{"team": "b"}
		_, err = command.ordinaryMask(other)
		require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	}
	// Нельзя получить обычную команду или пустую проверку эффектов для
	// одноимённого объекта из другой физической таблицы.
	foreign := request
	foreign.table = "resource_mirror"
	for _, mode := range []metadataMutationMode{metadataMutationOrdinary, metadataMutationAccessLabels} {
		foreign.mode = mode
		_, err := prepareMetadataMutationPatch(foreign)
		require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
	}
	_, err := captureMetadataGrant(context.Background(), nil, nil, foreign, mirrorMetadataScope{}, 1, nil, nil, json.RawMessage(`{}`))
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
}

func TestExternalMetadataPatchRequiresExactProtectedFields(t *testing.T) {
	req := metadataMutation{
		kind: "vpc.network", table: "resource_mirror", id: "network/demo",
		mode: metadataMutationAccessLabels, labels: domain.Labels{"team": "ordinary"},
		mask: []string{"labels", "access_labels"},
	}
	patch, err := prepareMetadataMutationPatch(req)
	require.NoError(t, err)
	require.JSONEq(t, `{"team":"ordinary"}`, string(patch.Labels))
	require.JSONEq(t, `{}`, string(patch.AccessLabels))
	encoded, err := json.Marshal(patch)
	require.NoError(t, err)
	prepared := metadataProtectedWrite{root: req.catalogRef(), patch: encoded}
	mask, err := prepared.ordinaryMask(req)
	require.NoError(t, err)
	require.Equal(t, []string{"labels"}, mask)
	peer := req
	peer.kind = "vpc.subnet"
	_, err = prepared.ordinaryMask(peer)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	peer = req
	peer.id = "network/peer"
	_, err = prepared.ordinaryMask(peer)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	for _, field := range []string{"name", "description", "parentProjectId", "resourceId"} {
		req.mask = []string{"access_labels", field}
		_, err = prepareMetadataMutationPatch(req)
		require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan, field)
	}
	req.mask = []string{"access_labels"}
	req.kind = "iam.project"
	_, err = prepareMetadataMutationPatch(req)
	require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
}

func TestServiceAccountProtectedCapabilityAndMixedClear(t *testing.T) {
	var ordinary any = &MetadataMutationWriters{}
	_, ok := ordinary.(kaname.ServiceAccountAccessLabelsWriterFactory)
	require.False(t, ok)
	var existing any = &accessLabelMetadataWriters{}
	_, ok = existing.(kaname.ServiceAccountAccessLabelsWriterFactory)
	require.False(t, ok, "account/project readiness cannot advertise service account capability")
	var installed any = &serviceAccountAccessLabelMetadataWriters{}
	_, ok = installed.(kaname.ServiceAccountAccessLabelsWriterFactory)
	require.True(t, ok)
	request := metadataMutation{kind: "service_account", table: "service_accounts", typ: "iam_service_account", id: "sva-root",
		mode: metadataMutationAccessLabels, labels: domain.Labels{"ordinary": "keep"}, mask: []string{"labels", "access_labels"}}
	patch, err := prepareMetadataMutationPatch(request)
	require.NoError(t, err)
	require.JSONEq(t, `{}`, string(patch.AccessLabels))
	require.JSONEq(t, `{"ordinary":"keep"}`, string(patch.Labels))
	encoded, err := json.Marshal(patch)
	require.NoError(t, err)
	command := metadataProtectedWrite{root: request.catalogRef(), patch: encoded}
	mask, err := command.ordinaryMask(request)
	require.NoError(t, err)
	require.Equal(t, []string{"labels"}, mask)
	request.accessLabels = domain.Labels{"unexpected": "value"}
	_, err = command.ordinaryMask(request)
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	request.typ = "service_account"
	_, err = prepareMetadataMutationPatch(request)
	require.ErrorIs(t, err, kaname.ErrInvalidAuthorityFencePlan)
}

func TestMirrorMetadataRequestPreservesImplicitMapsAndExplicitClears(t *testing.T) {
	root := domain.ResourceRef{Type: "vpc.network", ID: "n/shared"}
	ordinary := domain.Labels{"team": "app"}
	access := domain.Labels{"team": "secret"}
	for _, tc := range []struct {
		name           string
		labels, access domain.Labels
		mask           []string
		want           string
	}{
		{"absent", nil, nil, nil, `{}`},
		{"empty_body", domain.Labels{}, domain.Labels{}, nil, `{}`},
		{"implicit_labels", ordinary, nil, nil, `{"labels":{"team":"app"}}`},
		{"implicit_access", nil, access, nil, `{"access_labels":{"team":"secret"}}`},
		{"implicit_both", ordinary, access, nil, `{"labels":{"team":"app"},"access_labels":{"team":"secret"}}`},
		{"clear_only_labels", nil, access, []string{"labels"}, `{"labels":{}}`},
		{"clear_only_access", ordinary, nil, []string{"access_labels"}, `{"access_labels":{}}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			request := mirrorMetadataRequest(root, tc.labels, tc.access, tc.mask)
			patch, err := prepareMetadataMutationPatch(request)
			require.NoError(t, err)
			raw, err := json.Marshal(patch)
			require.NoError(t, err)
			require.JSONEq(t, tc.want, string(raw))
		})
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_metadata

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	authzv1 "github.com/PRO-Robotech/corelib/api/corelib/authz/v1"
	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/fieldmaskpb"
)

type metadataUpdateClient struct {
	iamv1.ResourceMetadataServiceClient
	request *iamv1.UpdateResourceMetadataRequest
}

func (c *metadataUpdateClient) Update(_ context.Context, req *iamv1.UpdateResourceMetadataRequest, _ ...grpc.CallOption) (*operationpb.Operation, error) {
	c.request = req
	return &operationpb.Operation{}, nil
}

func TestMetadataUpdateRouteAndDeclaredACR(t *testing.T) {
	method := iamv1.File_kaname_cloud_iam_v1_resource_metadata_service_proto.Services().ByName("ResourceMetadataService").Methods().ByName("Update")
	require.NotNil(t, method)
	require.Equal(t, "<exempt>", proto.GetExtension(method.Options(), authzv1.E_Permission))
	require.Equal(t, "HANDLER_DECIDES", proto.GetExtension(method.Options(), authzv1.E_ExemptReason))
	require.Equal(t, "1", proto.GetExtension(method.Options(), authzv1.E_RequiredAcrMin))
	mux := runtime.NewServeMux()
	client := &metadataUpdateClient{}
	require.NoError(t, iamv1.RegisterResourceMetadataServiceHandlerClient(context.Background(), mux, client))
	w := httptest.NewRecorder()
	mux.ServeHTTP(w, httptest.NewRequest(http.MethodPatch,
		"/iam/v1/resourceMetadata/registry.registries?resourceId=registry%2Fdemo%252Fchild&patch.accessLabels.injected=yes&resourceType=wrong.type",
		strings.NewReader(`{"updateMask":"accessLabels","accessLabels":{}}`)))
	require.Equal(t, http.StatusOK, w.Code, w.Body.String())
	require.NotNil(t, client.request)
	require.Equal(t, "registry.registries", client.request.GetResourceType())
	require.Equal(t, "registry/demo%2Fchild", client.request.GetResourceId())
	require.Equal(t, []string{"access_labels"}, client.request.GetPatch().GetUpdateMask().GetPaths())
	require.Empty(t, client.request.GetPatch().GetAccessLabels(), "query не меняет тело patch")
}

func TestMetadataUpdateMaskPreservesReplacesAndClears(t *testing.T) {
	for _, tc := range []struct {
		name                     string
		patch                    *iamv1.ResourceMetadataPatch
		labelsApply, accessApply bool
		bad                      bool
	}{
		{"absent", nil, false, false, false},
		{"empty_maps_without_mask", &iamv1.ResourceMetadataPatch{Labels: map[string]string{}, AccessLabels: map[string]string{}}, false, false, false},
		{"clear_labels", &iamv1.ResourceMetadataPatch{UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}}}, true, false, false},
		{"clear_access", &iamv1.ResourceMetadataPatch{UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"accessLabels"}}}, false, true, false},
		{"replace_both", &iamv1.ResourceMetadataPatch{Labels: map[string]string{"team": "ordinary"}, AccessLabels: map[string]string{"team": "protected"}}, true, true, false},
		{"unselected_access", &iamv1.ResourceMetadataPatch{UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"labels"}}, AccessLabels: map[string]string{"team": "ignored"}}, true, false, false},
		{"coordinate_immutable", &iamv1.ResourceMetadataPatch{UpdateMask: &fieldmaskpb.FieldMask{Paths: []string{"resource_id"}}}, false, false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			labels, access, _, err := parseMetadataPatch(tc.patch)
			if tc.bad {
				require.Error(t, err)
				return
			}
			require.NoError(t, err)
			require.Equal(t, tc.labelsApply, labels != nil)
			require.Equal(t, tc.accessApply, access != nil)
		})
	}
}

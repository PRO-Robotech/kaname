// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package resource_metadata

import (
	"context"
	"encoding/json"
	"errors"
	operationpb "github.com/PRO-Robotech/corelib/api/corelib/operation"
	"net/http"
	"net/http/httptest"
	"testing"

	authzv1 "github.com/PRO-Robotech/corelib/api/corelib/authz/v1"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestResourceMetadataContract(t *testing.T) {
	service := iamv1.File_kaname_cloud_iam_v1_resource_metadata_service_proto.Services().ByName("ResourceMetadataService")
	if service == nil || service.Methods().Len() != 2 {
		t.Fatal("metadata service must expose Get and Update")
	}
	method := service.Methods().ByName("Get")
	for _, tc := range []struct {
		ext  protoreflect.ExtensionType
		want string
	}{
		{authzv1.E_Permission, "<exempt>"},
		{authzv1.E_ExemptReason, "HANDLER_DECIDES"},
		{authzv1.E_RequiredAcrMin, "1"},
	} {
		if got := proto.GetExtension(method.Options(), tc.ext); got != tc.want {
			t.Errorf("annotation %s = %v, want %s", tc.ext.TypeDescriptor().FullName(), got, tc.want)
		}
	}
	httpRule := proto.GetExtension(method.Options(), annotations.E_Http).(*annotations.HttpRule)
	if got := httpRule.GetGet(); got != "/iam/v1/resourceMetadata/{resource_type}" {
		t.Errorf("unexpected GET route: %q", got)
	}
	fields := method.Input().Fields()
	if fields.Len() != 2 || fields.ByName("resource_type") == nil || fields.ByName("resource_id") == nil {
		t.Fatal("request must carry only resource type and id")
	}
	if method.Output().FullName() != "kaname.cloud.iam.v1.ResourceMetadata" {
		t.Fatalf("unexpected response: %s", method.Output().FullName())
	}
}

type metadataClient struct {
	t     *testing.T
	calls int
	empty bool
}

func (c *metadataClient) Get(_ context.Context, req *iamv1.GetResourceMetadataRequest, _ ...grpc.CallOption) (*iamv1.ResourceMetadata, error) {
	c.calls++
	if req.GetResourceType() != "registry.registries" || req.GetResourceId() != "registry/demo:tag" {
		c.t.Fatalf("path decoded incorrectly: %v", req)
	}
	result := &iamv1.ResourceMetadata{
		ResourceType: req.GetResourceType(), ResourceId: req.GetResourceId(),
	}
	if !c.empty {
		result.Labels = map[string]string{"purpose": "display"}
		result.AccessLabels = map[string]string{"purpose": "access"}
	}
	return result, nil
}

func TestRESTGetReturnsTopLevelMetadataMaps(t *testing.T) {
	const route = "/iam/v1/resourceMetadata/registry.registries?resourceId=registry%2Fdemo%3Atag"
	mux := runtime.NewServeMux()
	client := &metadataClient{t: t}
	if err := iamv1.RegisterResourceMetadataServiceHandlerClient(context.Background(), mux, client); err != nil {
		t.Fatal(err)
	}
	response := httptest.NewRecorder()
	mux.ServeHTTP(response, httptest.NewRequest(http.MethodGet, route, nil))
	if response.Code != http.StatusOK || client.calls != 1 {
		t.Fatalf("GET = %d, calls = %d: %s", response.Code, client.calls, response.Body.String())
	}
	var got struct {
		ResourceType string            `json:"resourceType"`
		ResourceID   string            `json:"resourceId"`
		Labels       map[string]string `json:"labels"`
		AccessLabels map[string]string `json:"accessLabels"`
	}
	if err := json.Unmarshal(response.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got.ResourceType != "registry.registries" || got.ResourceID != "registry/demo:tag" || got.Labels["purpose"] != "display" || got.AccessLabels["purpose"] != "access" {
		t.Fatalf("unexpected REST response: %s", response.Body.String())
	}
	client.empty = true
	empty := httptest.NewRecorder()
	mux.ServeHTTP(empty, httptest.NewRequest(http.MethodGet, route, nil))
	var raw map[string]json.RawMessage
	if err := json.Unmarshal(empty.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if empty.Code != http.StatusOK || client.calls != 2 || string(raw["labels"]) != "{}" || string(raw["accessLabels"]) != "{}" {
		t.Fatalf("unexpected empty REST response: %d, calls = %d: %s", empty.Code, client.calls, empty.Body.String())
	}
}

func (c *metadataClient) Update(context.Context, *iamv1.UpdateResourceMetadataRequest, ...grpc.CallOption) (*operationpb.Operation, error) {
	return nil, errors.New("unexpected metadata Update in Get test")
}

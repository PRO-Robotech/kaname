// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// interceptor_kac184_test.go — AuthorizeService.ListObjects (and symmetric
// ListSubjects) must be reachable for anonymous callers because they are
// invoked service-to-service from vpc/compute bootstrap paths without
// PerRPCCredentials. They are listed in whitelistFullMethod for that reason;
// production-strict cross-pod authn is delivered later via mTLS.
//
// Suffix-match on "List" intentionally does NOT match "ListObjects" — see the
// readonlySuffixes contract in interceptor.go (HasSuffix on "List" would only
// match names ending in exactly "List"; "ListObjects"/"ListSubjects" do not,
// so they fall through to default-deny). Hence the FullMethod whitelist entry
// is required.
package authzguard

import (
	"log/slog"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// Test_Authzguard_ListObjects_AnonymousCaller_AllowedByWhitelist —
// vpc/cmd/vpc/main.go calls AuthorizeService.ListObjects without
// PerRPCCredentials. Interceptor must allow it (whitelist entry).
func Test_Authzguard_ListObjects_AnonymousCaller_AllowedByWhitelist(t *testing.T) {
	iceptor := AntiAnonymousUnary(slog.Default())
	fm := "/kacho.cloud.iam.v1.AuthorizeService/ListObjects"
	_, err := iceptor(anonCtx(), nil,
		&grpc.UnaryServerInfo{FullMethod: fm}, fakeHandler)
	if err != nil {
		t.Fatalf("%s must be whitelist-allowed for anonymous (peer call from vpc/compute bootstrap), got %v", fm, err)
	}
}

// Test_Authzguard_ListSubjects_AnonymousCaller_AllowedByWhitelist — symmetric
// to ListObjects. AuthorizeService.ListSubjects is the inverse query (for a
// resource → which subjects can <verb> it?) used by the same peer-bootstrap
// flow; whitelisting both together avoids the same regression class.
func Test_Authzguard_ListSubjects_AnonymousCaller_AllowedByWhitelist(t *testing.T) {
	iceptor := AntiAnonymousUnary(slog.Default())
	fm := "/kacho.cloud.iam.v1.AuthorizeService/ListSubjects"
	_, err := iceptor(anonCtx(), nil,
		&grpc.UnaryServerInfo{FullMethod: fm}, fakeHandler)
	if err != nil {
		t.Fatalf("%s must be whitelist-allowed for anonymous (symmetric to ListObjects), got %v", fm, err)
	}
}

// Test_Authzguard_OtherMethod_AnonymousCaller_StillBlocked — negative control:
// the whitelist addition for ListObjects/ListSubjects must NOT relax the
// default-deny posture for unrelated mutating RPCs. UserService.Create is the
// canonical mutating RPC; anonymous callers must still receive PermissionDenied.
func Test_Authzguard_OtherMethod_AnonymousCaller_StillBlocked(t *testing.T) {
	iceptor := AntiAnonymousUnary(slog.Default())
	fm := "/kacho.cloud.iam.v1.UserService/Create"
	_, err := iceptor(anonCtx(), nil,
		&grpc.UnaryServerInfo{FullMethod: fm}, fakeHandler)
	if status.Code(err) != codes.PermissionDenied {
		t.Fatalf("negative control: %s anonymous → expected PermissionDenied, got %v", fm, err)
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// anon_table_test.go — anti-anonymous regression table.
//
// Reflection-based enumeration of every iam gRPC FullMethod, exercising the
// anti-anon interceptor with an anonymous principal. Catches future
// regressions: any new RPC added without a read-only suffix that is also not
// in `whitelistFullMethod` will be denied for anonymous (correct default).
//
// The table is built from the protobuf service-registry (protoreflect global
// files), which catalogues every service/method compiled into the binary
// regardless of whether a handler is registered. This means the test catches
// gaps even when a service isn't wired into main.go yet — a stronger guarantee
// than walking a live grpc.Server.
package authzguard

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	// Blank-import the iam proto package so its FileDescriptors register into
	// protoregistry.GlobalFiles. Without this the test would only enumerate
	// protos transitively imported by this package — incomplete.
	_ "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

// iamServicePrefix — only enumerate services in the iam proto package.
const iamServicePrefix = "kacho.cloud.iam.v1."

// TestAnonTable_AllFullMethodsClassified walks every method in
// kacho.cloud.iam.v1.* and asserts that anonymous callers reach the handler
// (read-only or whitelisted) OR are denied (everything else).
//
// Failures here signal one of:
//
//	(a) A new mutating RPC was added without being marked read-only or
//	    whitelisted → anonymous can call it → security hole.
//	(b) A new read-only RPC was misclassified as mutating → users get spurious
//	    PermissionDenied → UX bug.
//
// Either failure should be fixed by adjusting `readonlySuffixes` or
// `whitelistFullMethod` consciously, NOT by weakening this test.
func TestAnonTable_AllFullMethodsClassified(t *testing.T) {
	iceptor := AntiAnonymousUnary(nil)
	anon := anonCtxTable()
	handler := func(_ context.Context, _ any) (any, error) { return "ok", nil }

	count := 0
	var enumeratedNames []string

	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		services := fd.Services()
		for i := 0; i < services.Len(); i++ {
			svc := services.Get(i)
			fullSvcName := string(svc.FullName())
			if !strings.HasPrefix(fullSvcName, iamServicePrefix) {
				continue
			}
			methods := svc.Methods()
			for j := 0; j < methods.Len(); j++ {
				m := methods.Get(j)
				fm := "/" + fullSvcName + "/" + string(m.Name())
				count++
				enumeratedNames = append(enumeratedNames, fm)

				_, isWhitelist := whitelistFullMethod[fm]
				readOnly := isReadOnly(fm)

				_, err := iceptor(anon, nil,
					&grpc.UnaryServerInfo{FullMethod: fm}, handler)

				switch {
				case isWhitelist || readOnly:
					// Anonymous must reach handler — no error from interceptor.
					if err != nil {
						t.Errorf("FullMethod %s — classified as read-only/whitelist but interceptor returned err=%v", fm, err)
					}
				default:
					// Mutating — anonymous must be denied.
					if status.Code(err) != codes.PermissionDenied {
						t.Errorf("FullMethod %s — classified as mutating but anonymous NOT denied (err=%v); add to readonlySuffixes / whitelistFullMethod if intended, else fix suffix-detection", fm, err)
					}
				}
			}
		}
		return true
	})

	// Sanity: at least 50 iam RPCs enumerated (iam has 25+ services). If this
	// drops sharply, the proto registry likely failed to load.
	if count < 50 {
		t.Errorf("expected >=50 iam FullMethods enumerated, got %d (proto registry incomplete?)", count)
	}
	t.Logf("ANON-TABLE: enumerated %d iam FullMethods", count)
}

func anonCtxTable() context.Context {
	return anonCtx()
}

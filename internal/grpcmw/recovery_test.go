// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package grpcmw

import (
	"context"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestUnaryRecovery_RecoversPanic — a panicking handler must not propagate the
// panic (which would crash the process); the interceptor returns codes.Internal
// with a fixed, leak-free message.
func TestUnaryRecovery_RecoversPanic(t *testing.T) {
	intr := UnaryRecovery(nil)
	info := &grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.InternalIAMService/Check"}

	resp, err := intr(context.Background(), "req", info, func(context.Context, any) (any, error) {
		panic("simulated crypto/rand failure")
	})
	if resp != nil {
		t.Errorf("resp = %v; want nil on recovered panic", resp)
	}
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v; want Internal", status.Code(err))
	}
	if got := status.Convert(err).Message(); got != "internal error" {
		t.Errorf("message = %q; want fixed leak-free text", got)
	}
}

// TestUnaryRecovery_PassThrough — a normal (non-panicking) handler result is
// returned untouched.
func TestUnaryRecovery_PassThrough(t *testing.T) {
	intr := UnaryRecovery(nil)
	info := &grpc.UnaryServerInfo{FullMethod: "/svc/M"}

	resp, err := intr(context.Background(), "req", info, func(context.Context, any) (any, error) {
		return "ok", nil
	})
	if err != nil {
		t.Fatalf("unexpected err: %v", err)
	}
	if resp != "ok" {
		t.Errorf("resp = %v; want pass-through \"ok\"", resp)
	}
}

// TestStreamRecovery_RecoversPanic — stream-side counterpart.
func TestStreamRecovery_RecoversPanic(t *testing.T) {
	intr := StreamRecovery(nil)
	info := &grpc.StreamServerInfo{FullMethod: "/svc/S"}

	err := intr(nil, nil, info, func(any, grpc.ServerStream) error {
		panic("boom")
	})
	if status.Code(err) != codes.Internal {
		t.Fatalf("code = %v; want Internal", status.Code(err))
	}
}

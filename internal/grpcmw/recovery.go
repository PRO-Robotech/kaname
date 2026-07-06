// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package grpcmw — local gRPC interceptors not provided by kacho-corelib.
//
// recovery.go — a panic-recovery interceptor. gRPC does NOT recover handler
// panics by default, and corelib grpcsrv.NewServer injects none, so any
// unhandled panic in a unary/stream handler (or an inner interceptor) unwinds
// past the server goroutine and terminates the whole process. kacho-iam is the
// platform-wide authz PDP (InternalIAMService.Check answers on every RPC of
// every service), so a single bad request must never crash the PDP and
// fail-closed the entire cluster (CWE-248 / security.md availability). This
// interceptor turns a panic into a logged codes.Internal for that one request.
package grpcmw

import (
	"context"
	"log/slog"
	"runtime/debug"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// recoveredErr is the fixed, leak-free error a recovered panic surfaces to the
// client. The panic value + stack go to the server log only (never the wire).
func recoveredErr() error {
	return status.Error(codes.Internal, "internal error")
}

// logPanic records the recovered panic with its method and stack for
// server-side diagnosis. Never includes the panic detail in the returned error.
func logPanic(logger *slog.Logger, method string, r any) {
	if logger == nil {
		return
	}
	logger.Error("recovered panic in gRPC handler",
		"method", method,
		"panic", r,
		"stack", string(debug.Stack()))
}

// UnaryRecovery returns a unary interceptor that recovers a panic from any
// downstream interceptor or the handler, logs it, and returns codes.Internal.
// Wire it as the outermost SECURITY link (immediately after the metrics
// interceptor) so it protects the whole authz interceptor chain + handler while
// metrics still records the resulting code.
func UnaryRecovery(logger *slog.Logger) grpc.UnaryServerInterceptor {
	return func(ctx context.Context, req any, info *grpc.UnaryServerInfo, handler grpc.UnaryHandler) (resp any, err error) {
		defer func() {
			if r := recover(); r != nil {
				logPanic(logger, info.FullMethod, r)
				resp = nil
				err = recoveredErr()
			}
		}()
		return handler(ctx, req)
	}
}

// StreamRecovery is the stream-side counterpart of UnaryRecovery.
func StreamRecovery(logger *slog.Logger) grpc.StreamServerInterceptor {
	return func(srv any, ss grpc.ServerStream, info *grpc.StreamServerInfo, handler grpc.StreamHandler) (err error) {
		defer func() {
			if r := recover(); r != nil {
				logPanic(logger, info.FullMethod, r)
				err = recoveredErr()
			}
		}()
		return handler(srv, ss)
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service_account

// handler_serves_actions_test.go — the handler's own methods are what gRPC calls,
// not the Unimplemented stubs it embeds.
//
// WHY THIS NEEDS ITS OWN TEST. The generated server interface is satisfied by
// the embedded `UnimplementedServiceAccountServiceServer`. A handler method
// whose signature does not match exactly therefore does NOT fail the build — it
// simply never overrides. Every layer below stays green (use-case tests, repo
// tests, the whole issuance loop), the catalog and the route table both list the
// RPC, and every call answers `Unimplemented` at runtime. That is the one gap
// the rest of this change's tests structurally cannot see, because none of them
// enter through the transport.
//
// The discriminator is the STATUS CODE, and it is chosen so it cannot pass by
// accident: an anonymous context makes this handler's own method return
// `PermissionDenied` from the anti-anonymous floor — first statement, before any
// dependency is touched — while the embedded stub returns `Unimplemented`
// regardless of context. The two are never the same answer.

import (
	"context"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
)

func TestHandlerServesDisableAndEnable(t *testing.T) {
	// Nil use-cases on purpose: the anti-anonymous floor answers before any of
	// them is dereferenced, so the probe needs no fixture to be decisive.
	var srv iamv1.ServiceAccountServiceServer = NewHandler(
		nil, nil, nil, nil, nil,
		NewDisableServiceAccountUseCase(nil, nil),
		NewEnableServiceAccountUseCase(nil, nil),
	)

	t.Run("disable", func(t *testing.T) {
		_, err := srv.Disable(context.Background(), &iamv1.DisableServiceAccountRequest{
			ServiceAccountId: negSaID,
		})
		requireHandlerAnswered(t, err, "Disable")
	})
	t.Run("enable", func(t *testing.T) {
		_, err := srv.Enable(context.Background(), &iamv1.EnableServiceAccountRequest{
			ServiceAccountId: negSaID,
		})
		requireHandlerAnswered(t, err, "Enable")
	})
}

func requireHandlerAnswered(t *testing.T, err error, method string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: anonymous caller must be refused", method)
	}
	switch code := status.Code(err); code {
	case codes.PermissionDenied:
		// The handler's own method ran and its anti-anonymous floor answered.
	case codes.Unimplemented:
		t.Fatalf("%s: the embedded Unimplemented stub answered — the handler method does not "+
			"override it. The RPC is declared, routed and catalogued, and it would return "+
			"Unimplemented to every caller. Check the method signature against the generated "+
			"server interface.", method)
	default:
		t.Fatalf("%s: unexpected code %s (%v) — expected PermissionDenied from the "+
			"anti-anonymous floor", method, code, err)
	}
}

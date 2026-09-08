// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

// handler_serves_actions_test.go — the handler's own methods are what gRPC calls,
// not the Unimplemented stubs it embeds.
//
// WHY THIS NEEDS ITS OWN TEST. The generated server interface is satisfied by the
// embedded `UnimplementedUserServiceServer`. A handler method whose signature
// does not match exactly therefore does NOT fail the build — it simply never
// overrides. Every layer below stays green (use-case tests, repo tests, the whole
// issuance loop), the catalog and the route table both list the RPC, and every
// call answers `Unimplemented` at runtime. That is the one gap the rest of this
// change's tests structurally cannot see, because none of them enter through the
// transport.
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

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// actionsUserID — a well-formed user id. Well-formed on purpose: a malformed one
// would also be refused, but by the format check rather than by the floor, and
// then the probe would pass without the floor ever running.
const actionsUserID = "usr000000000000actns"

// actionsAccountID — well-formed account id, по той же причине, что и
// `actionsUserID`: отказ по формату прошёл бы мимо пола и оставил бы пробу
// зелёной, ни разу его не позвав.
const actionsAccountID = "acc000000000000actns"

func TestHandlerServesBlockAndUnblock(t *testing.T) {
	// Nil use-cases on purpose: the anti-anonymous floor answers before any of
	// them is dereferenced, so the probe needs no fixture to be decisive.
	var srv iamv1.UserServiceServer = NewHandler(
		nil, nil, nil, nil, nil,
		NewBlockUserUseCase(nil, nil),
		NewUnblockUserUseCase(nil, nil),
		NewRemoveFromAccountUseCase(nil, nil),
	)

	t.Run("block", func(t *testing.T) {
		_, err := srv.Block(context.Background(), &iamv1.BlockUserRequest{UserId: actionsUserID})
		requireUserHandlerAnswered(t, err, "Block")
	})
	t.Run("unblock", func(t *testing.T) {
		_, err := srv.Unblock(context.Background(), &iamv1.UnblockUserRequest{UserId: actionsUserID})
		requireUserHandlerAnswered(t, err, "Unblock")
	})
	// Исключение из аккаунта (#1127) — третье действие того же вида, и та же
	// ловушка ему грозит: RPC объявлен, маршрутизирован, стоит в каталоге, а
	// метод не переопределяет вшитую заглушку, и каждый вызов отвечает
	// `Unimplemented`. Ни одна проба слоёв ниже этого не увидит — они не входят
	// через транспорт.
	t.Run("removeFromAccount", func(t *testing.T) {
		_, err := srv.RemoveFromAccount(context.Background(),
			&iamv1.RemoveUserFromAccountRequest{UserId: actionsUserID, AccountId: actionsAccountID})
		requireUserHandlerAnswered(t, err, "RemoveFromAccount")
	})
}

// The two directions must not be interchangeable at the composition root. They
// are distinct types precisely so that swapping them is a compile error rather
// than a control that silently becomes its own opposite; this probe states that
// requirement where a reader of the package will find it.
func TestBlockAndUnblockUseCasesAreDistinctTypes(t *testing.T) {
	block := NewBlockUserUseCase(nil, nil)
	unblock := NewUnblockUserUseCase(nil, nil)

	if block.target == unblock.target {
		t.Fatalf("both directions write the same state (%q) — one of the constructors is wrong, "+
			"and `:block` and `:unblock` would be the same call", block.target)
	}
	if block.target != domain.InviteStatusBlocked {
		t.Fatalf("Block must write BLOCKED, got %q", block.target)
	}
	if unblock.target != domain.InviteStatusActive {
		t.Fatalf("Unblock must write ACTIVE, got %q", unblock.target)
	}
}

func requireUserHandlerAnswered(t *testing.T, err error, method string) {
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

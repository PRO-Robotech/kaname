// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package account

// get_store_unreachable_test.go — an unreachable relation store is not a denial.
//
// The read gate asks the relation store whether the caller may see the account.
// "The store said no" and "the store could not be asked" are different facts:
// the first is a decision, the second is an outage. Collapsing the second into
// the first turns every iam read into a terminal 404 for the whole cluster while
// the store is down — including for the owner — and a 404 tells the caller the
// resource is gone, which is a lie the client will act on (caches, cleanup,
// "recreate it"). The neighbouring page-filter (internal/authzfilter) already
// draws this line explicitly; the per-object gate must draw it too.

import (
	"context"
	"errors"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/clients"
	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// errFGA — relation store that cannot answer: every Check is a transport error.
type errFGA struct{ err error }

func (s *errFGA) Check(context.Context, string, string, string) (bool, error) {
	return false, s.err
}

// The write side of this fake is gone, and its absence is the point. It carried
// WriteTuples/DeleteTuples because clients.RelationStore used to declare them — a
// port onto someone else's storage. There is nowhere to write any more: the state
// an answer is folded from is this service's OWN journal (`kacho_iam.fga_outbox`),
// and the commit that changes a grant is the same commit that writes it. Methods
// standing for a port method that no longer exists have no caller and no producer:
// they cannot be exercised by anything, so they can never fail, and leaving them
// would make this fake look like it stands for a wider surface than it does.
var _ clients.RelationStore = (*errFGA)(nil)

// TestGetAccount_RelationStoreUnreachable_IsUnavailableNotNotFound — the caller
// must be told the decision could not be made, not that the account is missing.
func TestGetAccount_RelationStoreUnreachable_IsUnavailableNotNotFound(t *testing.T) {
	repo := &authzAcctRepo{ownerUserID: authzOwnerID}
	uc := NewGetAccountUseCase(repo).WithRelationStore(
		&errFGA{err: errors.New("relation form did not answer: connection refused")})

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: authzOwnerID})
	_, err := uc.Execute(ctx, domain.AccountID(authzAcctID))

	if code := status.Code(err); code != codes.Unavailable {
		t.Fatalf("an unreachable relation store must surface as Unavailable, got %s (%v)", code, err)
	}
	if msg := status.Convert(err).Message(); msg == "" {
		t.Fatalf("the refusal must carry a message")
	}
}

// TestGetAccount_RelationStoreDenies_StaysNotFound — the fix must not weaken the
// deny path: a store that ANSWERS "no" still hides the account behind NotFound
// (no enumeration oracle).
func TestGetAccount_RelationStoreDenies_StaysNotFound(t *testing.T) {
	repo := &authzAcctRepo{ownerUserID: authzOwnerID}
	uc := NewGetAccountUseCase(repo).WithRelationStore(newStubFGA()) // answers, denies everything

	ctx := operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: authzOtherID})
	_, err := uc.Execute(ctx, domain.AccountID(authzAcctID))

	if code := status.Code(err); code != codes.NotFound {
		t.Fatalf("an answered denial must stay hidden as NotFound, got %s (%v)", code, err)
	}
}

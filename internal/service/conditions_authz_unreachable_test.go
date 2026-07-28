// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package service

// conditions_authz_unreachable_test.go — ConditionsService reads must not report
// data facts they could not establish.
//
// The read gate asks the relation store whether the caller may see the project's
// conditions. While the store cannot be asked, "not found" (Get) and "no rows"
// (List) are claims about the data that nobody verified — and clients act on
// them. The unanswered gate is reported as such instead.

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
	"github.com/PRO-Robotech/kacho/services/iam/internal/repo/kacho/condition"
)

// ── fakes ────────────────────────────────────────────────────────────────────

// condRepoStub — ConditionsRepoPort serving one condition; only the read side is
// exercised here.
type condRepoStub struct{ row domain.Condition }

func (r *condRepoStub) Get(context.Context, domain.ConditionID) (domain.Condition, error) {
	return r.row, nil
}
func (r *condRepoStub) List(context.Context, condition.ListFilter) ([]domain.Condition, string, error) {
	return []domain.Condition{r.row}, "", nil
}
func (r *condRepoStub) CountReferences(context.Context, domain.ConditionID) (int64, error) {
	return 0, nil
}
func (r *condRepoStub) Insert(_ context.Context, c domain.Condition) (domain.Condition, error) {
	return c, nil
}
func (r *condRepoStub) UpdateMutable(context.Context, domain.ConditionID, condition.UpdatePatch, int64) (domain.Condition, error) {
	return domain.Condition{}, nil
}
func (r *condRepoStub) SetStatus(context.Context, domain.ConditionID, domain.ConditionStatus) error {
	return nil
}
func (r *condRepoStub) Delete(context.Context, domain.ConditionID) error { return nil }
func (r *condRepoStub) InsertTx(_ context.Context, _ Tx, c domain.Condition) (domain.Condition, error) {
	return c, nil
}
func (r *condRepoStub) UpdateMutableTx(context.Context, Tx, domain.ConditionID, condition.UpdatePatch, int64) (domain.Condition, error) {
	return domain.Condition{}, nil
}
func (r *condRepoStub) SetStatusTx(context.Context, Tx, domain.ConditionID, domain.ConditionStatus) error {
	return nil
}
func (r *condRepoStub) DeleteTx(context.Context, Tx, domain.ConditionID) error { return nil }
func (r *condRepoStub) CountReferencesTx(context.Context, Tx, domain.ConditionID) (int64, error) {
	return 0, nil
}

var _ ConditionsRepoPort = (*condRepoStub)(nil)

// unreachableChecker — every relation question fails in transport.
type unreachableChecker struct{ err error }

func (c unreachableChecker) Check(context.Context, string, string, string) (bool, error) {
	return false, c.err
}

// denyingChecker — every relation question is answered, and answered "no".
type denyingChecker struct{}

func (denyingChecker) Check(context.Context, string, string, string) (bool, error) {
	return false, nil
}

const (
	condTestID      = "cnd0000000000000cond"
	condTestProject = "prj0000000000000proj"
)

func condReaderCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr00000000000reader"})
}

func condSvc(chk interface {
	Check(ctx context.Context, subject, relation, object string) (bool, error)
},
) *ConditionsCRUDService {
	repo := &condRepoStub{row: domain.Condition{
		ID:        domain.ConditionID(condTestID),
		ProjectID: condTestProject,
		Status:    domain.ConditionStatusActive,
	}}
	return NewConditionsCRUDService(repo, nil, nil).WithRelationStore(chk)
}

// ── tests ────────────────────────────────────────────────────────────────────

// TestConditionsGet_StoreUnreachable_IsUnavailableNotNotFound.
func TestConditionsGet_StoreUnreachable_IsUnavailableNotNotFound(t *testing.T) {
	svc := condSvc(unreachableChecker{err: errors.New("dial openfga: connection refused")})

	_, err := svc.Get(condReaderCtx(), domain.ConditionID(condTestID))
	if !errors.Is(err, iamerr.ErrUnavailable) {
		t.Fatalf("an unreachable gate must surface as Unavailable, got %v", err)
	}
	if errors.Is(err, iamerr.ErrNotFound) {
		t.Fatalf("an unreachable gate must not claim the condition is missing: %v", err)
	}
}

// TestConditionsList_StoreUnreachable_IsUnavailableNotEmptyPage — an empty page
// reads as "this project has no conditions"; during an outage nobody knows that.
func TestConditionsList_StoreUnreachable_IsUnavailableNotEmptyPage(t *testing.T) {
	svc := condSvc(unreachableChecker{err: errors.New("dial openfga: connection refused")})

	out, _, err := svc.List(condReaderCtx(), condition.ListFilter{ProjectID: condTestProject})
	if !errors.Is(err, iamerr.ErrUnavailable) {
		t.Fatalf("an unreachable gate must surface as Unavailable, got rows=%d err=%v", len(out), err)
	}
}

// TestConditionsRead_AnsweredDenial_StaysHidden — the deny path is unchanged: an
// answered "no" still hides the condition (Get) and still yields an empty page
// (List), with no error.
func TestConditionsRead_AnsweredDenial_StaysHidden(t *testing.T) {
	svc := condSvc(denyingChecker{})

	if _, err := svc.Get(condReaderCtx(), domain.ConditionID(condTestID)); !errors.Is(err, iamerr.ErrNotFound) {
		t.Fatalf("an answered denial must stay hidden as NotFound, got %v", err)
	}
	out, _, err := svc.List(condReaderCtx(), condition.ListFilter{ProjectID: condTestProject})
	if err != nil || len(out) != 0 {
		t.Fatalf("an answered denial must yield an empty page with no error, got rows=%d err=%v", len(out), err)
	}
}

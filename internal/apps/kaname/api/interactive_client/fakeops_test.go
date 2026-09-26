// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package interactiveclient

// fakeops_test.go — an in-memory operations.Repo for the use-case tests.
//
// It records the two transitions the contract is about: the row is created
// BEFORE the mutation (so the id the caller receives is always pollable) and
// marked terminal after it. A fake that merely returned nil would let a
// use-case that never persisted an operation pass.

import (
	"context"

	"google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/operations"
)

type fakeOps struct {
	created    bool
	doneMarked bool
	errMarked  bool
	op         operations.Operation
	// doneResp — тело, ПЕРЕДАННОЕ в MarkDone: то, что ложится в строку
	// операции. Проба секрета судит именно его, а не ответ вызывающему.
	doneResp *anypb.Any
	// errStatus — статус, переданный в MarkError.
	errStatus *status.Status
	// markDoneErr — отказ терминальной записи, когда проба его подаёт.
	markDoneErr error
}

func (f *fakeOps) Create(_ context.Context, op operations.Operation) error {
	f.created = true
	f.op = op
	return nil
}

func (f *fakeOps) CreateWithPrincipal(_ context.Context, op operations.Operation, _ operations.Principal) error {
	f.created = true
	f.op = op
	return nil
}

func (f *fakeOps) Get(_ context.Context, _ string) (*operations.Operation, error) {
	o := f.op
	return &o, nil
}

func (f *fakeOps) List(_ context.Context, _ operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}

func (f *fakeOps) MarkDone(_ context.Context, _ string, resp *anypb.Any) error {
	if f.markDoneErr != nil {
		return f.markDoneErr
	}
	f.doneMarked = true
	f.doneResp = resp
	return nil
}

func (f *fakeOps) MarkError(_ context.Context, _ string, st *status.Status) error {
	f.errMarked = true
	f.errStatus = st
	return nil
}

func (f *fakeOps) Cancel(_ context.Context, _ string) error { return nil }

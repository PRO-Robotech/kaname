// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_keys_test

import (
	"context"
	"sync"
	"testing"
	"time"

	rpcstatus "google.golang.org/genproto/googleapis/rpc/status"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/operations"
)

// fakeOps — реестр операций в памяти; исход операции ждётся детерминированно
// по каналу, а не `time.Sleep`.
type fakeOps struct {
	mu   sync.Mutex
	ops  map[string]*operations.Operation
	done chan string
}

func newFakeOps() *fakeOps {
	return &fakeOps{ops: map[string]*operations.Operation{}, done: make(chan string, 64)}
}

func (f *fakeOps) Create(_ context.Context, op operations.Operation) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := op
	f.ops[op.ID] = &c
	return nil
}

func (f *fakeOps) CreateWithPrincipal(ctx context.Context, op operations.Operation, _ operations.Principal) error {
	return f.Create(ctx, op)
}

func (f *fakeOps) Get(_ context.Context, id string) (*operations.Operation, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	op, ok := f.ops[id]
	if !ok {
		return nil, operations.ErrNotFound
	}
	c := *op
	return &c, nil
}

func (f *fakeOps) List(context.Context, operations.ListFilter) ([]operations.Operation, string, error) {
	return nil, "", nil
}

func (f *fakeOps) MarkDone(_ context.Context, id string, resp *anypb.Any) error {
	f.mu.Lock()
	op := f.ops[id]
	op.Done, op.Response = true, resp
	f.mu.Unlock()
	f.done <- id
	return nil
}

func (f *fakeOps) MarkError(_ context.Context, id string, st *rpcstatus.Status) error {
	f.mu.Lock()
	op := f.ops[id]
	op.Done, op.Error = true, st
	f.mu.Unlock()
	f.done <- id
	return nil
}

func (f *fakeOps) Cancel(context.Context, string) error { return nil }

// await — дождаться терминального исхода операции id.
func (f *fakeOps) await(t *testing.T, id string) *operations.Operation {
	t.Helper()
	deadline := time.After(5 * time.Second)
	for {
		select {
		case got := <-f.done:
			if got == id {
				op, _ := f.Get(context.Background(), id)
				return op
			}
		case <-deadline:
			t.Fatalf("операция %s не завершилась", id)
		}
	}
}

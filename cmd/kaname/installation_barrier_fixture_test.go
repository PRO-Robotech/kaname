// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"google.golang.org/protobuf/types/known/anypb"
)

// ridArrival identifies an observed production boundary. A controller must
// receive every expected arrival before releasing concurrent attempts; elapsed
// time never substitutes for evidence that both real workers arrived.
type ridArrival struct {
	Boundary    string
	Writer      int64
	OperationID string
}
type ridBarrier struct {
	arrivals chan ridArrival
	release  chan struct{}
	once     sync.Once
}

func newRIDBarrier(participants int) *ridBarrier {
	if participants < 1 {
		panic("RID barrier requires actual participants")
	}
	return &ridBarrier{arrivals: make(chan ridArrival, participants), release: make(chan struct{})}
}
func (b *ridBarrier) arrive(ctx context.Context, arrival ridArrival) error {
	select {
	case b.arrivals <- arrival:
	case <-ctx.Done():
		return ctx.Err()
	}
	select {
	case <-b.release:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}
func (b *ridBarrier) await(ctx context.Context, count int) ([]ridArrival, error) {
	var got []ridArrival
	for len(got) < count {
		select {
		case a := <-b.arrivals:
			got = append(got, a)
		case <-ctx.Done():
			return got, ctx.Err()
		}
	}
	return got, nil
}
func (b *ridBarrier) open() { b.once.Do(func() { close(b.release) }) }

// ridBoundaryRepo decorates the ACTUAL repository. Reader, SQL, transaction
// begin/commit, locks and all domain writers remain the real implementation.
// beforeWriter is after the normal Create Operation (the use-case owns ordering).
// Its controller must independently observe that Operation before returning an
// injected unknown BeginTx error. beforeCommit/afterCommit permit process-stop
// or cancellation/reconciler overlap at precisely those boundaries.
type ridBoundaryRepo struct {
	kanamerepo.Repository
	writers      atomic.Int64
	beforeWriter func(context.Context, int64) error
	beforePair   func(context.Context, ridArrival) error
	beforeCommit func(context.Context, ridArrival) error
	afterCommit  func(context.Context, ridArrival) error
}

func (r *ridBoundaryRepo) Writer(ctx context.Context) (kanamerepo.Writer, error) {
	ordinal := r.writers.Add(1)
	if r.beforeWriter != nil {
		if err := r.beforeWriter(ctx, ordinal); err != nil {
			return nil, err
		}
	}
	real, err := r.Repository.Writer(ctx)
	if err != nil {
		return nil, err
	}
	control, ok := real.(installationTransactionControl)
	if !ok {
		_ = real.Rollback(ctx)
		return nil, fmt.Errorf("real RID writer lacks installation controls")
	}
	return &ridBoundaryWriter{Writer: real, control: control, owner: r, arrival: ridArrival{Writer: ordinal}}, nil
}

type ridBoundaryWriter struct {
	kanamerepo.Writer
	control installationTransactionControl
	owner   *ridBoundaryRepo
	arrival ridArrival
}

func (w *ridBoundaryWriter) LockPendingInstallationOperation(ctx context.Context, id, account, proposed string) error {
	if err := w.control.LockPendingInstallationOperation(ctx, id, account, proposed); err != nil {
		return err
	}
	w.arrival.OperationID = id
	w.arrival.Boundary = "before-pair"
	if w.owner.beforePair != nil {
		return w.owner.beforePair(ctx, w.arrival)
	}
	return nil
}
func (w *ridBoundaryWriter) RequireInstallationAuthority(ctx context.Context, plans *authzmodel.Plans) error {
	return w.control.RequireInstallationAuthority(ctx, plans)
}
func (w *ridBoundaryWriter) BindInstallationOperation(ctx context.Context, id string, metadata *anypb.Any, resource string) error {
	return w.control.BindInstallationOperation(ctx, id, metadata, resource)
}
func (w *ridBoundaryWriter) Commit(ctx context.Context) error {
	w.arrival.Boundary = "before-commit"
	if w.owner.beforeCommit != nil {
		if err := w.owner.beforeCommit(ctx, w.arrival); err != nil {
			return err
		}
	}
	if err := w.Writer.Commit(ctx); err != nil {
		return err
	}
	w.arrival.Boundary = "after-commit-before-terminal"
	if w.owner.afterCommit != nil {
		return w.owner.afterCommit(ctx, w.arrival)
	}
	return nil
}

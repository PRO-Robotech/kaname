// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check

import (
	"context"
	"testing"
)

// Новое efficiency-требование: до первого predicate live record не владеет
// dependency backing. Это component oracle того же constructor, который
// вызывается production miss; metadata fixture не подставляет dependencies,
// cached answers или work counters. Baseline extraction ещё выделяет eager64.
func TestCallerIdentityLiveWorkspaceStartsWithoutBacking(t *testing.T) {
	ctx := context.Background()
	g := &callerGraph{ctx: ctx}
	c := &callerObjectExecutions{}
	chain := &callerTraceChain{}
	scope := &callerObjectExecutionScope{}
	const source callerObjectSourceID = 1
	record := c.newCallerTraceLiveRecord(g, chain, scope, source)
	if record == nil || record.count != 0 || record.phase != callerTraceLive || record.source != source || record.ctx != ctx || record.scope != scope || record.chain != chain || !record.holdsScope || !record.ticket || !record.scopeIndependent {
		t.Fatal("constructor did not return the original empty LIVE record metadata")
	}
	// nil дополнительно исключает нулевой slice-header над удержанным backing.
	// Record allocation допустима; предмет нового требования — только workspace.
	if record.dependencies != nil || len(record.dependencies) != 0 || cap(record.dependencies) != 0 {
		t.Fatalf("new LIVE workspace at k=0 retains dependency backing: len=%d cap=%d; want nil backing with len=0 cap=0", len(record.dependencies), cap(record.dependencies))
	}
}

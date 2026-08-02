// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// openfga_stub_test.go — in-memory OpenFGA stub used ONLY by tests in this
// package (the file has the `_test` suffix, so the type is never linked into
// the production binary). Production wiring builds OpenFGAHTTPClient directly
// and the composition root fails fast when KACHO_IAM_OPENFGA_STORE_ID is
// empty (запрет #11 — no mock-instead-of-real fallback).
package clients

import (
	"context"
	"fmt"
	"sync"
)

// OpenFGAStubClient — in-memory thread-safe stub used by tests in the
// `clients` package.
type OpenFGAStubClient struct {
	mu    sync.RWMutex
	store map[string]struct{}

	// RelationQueries.ListObjects backing state.
	listObjects      map[string][]string
	listObjectsErr   error
	listObjectsCalls int
	lastListSubject  string
}

// NewOpenFGAStubClient — test helper.
func NewOpenFGAStubClient() *OpenFGAStubClient {
	return &OpenFGAStubClient{store: make(map[string]struct{}, 64)}
}

func stubKey(subject, relation, object string) string {
	return subject + "|" + relation + "|" + object
}

// Check — simple lookup. НЕ вычисляет computed cascade (для unit-тестов нужно
// явно записывать все production tuples).
func (c *OpenFGAStubClient) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	_, ok := c.store[stubKey(subject, relation, object)]
	return ok, nil
}

// WriteTuples — appends tuples to the in-memory store.
func (c *OpenFGAStubClient) WriteTuples(ctx context.Context, tuples []RelationTuple) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, t := range tuples {
		c.store[stubKey(t.User, t.Relation, t.Object)] = struct{}{}
	}
	return nil
}

// DeleteTuples — removes tuples from the in-memory store.
func (c *OpenFGAStubClient) DeleteTuples(ctx context.Context, tuples []RelationTuple) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	for _, t := range tuples {
		delete(c.store, stubKey(t.User, t.Relation, t.Object))
	}
	return nil
}

// ── RelationQueries impl ─────────────────────────────────────
//
// The use-case FGA-list filter (account/project ListAccountsUseCase /
// ListProjectsUseCase) resolves the visible object-id set via
// RelationQueries.ListObjects. The stub answers from an in-memory
// (subject|relation|objectType) → ids map preloaded by the test, so unit
// tests deterministically drive the filter without a real OpenFGA. The other
// RelationQueries methods are minimal no-ops sufficient to satisfy the
// interface — the list filter only ever calls ListObjects.

// SetListObjects preloads the id-set returned for
// ListObjects(subject, relation, objectType, …).
func (c *OpenFGAStubClient) SetListObjects(subject, relation, objectType string, ids []string) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.listObjects == nil {
		c.listObjects = make(map[string][]string, 8)
	}
	c.listObjects[stubKey(subject, relation, objectType)] = ids
}

// SetListObjectsErr makes the next ListObjects calls return err (FGA-outage
// simulation for the fail-closed contract).
func (c *OpenFGAStubClient) SetListObjectsErr(err error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.listObjectsErr = err
}

// ListObjectsCalls returns the number of ListObjects invocations (used to
// assert the anonymous short-circuit never reaches FGA).
func (c *OpenFGAStubClient) ListObjectsCalls() int {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.listObjectsCalls
}

// LastListSubject returns the exact subject string passed to the most recent
// ListObjects call (subject-prefix assertion).
func (c *OpenFGAStubClient) LastListSubject() string {
	c.mu.RLock()
	defer c.mu.RUnlock()
	return c.lastListSubject
}

// BatchCheckWithContext — see RelationQueries. Answers the batched shape from
// the same in-memory tuple set the single Check answers from, so a test cannot
// get a different verdict depending on which door was used.
//
// It refuses an over-cap request exactly as the store does — an error, never a
// trim — because a stub more permissive than the thing it stands in for is how a
// partitioning bug reaches a deployment green.
func (c *OpenFGAStubClient) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	if len(objects) > fgaMaxChecksPerBatchCheck {
		return nil, fmt.Errorf("batchCheck received %d checks, the maximum allowed is %d",
			len(objects), fgaMaxChecksPerBatchCheck)
	}
	out := make([]bool, len(objects))
	for i, object := range objects {
		allowed, err := c.CheckWithContext(ctx, subject, relation, object, condCtx)
		if err != nil {
			return nil, err
		}
		out[i] = allowed
	}
	return out, nil
}

// ListObjects — see RelationQueries. Returns the preloaded id-set for the
// (subject, relation, objectType) key, or the preloaded error.
func (c *OpenFGAStubClient) ListObjects(ctx context.Context, subject, relation, objectType string,
	condCtx map[string]any, maxResults int) ([]string, error) {
	c.mu.Lock()
	c.listObjectsCalls++
	c.lastListSubject = subject
	err := c.listObjectsErr
	ids := c.listObjects[stubKey(subject, relation, objectType)]
	c.mu.Unlock()
	if err != nil {
		return nil, err
	}
	return ids, nil
}

// The remaining RelationQueries methods are unused by the list filter; they
// exist only so the stub satisfies the full interface.

func (c *OpenFGAStubClient) CheckWithContext(ctx context.Context, subject, relation, object string, condCtx map[string]any) (bool, error) {
	return c.Check(ctx, subject, relation, object)
}

func (c *OpenFGAStubClient) ListSubjects(ctx context.Context, objectType, objectID, relation string, pageSize int, pageToken string) ([]string, string, error) {
	if err := stubPagination(pageSize, pageToken); err != nil {
		return nil, "", err
	}
	return nil, "", nil
}

func (c *OpenFGAStubClient) Expand(ctx context.Context, objectType, objectID, relation string) (*ExpandTree, error) {
	return nil, ErrNotConfigured
}

func (c *OpenFGAStubClient) ReadTuples(ctx context.Context, subjectFilter, relationFilter, objectFilter string, pageSize int, pageToken string) ([]ConditionalTuple, string, error) {
	if err := stubPagination(pageSize, pageToken); err != nil {
		return nil, "", err
	}
	return nil, "", nil
}

// stubPagination — the pagination contract the stub holds callers to.
//
// Both paginated stub methods return an empty page and, with it, an EMPTY
// continuation token: they never issue one. A caller that presents a non-empty
// token is therefore presenting a token this store never produced, and a caller
// that asks for a negative page is asking for something no page size means.
// Answering either with "here is your empty page" makes the stub more permissive
// than the thing it stands in for, and a test written against such a stub is
// green no matter what it passes — which is the same as having no assertion
// about pagination at all.
func stubPagination(pageSize int, pageToken string) error {
	if pageSize < 0 {
		return fmt.Errorf("openfga stub: page size %d is not a page size", pageSize)
	}
	if pageToken != "" {
		return fmt.Errorf("openfga stub: continuation token %q was never issued by this store", pageToken)
	}
	return nil
}

func (c *OpenFGAStubClient) WriteConditionalTuples(ctx context.Context, writes, deletes []ConditionalTuple) error {
	return nil
}

func (c *OpenFGAStubClient) GetStoreInfo(ctx context.Context) (StoreInfo, error) {
	return StoreInfo{}, ErrNotConfigured
}

var (
	_ RelationStore   = (*OpenFGAStubClient)(nil)
	_ RelationQueries = (*OpenFGAStubClient)(nil)
)

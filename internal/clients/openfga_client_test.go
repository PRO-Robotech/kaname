// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package clients_test

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kacho/services/iam/internal/clients"
)

func TestOpenFGAStubClient_WriteCheck(t *testing.T) {
	c := clients.NewOpenFGAStubClient()
	ctx := context.Background()
	if err := c.WriteTuples(ctx, []clients.RelationTuple{
		{User: "user:usr_alice", Relation: "editor", Object: "project:prj_dev"},
	}); err != nil {
		t.Fatalf("write: %v", err)
	}
	allowed, err := c.Check(ctx, "user:usr_alice", "editor", "project:prj_dev")
	if err != nil {
		t.Fatalf("check: %v", err)
	}
	if !allowed {
		t.Fatalf("expected allowed")
	}
}

func TestOpenFGAStubClient_DeleteTuples(t *testing.T) {
	c := clients.NewOpenFGAStubClient()
	ctx := context.Background()
	tup := []clients.RelationTuple{{User: "user:usr_alice", Relation: "editor", Object: "project:prj_dev"}}
	_ = c.WriteTuples(ctx, tup)
	if err := c.DeleteTuples(ctx, tup); err != nil {
		t.Fatalf("delete: %v", err)
	}
	allowed, _ := c.Check(ctx, "user:usr_alice", "editor", "project:prj_dev")
	if allowed {
		t.Fatalf("expected deleted")
	}
}

func TestOpenFGAStubClient_NoComputedCascade(t *testing.T) {
	// The stub does NOT implement computed cascade — derived tuples must be
	// recorded explicitly. Documented in the Check comment.
	c := clients.NewOpenFGAStubClient()
	ctx := context.Background()
	_ = c.WriteTuples(ctx, []clients.RelationTuple{
		{User: "user:usr_alice", Relation: "admin", Object: "project:prj_dev"},
	})
	// `admin → viewer` cascade NOT supported by stub.
	allowed, _ := c.Check(ctx, "user:usr_alice", "viewer", "project:prj_dev")
	if allowed {
		t.Fatalf("stub must NOT auto-cascade admin→viewer; record real tuples explicitly")
	}
}

func TestOpenFGAHTTPClient_NotConfiguredErr(t *testing.T) {
	// ErrNotConfigured fires only when Endpoint=="" or StoreID=="".
	// This test exercises that branch (fail-closed for an unconfigured
	// OpenFGAHTTPClient).
	c := &clients.OpenFGAHTTPClient{Endpoint: "", StoreID: "st_test"}
	ctx := context.Background()
	_, err := c.Check(ctx, "user:usr_alice", "editor", "project:prj_dev")
	if !errors.Is(err, clients.ErrNotConfigured) {
		t.Fatalf("expected ErrNotConfigured, got %v", err)
	}
}

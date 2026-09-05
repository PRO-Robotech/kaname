// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// read_authz_unreachable_test.go — AllowsVerb must distinguish "the store said
// no" from "the store could not be asked". Both are non-allows, but only the
// first is a decision; the second must reach the caller as such so it can answer
// Unavailable instead of asserting that the resource does not exist.
//
// «Хранилище» здесь — СВОЯ база службы прав: со снятия внешнего движка на вопрос
// отвечает реляционная форма (`relverdict`) читающей транзакцией. Свойство от
// этого не изменилось, а вот вид отказа изменился, и он тут и есть вход: отказ
// читающей транзакции, а не отказ соединения с чужим движком.

import (
	"context"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// checkerFn — RelationChecker from a function.
type checkerFn func(ctx context.Context, subject, relation, object string) (bool, error)

func (f checkerFn) Check(ctx context.Context, subject, relation, object string) (bool, error) {
	return f(ctx, subject, relation, object)
}

func readerCtx() context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: "usr00000000000reader"})
}

// TestAllowsVerb_StoreUnreachable_ReportsTheOutage — every Check fails: the
// verdict is "unknown", not "denied".
func TestAllowsVerb_StoreUnreachable_ReportsTheOutage(t *testing.T) {
	boom := errors.New("relverdict: транзакция чтения: dial tcp 127.0.0.1:5432: connect: connection refused")
	chk := checkerFn(func(context.Context, string, string, string) (bool, error) {
		return false, boom
	})

	allowed, err := AllowsVerb(readerCtx(), chk, "v_get", "account", "acc0000000000000abcd")
	if allowed {
		t.Fatalf("an unreachable store must never allow")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("an unreachable store must surface as an error, got err=%v", err)
	}
}

// TestAllowsVerb_StoreAnswersNo_IsAPlainDenial — the store answers: no error, no
// allow. The caller may hide existence on this.
func TestAllowsVerb_StoreAnswersNo_IsAPlainDenial(t *testing.T) {
	chk := checkerFn(func(context.Context, string, string, string) (bool, error) {
		return false, nil
	})

	allowed, err := AllowsVerb(readerCtx(), chk, "v_get", "account", "acc0000000000000abcd")
	if allowed || err != nil {
		t.Fatalf("an answered denial must be (false, nil), got (%v, %v)", allowed, err)
	}
}

// TestAllowsVerb_ClusterAdminProbeUnreachable_IsNotADenial — the super-gate probe
// is a Check too. If it fails and the verb Check denies, the caller has NOT been
// told "no" by both questions — one of them was never answered, so the outage
// must reach the caller rather than becoming a 404.
func TestAllowsVerb_ClusterAdminProbeUnreachable_IsNotADenial(t *testing.T) {
	boom := errors.New("relverdict: транзакция чтения: dial tcp 127.0.0.1:5432: connect: connection refused")
	chk := checkerFn(func(_ context.Context, _, relation, object string) (bool, error) {
		if relation == "system_admin" && object == "cluster:"+domain.ClusterSingletonID {
			return false, boom
		}
		return false, nil // the verb question answers, and answers no
	})

	allowed, err := AllowsVerb(readerCtx(), chk, "v_get", "account", "acc0000000000000abcd")
	if allowed {
		t.Fatalf("a failed super-gate probe must never allow")
	}
	if !errors.Is(err, boom) {
		t.Fatalf("an unanswered super-gate probe must surface as an error, got err=%v", err)
	}
}

// TestAllowsVerb_Unwired_IsADenialNotAnOutage — a nil checker is a wiring fact,
// not an outage: the gate is closed and the caller hides existence as usual.
func TestAllowsVerb_Unwired_IsADenialNotAnOutage(t *testing.T) {
	allowed, err := AllowsVerb(readerCtx(), nil, "v_get", "account", "acc0000000000000abcd")
	if allowed || err != nil {
		t.Fatalf("a nil checker must be (false, nil), got (%v, %v)", allowed, err)
	}
}

// TestAllowsVerb_Anonymous_IsADenialNotAnOutage — no principal, nothing to ask.
func TestAllowsVerb_Anonymous_IsADenialNotAnOutage(t *testing.T) {
	chk := checkerFn(func(context.Context, string, string, string) (bool, error) {
		t.Fatalf("an anonymous caller must not reach the store")
		return false, nil
	})
	allowed, err := AllowsVerb(context.Background(), chk, "v_get", "account", "acc0000000000000abcd")
	if allowed || err != nil {
		t.Fatalf("an anonymous caller must be (false, nil), got (%v, %v)", allowed, err)
	}
}

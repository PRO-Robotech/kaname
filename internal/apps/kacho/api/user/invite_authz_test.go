// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package user

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// recordingChecker captures the subject strings the cascade asks about, so a test
// can assert WHO was checked rather than only what the answer was. The defect this
// file locks would otherwise be invisible: the cascade returns a well-formed "no"
// for a subject that cannot exist, which is indistinguishable from a real refusal
// unless the asked-for subject is observed.
type recordingChecker struct {
	asked    []string
	allowFor string // subject that is granted `editor`/`admin`/`owner`
}

func (r *recordingChecker) Check(_ context.Context, subject, relation, object string) (bool, error) {
	r.asked = append(r.asked, subject)
	return subject == r.allowFor, nil
}

func ctxWithPrincipal(t *testing.T, typ, id string) context.Context {
	t.Helper()
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: typ, ID: id})
}

// A SERVICE ACCOUNT holding account-admin must be able to invite.
//
// Why this is the load-bearing case. Every token a production-posture stand issues
// to a non-interactive caller is a service-account token (keys are issued by
// SAKeyService and exchanged at the provider), so "account admin" on such a stand IS
// a service account. The invite gate spelled its subject as "user:"+id with no
// regard for the principal's type, so the store was asked about a subject that does
// not exist, answered "no", and the account's own administrator was refused —
// by construction, for every machine caller, regardless of its grants.
//
// It denies rather than admits, so it is a correctness defect and not an escalation.
// It is still the directive in `security.md`: a service account is a first-class
// principal, not an exception, and authorization is decided by the model on the
// subject that actually made the call.
func TestCanInviteUsers_ServiceAccountPrincipalIsAskedAsServiceAccount(t *testing.T) {
	const saID = "sva6rxe7xcemam63vwcv"
	const acct = "accyknbh4w66wg06zpyr"

	c := &recordingChecker{allowFor: "service_account:" + saID}
	ctx := ctxWithPrincipal(t, "service_account", saID)

	allowed, err := canInviteUsers(ctx, c, acct)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatalf("service account holding account-admin was refused; subjects asked: %v\n"+
			"the store was asked about a subject that cannot exist, so its 'no' says nothing "+
			"about the caller's grants", c.asked)
	}
	for _, s := range c.asked {
		if s != "service_account:"+saID {
			t.Fatalf("cascade asked about %q; a service-account principal must be named "+
				"service_account:<id> — spelling it user:<id> asks about somebody else", s)
		}
	}
}

// The user path must keep working unchanged — a fix that only moved the defect from
// one principal type to the other would pass the test above on its own.
func TestCanInviteUsers_UserPrincipalIsAskedAsUser(t *testing.T) {
	const usrID = "usr7cst95wa4q3myxey4"
	const acct = "accyknbh4w66wg06zpyr"

	c := &recordingChecker{allowFor: "user:" + usrID}
	ctx := ctxWithPrincipal(t, "user", usrID)

	allowed, err := canInviteUsers(ctx, c, acct)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !allowed {
		t.Fatalf("user holding account-admin was refused; subjects asked: %v", c.asked)
	}
	if c.asked[0] != "user:"+usrID {
		t.Fatalf("cascade asked about %q, want user:%s", c.asked[0], usrID)
	}
}

// An unresolvable principal must be refused WITHOUT consulting the store. Deciding
// on a subject we could not name is the failure mode `SubjectFromPrincipal` was
// introduced to remove: its predecessors defaulted an unknown type to "user:", which
// is an over-grant rather than a refusal.
func TestCanInviteUsers_UnknownPrincipalTypeIsRefusedWithoutAsking(t *testing.T) {
	c := &recordingChecker{allowFor: "user:whatever"}
	ctx := ctxWithPrincipal(t, "banana", "whatever")

	allowed, err := canInviteUsers(ctx, c, "accyknbh4w66wg06zpyr")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if allowed {
		t.Fatal("a principal with an unresolvable type was admitted")
	}
	if len(c.asked) != 0 {
		t.Fatalf("store was consulted for an unnameable subject: %v", c.asked)
	}
}

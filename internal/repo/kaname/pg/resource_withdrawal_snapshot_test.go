// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"encoding/json"
	"errors"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/domain"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

func resourceWithdrawalSnapshotFixture() *resourceWithdrawalCapture {
	row := func(value string) resourceSourceRow {
		return resourceSourceRow{state: value, value: json.RawMessage(value)}
	}
	return &resourceWithdrawalCapture{
		source: &resourceSourceCapture{lifetime: &resourceAttemptLifetime{}, entries: map[resourceSourceKey][]resourceSourceRow{
			{kind: resourceSourceBindingSubjects, typ: "binding", id: "binding-a"}: {
				row(`{"binding_id":"binding-a","subject_type":"user","subject_id":"second","ordinal":2}`),
				row(`{"binding_id":"binding-a","subject_type":"service_account","subject_id":"first","ordinal":1}`),
			},
			{kind: resourceSourceBindingLedger, typ: "binding", id: "binding-a"}: {
				row(`{"binding_id":"binding-a","fga_user":"user:first","relation":"viewer","object":"vpc.address:a","member_object_id":"x"}`),
				row(`{"binding_id":"binding-a","fga_user":"user:first","relation":"viewer","object":"vpc.address:a","member_object_id":"y"}`),
			},
		}},
		bindings: map[string][]resourceSourceRow{"binding-a": {row(`{"id":"binding-a","subject_type":"user","subject_id":"legacy","role_id":null,"resource_type":"account","resource_id":"a","scope":2,"status":"PENDING","expires_at":"2000-01-01T00:00:00Z","revoked_at":null,"labels":{},"target":{"resources":[{"type":"vpc.address","id":"a"}]},"granted_relation":"viewer","is_system":true}`)}},
		roles:    map[string][]resourceSourceRow{}, rewriteRoles: map[string]bool{}, targetBindings: map[string]bool{"binding-a": true},
	}
}

func TestResourceWithdrawalSnapshotPreservesPendingExpiredAndAllSubjects(t *testing.T) {
	captured := resourceWithdrawalSnapshotFixture()
	snapshot, err := captured.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(snapshot.Bindings) != 1 {
		t.Fatalf("bindings=%d", len(snapshot.Bindings))
	}
	got := snapshot.Bindings[0]
	if got.Binding.Status != domain.AccessBindingStatusPending || got.Binding.ExpiresAt == nil || got.Binding.RevokedAt != nil || got.Binding.RoleID != "" || got.Binding.GrantedRelation != "viewer" {
		t.Fatalf("lifecycle/form lost: %+v", got.Binding)
	}
	if len(got.Subjects) != 2 || got.Subjects[0].ID != "first" || got.Subjects[1].ID != "second" {
		t.Fatalf("subjects=%+v", got.Subjects)
	}
	if len(got.Emitted) != 1 || got.Emitted[0].Object != "vpc.address:a" {
		t.Fatalf("ledger=%+v", got.Emitted)
	}
	// Вход не меняется: разные owners одного кортежа остаются в witness.
	key := resourceSourceKey{kind: resourceSourceBindingLedger, typ: "binding", id: "binding-a"}
	if len(captured.source.entries[key]) != 2 {
		t.Fatal("captured ledger mutated")
	}
}

func TestResourceWithdrawalSnapshotRejectsMissingOrForeignWitness(t *testing.T) {
	for _, name := range []string{"subjects absent", "ledger absent", "foreign ledger", "foreign subject", "duplicate subject", "closed attempt"} {
		t.Run(name, func(t *testing.T) {
			c := resourceWithdrawalSnapshotFixture()
			subjects := resourceSourceKey{kind: resourceSourceBindingSubjects, typ: "binding", id: "binding-a"}
			ledger := resourceSourceKey{kind: resourceSourceBindingLedger, typ: "binding", id: "binding-a"}
			switch name {
			case "subjects absent":
				delete(c.source.entries, subjects)
			case "ledger absent":
				delete(c.source.entries, ledger)
			case "foreign ledger":
				c.source.entries[ledger][0].value = json.RawMessage(`{"binding_id":"foreign","fga_user":"u","relation":"r","object":"o"}`)
			case "foreign subject":
				c.source.entries[subjects][0].value = json.RawMessage(`{"binding_id":"foreign","subject_type":"user","subject_id":"u","ordinal":1}`)
			case "duplicate subject":
				c.source.entries[subjects] = append(c.source.entries[subjects], c.source.entries[subjects][0])
			case "closed attempt":
				c.source.lifetime.close()
			}
			if _, err := c.snapshot(); !errors.Is(err, kaname.ErrSourceUnconfirmed) {
				t.Fatalf("err=%v", err)
			}
		})
	}
}

func TestResourceWithdrawalSnapshotExplicitEmptySubjectsPreservesLegacyAnchor(t *testing.T) {
	c := resourceWithdrawalSnapshotFixture()
	c.source.entries[resourceSourceKey{kind: resourceSourceBindingSubjects, typ: "binding", id: "binding-a"}] = nil
	got, err := c.snapshot()
	if err != nil {
		t.Fatal(err)
	}
	if len(got.Bindings) != 1 || len(got.Bindings[0].Subjects) != 0 || got.Bindings[0].Binding.SubjectID != "legacy" {
		t.Fatalf("snapshot=%+v", got)
	}
}

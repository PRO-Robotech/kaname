// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"encoding/json"
	"github.com/stretchr/testify/require"
	"testing"
	"time"
)

func rid06HistoryClockFixture(t *testing.T) (ridWholeDeliverySnapshot, ridWholeDeliverySnapshot) {
	base := time.Date(2026, 11, 3, 12, 0, 0, 0, time.UTC)
	a := ridWholeDeliverySnapshot{PrimaryStartedAt: base, PrimaryFinishedAt: base.Add(time.Second), OwnCeilings: ridWholeOwnCeilings{Raw: ridWholeTable{Columns: []string{"kind", "limit_value", "stated_at", "future"}, Rows: []string{"old-raw-a", "old-raw-b"}}, Semantic: map[string]string{"iam.a": "unchanged-full-row-a-including-future", "iam.b": "unchanged-full-row-b-including-future"}, StatedAt: map[string]time.Time{"iam.a": base.Add(-time.Minute), "iam.b": base.Add(-time.Minute)}}}
	raw, err := json.Marshal(a)
	require.NoError(t, err)
	var b ridWholeDeliverySnapshot
	require.NoError(t, json.Unmarshal(raw, &b))
	b.PrimaryStartedAt = base.Add(3 * time.Second)
	b.PrimaryFinishedAt = base.Add(4 * time.Second)
	return a, b
}
func TestRID06HistoryOwnCeilings(t *testing.T) {
	for _, name := range []string{"unchanged-postseed-clock", "legal-primary-interval-change", "mixed-unchanged-and-changed", "changed-past", "changed-future", "missing-before-clock", "missing-after-clock", "zero-before-clock", "zero-after-clock", "before-clock-after-finished", "missing-kind", "extra-kind", "semantic-mutation", "unknown-column-semantic-mutation", "columns-changed", "missing-stated-column", "duplicate-column", "row-count-changed", "before-count-inconsistent", "raw-mutated-without-clock-change", "snapshot-order-invalid", "missing-primary-clock", "unchanged-future-clock", "unchanged-future-kind", "changed-future-kind-semantic", "empty-kind", "empty-semantic"} {
		t.Run(name, func(t *testing.T) {
			a, b := rid06HistoryClockFixture(t)
			switch name {
			case "legal-primary-interval-change":
				for k := range b.OwnCeilings.StatedAt {
					b.OwnCeilings.StatedAt[k] = a.PrimaryFinishedAt.Add(time.Second)
				}
				b.OwnCeilings.Raw.Rows = []string{"new-raw-a", "new-raw-b"}
			case "mixed-unchanged-and-changed":
				b.OwnCeilings.StatedAt["iam.a"] = a.PrimaryFinishedAt.Add(time.Second)
				b.OwnCeilings.Raw.Rows[0] = "new-raw-a"
			case "changed-past":
				b.OwnCeilings.StatedAt["iam.a"] = a.PrimaryStartedAt.Add(-time.Second)
			case "changed-future":
				b.OwnCeilings.StatedAt["iam.a"] = b.PrimaryStartedAt.Add(time.Nanosecond)
			case "missing-before-clock":
				delete(a.OwnCeilings.StatedAt, "iam.a")
			case "missing-after-clock":
				delete(b.OwnCeilings.StatedAt, "iam.a")
			case "zero-before-clock":
				a.OwnCeilings.StatedAt["iam.a"] = time.Time{}
			case "zero-after-clock":
				b.OwnCeilings.StatedAt["iam.a"] = time.Time{}
			case "before-clock-after-finished":
				a.OwnCeilings.StatedAt["iam.a"] = a.PrimaryFinishedAt.Add(time.Nanosecond)
			case "missing-kind":
				delete(b.OwnCeilings.Semantic, "iam.a")
			case "extra-kind":
				b.OwnCeilings.Semantic["iam.extra"] = "unexpected"
				b.OwnCeilings.StatedAt["iam.extra"] = a.PrimaryStartedAt
			case "semantic-mutation", "unknown-column-semantic-mutation":
				b.OwnCeilings.Semantic["iam.a"] = "changed-full-row"
			case "columns-changed":
				b.OwnCeilings.Raw.Columns = append(b.OwnCeilings.Raw.Columns, "unexpected")
			case "missing-stated-column":
				b.OwnCeilings.Raw.Columns = []string{"kind", "limit_value", "future"}
				a.OwnCeilings.Raw.Columns = append([]string{}, b.OwnCeilings.Raw.Columns...)
			case "duplicate-column":
				a.OwnCeilings.Raw.Columns = append(a.OwnCeilings.Raw.Columns, "kind")
				b.OwnCeilings.Raw.Columns = append([]string{}, a.OwnCeilings.Raw.Columns...)
			case "row-count-changed":
				b.OwnCeilings.Raw.Rows = append(b.OwnCeilings.Raw.Rows, "extra")
			case "before-count-inconsistent":
				a.OwnCeilings.Raw.Rows = nil
			case "raw-mutated-without-clock-change":
				b.OwnCeilings.Raw.Rows[0] = "changed-raw"
			case "snapshot-order-invalid":
				b.PrimaryStartedAt = a.PrimaryFinishedAt.Add(-time.Nanosecond)
			case "missing-primary-clock":
				a.PrimaryStartedAt = time.Time{}
			case "unchanged-future-clock":
				a.OwnCeilings.StatedAt["iam.a"] = b.PrimaryStartedAt.Add(time.Nanosecond)
				b.OwnCeilings.StatedAt["iam.a"] = a.OwnCeilings.StatedAt["iam.a"]
			case "unchanged-future-kind", "changed-future-kind-semantic":
				a.OwnCeilings.Semantic["future.unknown"] = "unchanged-unknown-kind-full-row"
				b.OwnCeilings.Semantic["future.unknown"] = "unchanged-unknown-kind-full-row"
				a.OwnCeilings.StatedAt["future.unknown"] = a.PrimaryStartedAt.Add(-time.Minute)
				b.OwnCeilings.StatedAt["future.unknown"] = a.OwnCeilings.StatedAt["future.unknown"]
				a.OwnCeilings.Raw.Rows = append(a.OwnCeilings.Raw.Rows, "unknown-kind-raw")
				b.OwnCeilings.Raw.Rows = append(b.OwnCeilings.Raw.Rows, "unknown-kind-raw")
				if name == "changed-future-kind-semantic" {
					b.OwnCeilings.Semantic["future.unknown"] = "unexpected-change"
				}
			case "empty-kind":
				a.OwnCeilings.Semantic[""] = a.OwnCeilings.Semantic["iam.a"]
				delete(a.OwnCeilings.Semantic, "iam.a")
				b.OwnCeilings.Semantic[""] = b.OwnCeilings.Semantic["iam.a"]
				delete(b.OwnCeilings.Semantic, "iam.a")
				a.OwnCeilings.StatedAt[""] = a.OwnCeilings.StatedAt["iam.a"]
				delete(a.OwnCeilings.StatedAt, "iam.a")
				b.OwnCeilings.StatedAt[""] = b.OwnCeilings.StatedAt["iam.a"]
				delete(b.OwnCeilings.StatedAt, "iam.a")
			case "empty-semantic":
				a.OwnCeilings.Semantic["iam.a"] = ""
				b.OwnCeilings.Semantic["iam.a"] = ""
			}
			require.Equal(t, name == "unchanged-postseed-clock" || name == "legal-primary-interval-change" || name == "mixed-unchanged-and-changed" || name == "unchanged-future-kind", rid06HistoryOwnCeilingsValid(a, b))
		})
	}
}
func TestRID06HistoryMalformedClockFailsDecode(t *testing.T) {
	for _, name := range []string{"string", "number", "array"} {
		t.Run(name, func(t *testing.T) {
			values := map[string]string{"string": `"not-a-primary-timestamp"`, "number": `7`, "array": `[]`}
			var snapshot ridWholeDeliverySnapshot
			err := json.Unmarshal([]byte(`{"ownCeilings":{"statedAtByKind":{"iam.a":`+values[name]+`}}}`), &snapshot)
			require.Error(t, err)
			require.False(t, rid06HistoryOwnCeilingsValid(snapshot, snapshot))
		})
	}
}

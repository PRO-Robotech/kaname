// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/stretchr/testify/require"
)

func TestChildRegistrationOutcomeUsesFinalClockAndHeldState(t *testing.T) {
	r, _ := writerProtocolRigBeforePreparation(t)
	at := time.Date(2026, 11, 22, 12, 0, 0, 123456000, time.UTC)
	previous := at.Add(-time.Hour)
	base := func() map[string]any {
		return map[string]any{
			"parent_version":    previous,
			"closed_at":         nil,
			"child_version":     nil,
			"replay_version":    nil,
			"policy":            map[string]any{"MaxChildren": 2, "MaxCreates": 2, "WindowSeconds": 60},
			"live_children":     0,
			"recent_creations":  []time.Time{},
			"version_watermark": nil,
		}
	}
	encode := func(witness map[string]any) []byte {
		t.Helper()
		value, err := json.Marshal(witness)
		require.NoError(t, err)
		return value
	}
	for _, tc := range []struct {
		name    string
		change  func(map[string]any)
		outcome string
		version *time.Time
	}{
		{name: "new child uses final decision time", outcome: "create", version: &at},
		{name: "missing parent overrides replay", change: func(w map[string]any) {
			w["parent_version"], w["child_version"], w["replay_version"] = nil, previous, previous
		}, outcome: "parent_missing"},
		{name: "closed parent overrides replay", change: func(w map[string]any) {
			w["closed_at"], w["child_version"], w["replay_version"] = previous, previous, previous
		}, outcome: "parent_closed"},
		{name: "external child remains occupied", change: func(w map[string]any) {
			w["child_version"] = previous
		}, outcome: "child_occupied"},
		{name: "replay returns exact saved version despite exhausted limits", change: func(w map[string]any) {
			w["child_version"], w["replay_version"] = previous, previous
			w["live_children"] = 2
			w["recent_creations"] = []time.Time{at, at.Add(-time.Second)}
			w["version_watermark"] = at.Add(time.Hour)
		}, outcome: "replay", version: &previous},
		{name: "replay needs no quota capture", change: func(w map[string]any) {
			w["child_version"], w["replay_version"], w["live_children"] = previous, previous, nil
		}, outcome: "replay", version: &previous},
		{name: "capacity boundary denies new child", change: func(w map[string]any) {
			w["live_children"] = 2
		}, outcome: "capacity"},
		{name: "one free capacity slot allows creation", change: func(w map[string]any) {
			w["live_children"] = 1
		}, outcome: "create", version: &at},
		{name: "two in-window creations exhaust rate", change: func(w map[string]any) {
			w["recent_creations"] = []time.Time{at.Add(-time.Second), at.Add(-59 * time.Second)}
		}, outcome: "rate"},
		{name: "exact expiry frees rate slot", change: func(w map[string]any) {
			w["recent_creations"] = []time.Time{at.Add(-time.Second), at.Add(-time.Minute)}
		}, outcome: "create", version: &at},
		{name: "one microsecond before expiry still charges rate", change: func(w map[string]any) {
			w["recent_creations"] = []time.Time{at.Add(-time.Second), at.Add(-time.Minute + time.Microsecond)}
		}, outcome: "rate"},
		{name: "equal decision timestamps still charge rate", change: func(w map[string]any) {
			w["recent_creations"] = []time.Time{at, at}
		}, outcome: "rate"},
		{name: "clock rollback does not refund future receipts", change: func(w map[string]any) {
			w["recent_creations"] = []time.Time{at.Add(time.Hour), at.Add(time.Second)}
		}, outcome: "rate"},
		{name: "expired suffix allows creation", change: func(w map[string]any) {
			w["recent_creations"] = []time.Time{at.Add(-time.Minute), at.Add(-2 * time.Minute)}
		}, outcome: "create", version: &at},
		{name: "older watermark does not replace final clock", change: func(w map[string]any) {
			w["version_watermark"] = previous
		}, outcome: "create", version: &at},
	} {
		t.Run(tc.name, func(t *testing.T) {
			witness := base()
			if tc.change != nil {
				tc.change(witness)
			}
			var outcome string
			var version *time.Time
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT outcome,source_version FROM kaname._authority_child_registration_outcome_v1($1::jsonb,$2::timestamptz)`, encode(witness), at).Scan(&outcome, &version))
			require.Equal(t, tc.outcome, outcome)
			if tc.version == nil {
				require.Nil(t, version, "a denial must not issue a source version")
			} else {
				require.NotNil(t, version)
				require.True(t, tc.version.Equal(*version), "want %s, got %s", tc.version, version)
			}
		})
	}

	for _, watermark := range []time.Time{at, at.Add(time.Hour)} {
		t.Run("new version exceeds watermark "+watermark.Format(time.RFC3339Nano), func(t *testing.T) {
			witness := base()
			witness["version_watermark"] = watermark
			var outcome string
			var version time.Time
			require.NoError(t, r.admin.QueryRow(r.ctx, `SELECT outcome,source_version FROM kaname._authority_child_registration_outcome_v1($1::jsonb,$2::timestamptz)`, encode(witness), at).Scan(&outcome, &version))
			require.Equal(t, "create", outcome)
			require.True(t, watermark.Add(time.Microsecond).Equal(version))
		})
	}

	for _, decision := range []any{nil, "infinity", "-infinity", "0001-01-01 00:00:00 BC", "10000-01-01 00:00:00+00"} {
		t.Run("invalid final clock", func(t *testing.T) {
			_, err := r.admin.Exec(r.ctx, `SELECT * FROM kaname._authority_child_registration_outcome_v1($1::jsonb,$2::timestamptz)`, encode(base()), decision)
			var pe *pgconn.PgError
			require.ErrorAs(t, err, &pe)
			require.Equal(t, "22023", pe.Code)
		})
	}
	t.Run("watermark cannot advance beyond protobuf timestamp range", func(t *testing.T) {
		witness := base()
		witness["version_watermark"] = "9999-12-31T23:59:59.999999Z"
		_, err := r.admin.Exec(r.ctx, `SELECT * FROM kaname._authority_child_registration_outcome_v1($1::jsonb,$2::timestamptz)`, encode(witness), at)
		var pe *pgconn.PgError
		require.ErrorAs(t, err, &pe)
		require.Equal(t, "22023", pe.Code)
	})
	t.Run("runtime cannot manufacture a held-state decision", func(t *testing.T) {
		_, err := r.runtime.Exec(r.ctx, `SELECT * FROM kaname._authority_child_registration_outcome_v1($1::jsonb,$2::timestamptz)`, encode(base()), at)
		var pe *pgconn.PgError
		require.ErrorAs(t, err, &pe)
		require.Equal(t, "42501", pe.Code)
	})
}

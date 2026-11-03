// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package main

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/testsupport/installruntime"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/anypb"
)

type rid08Admission struct {
	RemainingSeconds               float64
	User, CarrierDigest            string
	Limit, WindowSeconds, Admitted int64
	Present                        bool
	Started, DBNow                 time.Time
}

func rid08Write(t *testing.T, root, name string, value any) {
	t.Helper()
	raw, err := json.MarshalIndent(value, "", "  ")
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(filepath.Join(root, name+".json"), raw, 0600))
}
func rid08AdmissionRead(t *testing.T, f *installationNativeWorld) rid08Admission {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.given.ctx, 5*time.Second)
	defer cancel()
	a := rid08Admission{User: string(f.given.user)}
	var carrier string
	require.NoError(t, f.given.pool.QueryRow(ctx, `SELECT
 CASE WHEN u.external_id LIKE 'own:%' THEN u.admission_carrier ELSE u.external_id END,
 l.max_events,l.window_seconds,clock_timestamp(),w.carrier_id IS NOT NULL,
 COALESCE(w.admitted,0),COALESCE(w.window_started_at,'epoch'::timestamptz),
 COALESCE(GREATEST(EXTRACT(EPOCH FROM w.window_started_at + make_interval(secs => l.window_seconds) - clock_timestamp()),0),0)::double precision
 FROM kaname.users u JOIN kaname.account_admission_rate_limits l
 ON l.kind='iam.account' AND l.withdrawn_at IS NULL
 LEFT JOIN kaname.identity_admission_windows w ON w.kind=l.kind
 AND w.carrier_id=CASE WHEN u.external_id LIKE 'own:%' THEN u.admission_carrier ELSE u.external_id END
 WHERE u.id=$1`, a.User).Scan(&carrier, &a.Limit, &a.WindowSeconds, &a.DBNow, &a.Present, &a.Admitted, &a.Started, &a.RemainingSeconds))
	require.NotEmpty(t, carrier)
	digest := sha256.Sum256([]byte(carrier))
	a.CarrierDigest = hex.EncodeToString(digest[:])
	require.EqualValues(t, 3, a.Limit)
	require.EqualValues(t, 3600, a.WindowSeconds)
	return a
}
func rid08CreateAccount(t *testing.T, f *installationNativeWorld, name string) string {
	t.Helper()
	ctx, cancel := context.WithTimeout(f.given.ctx, 15*time.Second)
	defer cancel()
	require.Equal(t, string(f.given.user), f.operator.UserID())
	var op installruntime.Operation
	code, err := f.wire.JSON(ctx, http.MethodPost, "/iam/v1/accounts", f.operator.Bearer(), map[string]string{"name": name}, &op)
	require.NoError(t, err)
	require.Equal(t, http.StatusOK, code)
	require.NotEmpty(t, op.ID)
	op, err = f.wire.AwaitOperation(ctx, f.operator.Bearer(), op)
	require.NoError(t, err)
	require.True(t, op.Done)
	require.Nil(t, op.Error)
	var any anypb.Any
	require.NoError(t, protojson.Unmarshal(op.Response, &any))
	var account iamv1.Account
	require.NoError(t, any.UnmarshalTo(&account))
	require.NotEmpty(t, account.Id)
	require.Equal(t, name, account.Name)
	var got iamv1.Account
	f.publicRead(t, "/iam/v1/accounts/"+account.Id, &got)
	require.Equal(t, account.Id, got.Id)
	require.Equal(t, name, got.Name)
	var owner string
	require.NoError(t, f.given.pool.QueryRow(ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id=$1`, account.Id).Scan(&owner))
	require.Equal(t, string(f.given.user), owner)
	require.NoError(t, ctx.Err())
	return account.Id
}
func rid08WaitRealWindow(t *testing.T, f *installationNativeWorld, full rid08Admission) rid08Admission {
	t.Helper()
	require.True(t, full.Present)
	require.EqualValues(t, 3, full.Admitted)
	deadline := full.Started.Add(time.Duration(full.WindowSeconds) * time.Second)
	var sessionExpires time.Time
	require.NoError(t, f.given.pool.QueryRow(f.given.ctx, `SELECT expires_at FROM kaname.human_sessions WHERE id=$1 AND user_id=$2`, string(f.given.session.id), string(f.given.user)).Scan(&sessionExpires))
	require.True(t, sessionExpires.After(deadline.Add(10*time.Minute)), "same O's real initial session covers actual hour")
	require.True(t, f.creator.ExpiresAt.After(deadline.Add(10*time.Minute)), "same standing key must cover the lawful wait")
	var observations []rid08Admission
	for {
		now := rid08AdmissionRead(t, f)
		require.Equal(t, full.CarrierDigest, now.CarrierDigest)
		observations = append(observations, now)
		if !now.DBNow.Before(deadline) {
			// Normal retention may already remove an elapsed row. Never rewrite it or
			// require it to survive its own normal cleanup policy.
			if now.Present {
				require.Equal(t, full.Started, now.Started)
				require.EqualValues(t, 3, now.Admitted)
			}
			rid08Write(t, f.session.Root, "real-admission-window", struct {
				Original                            rid08Admission
				Expires, SessionExpires, KeyExpires time.Time
				Observations                        []rid08Admission
			}{full, deadline, sessionExpires, f.creator.ExpiresAt, observations})
			f.renewOperator(t, f.given.ctx)
			require.Equal(t, full.User, f.operator.UserID())
			return now
		}
		require.True(t, now.Present)
		require.Equal(t, full.Started, now.Started)
		require.EqualValues(t, 3, now.Admitted)
		remaining := deadline.Sub(now.DBNow)
		if remaining > time.Minute {
			remaining = time.Minute
		}
		timer := time.NewTimer(remaining)
		select {
		case <-f.given.ctx.Done():
			timer.Stop()
			t.Fatal("actual admission window did not expire before job deadline")
		case <-timer.C:
		}
	}
}

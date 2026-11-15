// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"net"
	"testing"
	"time"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

func TestResourceOpenErrorRetainsOutageAndCancellationCauses(t *testing.T) {
	dial := &net.OpError{Op: "dial", Net: "tcp", Err: errors.New("connection refused")}
	outage := errors.Join(errors.New("pool connection acquisition failed"), dial)
	got := resourceOpenError(context.Background(), outage)
	require.ErrorIs(t, got, iamerr.ErrUnavailable)
	require.ErrorIs(t, got, outage)
	require.ErrorIs(t, got, dial)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	got = resourceOpenError(ctx, outage)
	require.ErrorIs(t, got, context.Canceled)
	require.ErrorIs(t, got, outage)
	require.False(t, errors.Is(got, iamerr.ErrUnavailable))
	unknown := errors.New("unclassified open failure")
	got = resourceOpenError(context.Background(), unknown)
	require.ErrorIs(t, got, unknown)
	require.False(t, errors.Is(got, iamerr.ErrUnavailable))
}

func TestResourceRunRejectsMissingRunnerBeforePoolAccess(t *testing.T) {
	var runner *ResourceDecisionRunner
	_, err := runner.RunResourceDecision(context.Background(), kaname.ResourceDecisionIntent{})
	require.ErrorIs(t, err, kaname.ErrSourceUnconfirmed)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = runner.RunResourceDecision(ctx, kaname.ResourceDecisionIntent{})
	require.ErrorIs(t, err, context.Canceled)
}

func TestResourceAttemptRollbackOutlivesCanceledRequestWithDeadline(t *testing.T) {
	raw := &resourceLifecycleTx{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started := time.Now()
	require.NoError(t, rollbackResourceAttempt(ctx, raw))
	require.Equal(t, 1, raw.rollbacks)
	deadline, ok := raw.cleanup.Deadline()
	require.True(t, ok)
	require.WithinDuration(t, started.Add(5*time.Second), deadline, time.Second)
}

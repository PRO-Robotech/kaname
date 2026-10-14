// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package revocationpolicy_test

// clock_test.go — порт общего источника моментов (задача kaname#589): предел
// на каждый вызов, отказ построения без источника и без предела, отказ —
// ошибка, а не нулевой момент.

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/testsupport/momentclock"
)

// deadlineSeen — источник, запоминающий срок контекста вызова.
type deadlineSeen struct {
	at       time.Time
	deadline time.Time
	has      bool
}

func (d *deadlineSeen) Now(ctx context.Context) (time.Time, error) {
	d.deadline, d.has = ctx.Deadline()
	return d.at, nil
}

func TestClockWithDeadline_BoundsEveryCall(t *testing.T) {
	inner := &deadlineSeen{at: time.Date(2026, 10, 7, 9, 0, 0, 0, time.FixedZone("x", 3*3600))}
	c, err := revocationpolicy.ClockWithDeadline(inner, 3*time.Second)
	require.NoError(t, err)
	before := time.Now()
	at, err := revocationpolicy.Moment(context.Background(), c)
	require.NoError(t, err)
	require.True(t, inner.has, "вызов источника несёт срок")
	require.False(t, inner.deadline.After(before.Add(3*time.Second+time.Second)), "срок — объявленный предел")
	require.Equal(t, time.UTC, at.Location(), "момент — в UTC")
	require.True(t, at.Equal(inner.at))
}

func TestClockWithDeadline_RefusesToBuildWithoutSourceOrLimit(t *testing.T) {
	_, err := revocationpolicy.ClockWithDeadline(momentclock.Func(time.Now), 0)
	require.ErrorIs(t, err, revocationpolicy.ErrLimitNotPositive)
	_, err = revocationpolicy.ClockWithDeadline(nil, time.Second)
	require.ErrorIs(t, err, revocationpolicy.ErrNoClock)
}

func TestMoment_RefusalIsAnErrorNotAZeroMoment(t *testing.T) {
	cause := errors.New("dial tcp 10.0.0.9:5432")
	for name, c := range map[string]struct {
		clock revocationpolicy.Clock
		is    error
		class string
	}{
		"не ответил":        {momentclock.Failing{Err: cause}, revocationpolicy.ErrClockUnavailable, "store"},
		"вышел срок":        {momentclock.Failing{Err: context.DeadlineExceeded}, revocationpolicy.ErrClockUnavailable, "deadline"},
		"отменён":           {momentclock.Failing{Err: context.Canceled}, revocationpolicy.ErrClockUnavailable, "canceled"},
		"ответил нулём":     {momentclock.At(time.Time{}), revocationpolicy.ErrClockUnavailable, "store"},
		"источник не подан": {nil, revocationpolicy.ErrNoClock, "unwired"},
	} {
		t.Run(name, func(t *testing.T) {
			at, err := revocationpolicy.Moment(context.Background(), c.clock)
			require.ErrorIs(t, err, c.is)
			require.True(t, at.IsZero())
			require.Equal(t, c.class, revocationpolicy.MomentFailureClass(err))
		})
	}
}

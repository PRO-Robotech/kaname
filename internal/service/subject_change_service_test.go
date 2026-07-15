// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// subject_change_service_test.go — unit tests for SubjectChangeService clamp logic.
// Uses a fake SubjectChangeReader (records the limit argument received) so no
// Docker / Postgres is needed — runs fast even without -short.
package service_test

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

// fakeReader records the last limit argument passed to PollSubjectChanges.
type fakeReader struct{ lastLimit int32 }

func (f *fakeReader) PollSubjectChanges(_ context.Context, _ int64, limit int32) ([]service.SubjectChange, int64, error) {
	f.lastLimit = limit
	return nil, 0, nil
}

func TestSubjectChangeService_LimitClamp(t *testing.T) {
	ctx := context.Background()

	tests := []struct {
		name      string
		inputLmt  int32
		wantLimit int32
	}{
		{"zero_defaults_to_256", 0, 256},
		{"negative_defaults_to_256", -1, 256},
		{"over_max_clamped_to_1000", 5000, 1000},
		{"at_max_passes_through", 1000, 1000},
		{"small_value_passes_through", 50, 50},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			fake := &fakeReader{}
			svc := service.NewSubjectChangeService(fake)
			_, _, err := svc.PollSubjectChanges(ctx, 0, tc.inputLmt)
			require.NoError(t, err)
			require.Equal(t, tc.wantLimit, fake.lastLimit,
				"fake reader received unexpected limit")
		})
	}
}

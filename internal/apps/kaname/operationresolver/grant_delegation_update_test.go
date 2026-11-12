// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package operationresolver

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/operations"
	kanamerepo "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/anypb"
)

// Никакое чтение строки не восстановит потерянные целевые оси. Даже отсутствие
// primary-порта или его недоступность не должны оставлять Update незавершённым.
func TestGrantDelegationUpdateRecoveryIsInterruptedWithoutReader(t *testing.T) {
	metadata, err := anypb.New(&iamv1.UpdateGrantDelegationMetadata{
		GrantDelegationId: "gdl00000000000000001", AccountId: "acc00000000000000001",
	})
	require.NoError(t, err)
	for _, tc := range []struct {
		name string
		repo kanamerepo.Repository
	}{
		{"no repository", nil},
		{"no primary port", struct{ kanamerepo.Repository }{}},
		{"readers unavailable", &primaryRouteProbe{cause: context.DeadlineExceeded}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := New(tc.repo, nil, nil)
			for i := 0; i < 2; i++ {
				result, err := r.Resolve(context.Background(), operations.Operation{ID: "iop_update", Metadata: metadata})
				require.NoError(t, err, "ошибка resolver оставила бы orphan до следующего прохода")
				require.Equal(t, operations.OutcomeInterrupted, result.Outcome, "ни ложный Done, ни бесконечный Skip")
				require.Nil(t, result.Response, "неизвестный исход коммита не является успешным ответом")
			}
			if probe, ok := tc.repo.(*primaryRouteProbe); ok {
				require.Zero(t, probe.primary)
				require.Zero(t, probe.ordinary)
			}
		})
	}
}

// Create/Revoke по-прежнему требуют primary: их исход зависит от строки, и
// новая ветка Update не разрешает им fallback на реплику или общий Interrupted.
func TestGrantDelegationRecoveryStillRequiresPrimaryPort(t *testing.T) {
	for _, metadata := range []proto.Message{
		&iamv1.CreateGrantDelegationMetadata{},
		&iamv1.RevokeGrantDelegationMetadata{},
	} {
		t.Run(string(metadata.ProtoReflect().Descriptor().Name()), func(t *testing.T) {
			packed, err := anypb.New(metadata)
			require.NoError(t, err)
			// Встроенный nil-порт упадёт, если resolver попробует ordinary Reader.
			repo := struct{ kanamerepo.Repository }{}
			result, err := New(repo, nil, nil).Resolve(context.Background(), operations.Operation{Metadata: packed})
			require.EqualError(t, err, "operationresolver: grant delegation primary reader is not wired")
			require.Equal(t, operations.OutcomeSkip, result.Outcome)
			require.Nil(t, result.Response)
		})
	}
}

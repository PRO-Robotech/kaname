// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package operationresolver

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

func getPresent(_ context.Context, id domain.RoleID) (domain.Role, error) {
	return domain.Role{ID: id}, nil
}

func getAbsent(_ context.Context, _ domain.RoleID) (domain.Role, error) {
	return domain.Role{}, iamerr.ErrNotFound
}

func marshalTestRole(r domain.Role) (*anypb.Any, error) {
	return anypb.New(&iamv1.Role{Id: string(r.ID)})
}

// TestResolveExistence — ядро orphan-резолюции: для Create/Update ресурс должен
// присутствовать (→ Done+Response), иначе работа не закоммичена (→ Interrupted);
// для Delete отсутствие = успех (→ Done(nil)), присутствие = не завершено
// (→ Interrupted).
func TestResolveExistence(t *testing.T) {
	ctx := context.Background()

	t.Run("create present → Done with response", func(t *testing.T) {
		res, err := resolveExistence(ctx, kindCreate, "rol_1", getPresent, marshalTestRole)
		require.NoError(t, err)
		require.Equal(t, operations.OutcomeDone, res.Outcome)
		require.NotNil(t, res.Response, "Done на Create несет текущий ресурс")
	})

	t.Run("create absent → Interrupted", func(t *testing.T) {
		res, err := resolveExistence(ctx, kindCreate, "rol_1", getAbsent, marshalTestRole)
		require.NoError(t, err)
		require.Equal(t, operations.OutcomeInterrupted, res.Outcome)
	})

	t.Run("update absent → Interrupted", func(t *testing.T) {
		res, err := resolveExistence(ctx, kindUpdate, "rol_1", getAbsent, marshalTestRole)
		require.NoError(t, err)
		require.Equal(t, operations.OutcomeInterrupted, res.Outcome)
	})

	t.Run("delete absent → Done empty", func(t *testing.T) {
		res, err := resolveExistence(ctx, kindDelete, "rol_1", getAbsent, marshalTestRole)
		require.NoError(t, err)
		require.Equal(t, operations.OutcomeDone, res.Outcome)
		require.Nil(t, res.Response, "удаленный ресурс → Empty-семантика")
	})

	t.Run("delete present → Interrupted", func(t *testing.T) {
		res, err := resolveExistence(ctx, kindDelete, "rol_1", getPresent, marshalTestRole)
		require.NoError(t, err)
		require.Equal(t, operations.OutcomeInterrupted, res.Outcome)
	})
}

// TestResolveExistence_TransientReadError — нераспознанная ошибка чтения (не
// not-found) пробрасывается: движок инкрементит reconcile_errors и пропускает
// orphan до следующего sweep'а, а не «решает» его неверно.
func TestResolveExistence_TransientReadError(t *testing.T) {
	getErr := func(_ context.Context, _ domain.RoleID) (domain.Role, error) {
		return domain.Role{}, context.DeadlineExceeded
	}
	_, err := resolveExistence(context.Background(), kindCreate, "rol_1", getErr, marshalTestRole)
	require.Error(t, err, "transient read error must not be swallowed into a terminal decision")
}

// TestResolve_NilMetadata — операция без метаданных не наша → Skip.
func TestResolve_NilMetadata(t *testing.T) {
	r := New(nil)
	res, err := r.Resolve(context.Background(), operations.Operation{ID: "iop_1"})
	require.NoError(t, err)
	require.Equal(t, operations.OutcomeSkip, res.Outcome)
}

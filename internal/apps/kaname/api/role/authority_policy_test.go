// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package role

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

func TestRoleActivePolicyNeverFallsBackToLegacyWriter(t *testing.T) {
	for _, create := range []bool{true, false} {
		called := false
		_, err := (rolePolicySelection{configured: true}).run(context.Background(), nil, domain.Role{}, create, true, func(context.Context, Writer) (domain.Role, error) { called = true; return domain.Role{}, nil })
		require.Error(t, err)
		require.False(t, called)
	}
}

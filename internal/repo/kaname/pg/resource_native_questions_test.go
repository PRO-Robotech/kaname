// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/stretchr/testify/require"
)

func TestResourceNativeQuestionsUseOnlyRegistrationOwnerAccounts(t *testing.T) {
	require.NoError(t, validateResourceRegistrationModel(nativeBoundaryBundle(t)))
	q, err := resourceRegistrationQuestions("registry", []domain.AccountID{"acc_old", "acc_new", "acc_old"})
	require.NoError(t, err)
	require.Len(t, q.roots, 2)
	actor := "service_account:" + authzguard.ServiceAccountIDForService("registry")
	require.Contains(t, q.roots, nativePolicyQuestion{actor, "fga_writer", "account", "acc_old"})
	require.Contains(t, q.roots, nativePolicyQuestion{actor, "fga_writer", "account", "acc_new"})
	for _, accounts := range [][]domain.AccountID{nil, {""}, {"acc:foreign"}, {"*"}} {
		_, err := resourceRegistrationQuestions("registry", accounts)
		require.Error(t, err)
	}
	_, err = resourceRegistrationQuestions("", []domain.AccountID{"acc_old"})
	require.Error(t, err)
}

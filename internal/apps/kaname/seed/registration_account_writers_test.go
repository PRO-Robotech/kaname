// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package seed

import (
	"context"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/stretchr/testify/require"
	"testing"
)

type registrationPlanStore struct{ calls int }

func (s *registrationPlanStore) ApplyRegistrationAccountWriters(context.Context, RegistrationWriterPlan) error {
	s.calls++
	return nil
}
func TestRegistrationWriterPlan_ValidatesEntireBatchAgainstExistingRoster(t *testing.T) {
	roster, err := moduleidentity.Parse([]string{"modules/kacho-registry=module-writer"})
	require.NoError(t, err)
	valid := domain.RegistrationAccountWriter{AssignmentID: "installation-1", AccountID: "acc-a", Module: "registry"}
	for _, bad := range []domain.RegistrationAccountWriter{
		{AssignmentID: "", AccountID: "acc-a", Module: "registry"},
		{AssignmentID: "star", AccountID: "*", Module: "registry"},
		{AssignmentID: "unknown-module", AccountID: "acc-a", Module: "vpc"},
		valid,
	} {
		s := &registrationPlanStore{}
		err := ApplyRegistrationAccountWriters(context.Background(), s, roster, RegistrationWriterPlan{Assignments: []domain.RegistrationAccountWriter{valid, bad}})
		require.Error(t, err)
		require.Zero(t, s.calls)
	}
	s := &registrationPlanStore{}
	require.NoError(t, ApplyRegistrationAccountWriters(context.Background(), s, roster, RegistrationWriterPlan{Assignments: []domain.RegistrationAccountWriter{valid}}))
	require.Equal(t, 1, s.calls)
	s = &registrationPlanStore{}
	require.NoError(t, ApplyRegistrationAccountWriters(context.Background(), s, roster, RegistrationWriterPlan{Assignments: []domain.RegistrationAccountWriter{}}))
	require.Equal(t, 1, s.calls)
}

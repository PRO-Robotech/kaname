// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// wildcardBinding — выдача на кластере с набором субъектов subjects; пара —
// проекция первого члена, как после нормализации.
func wildcardBinding(system bool, subjects ...Subject) AccessBinding {
	return AccessBinding{
		SubjectType:  subjects[0].Type,
		SubjectID:    subjects[0].ID,
		Subjects:     subjects,
		RoleID:       "rol_wildcard_probe01",
		ResourceType: "cluster",
		ResourceID:   ClusterSingletonID,
		System:       system,
	}
}

// TestAccessBindingValidate_WildcardIsJudgedOnEverySubject — подстановочный
// субъект судится на КАЖДОМ члене набора, а не на проекции первого (kaname#917).
func TestAccessBindingValidate_WildcardIsJudgedOnEverySubject(t *testing.T) {
	named := Subject{Type: SubjectTypeUser, ID: "usr_wildcardprobe001"}
	wild := Subject{Type: SubjectTypeUser, ID: "*"}

	t.Run("второй член набора, несистемная выдача — отказ", func(t *testing.T) {
		err := wildcardBinding(false, named, wild).Validate()
		require.Error(t, err)
		require.Contains(t, err.Error(), `Illegal argument subject_id "*" on a non-system access binding`)
	})
	t.Run("первый член набора, несистемная выдача — отказ", func(t *testing.T) {
		require.Error(t, wildcardBinding(false, wild, named).Validate())
	})
	t.Run("системная выдача — законна", func(t *testing.T) {
		require.NoError(t, wildcardBinding(true, named, wild).Validate())
	})
	t.Run("без подстановочного — законна", func(t *testing.T) {
		require.NoError(t, wildcardBinding(false, named, Subject{Type: SubjectTypeUser, ID: "usr_wildcardprobe002"}).Validate())
	})
}

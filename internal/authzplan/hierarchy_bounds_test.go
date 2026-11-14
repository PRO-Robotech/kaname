// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzplan

import (
	"github.com/stretchr/testify/require"
	"testing"
)

// Полный путь до cluster сохраняет единственный разрешающий источник.
// Шестой переход обязан сделать весь план невыразимым, а не пустым допустимым.
func TestCompileHierarchyFiveHopsAndSixthRejected(t *testing.T) {
	m, err := ParseModel(`model
  schema 1.1
type user
type cluster
  relations
   define admin: [user]
type account
  relations
   define cluster: [cluster]
   define admin: admin from cluster
type project
  relations
   define account: [account]
   define admin: admin from account
type box
  relations
   define project: [project]
   define admin: admin from project
type item
  relations
   define box: [box]
   define admin: admin from box
type tag
  relations
   define item: [item]
   define admin: admin from item
type leaf
  relations
   define tag: [tag]
   define admin: admin from tag
`)
	require.NoError(t, err)
	five, err := m.Compile("tag", "admin")
	require.NoError(t, err)
	require.True(t, five.Expressible(), "%v", five.Unclassified)
	require.Len(t, five.Atoms, 1)
	require.Equal(t, AtomFact, five.Atoms[0].Kind)
	require.Equal(t, "cluster", five.Atoms[0].ParentType)
	require.Equal(t, "admin", five.Atoms[0].Relation)
	six, err := m.Compile("leaf", "admin")
	require.NoError(t, err)
	require.False(t, six.Expressible())
	require.NotEmpty(t, six.Unclassified)
	require.Empty(t, six.Atoms, "источник за границей не превращается в доступный частичный план")
}

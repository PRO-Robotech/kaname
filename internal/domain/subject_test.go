// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package domain

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// Subject value-object + the normalization of the AccessBinding subjects[] input
// against the legacy single subject (two-way projection). These are PURE domain
// rules (no DB / no transport); the use-case maps the returned sentinel to the
// gRPC code.

func TestSubject_Validate(t *testing.T) {
	t.Run("valid user", func(t *testing.T) {
		require.NoError(t, Subject{Type: SubjectTypeUser, ID: "usr_alice"}.Validate())
	})
	t.Run("valid service_account", func(t *testing.T) {
		require.NoError(t, Subject{Type: SubjectTypeServiceAccount, ID: "sva_bot"}.Validate())
	})
	t.Run("valid group", func(t *testing.T) {
		require.NoError(t, Subject{Type: SubjectTypeGroup, ID: "grp_admins"}.Validate())
	})
	t.Run("empty id rejected", func(t *testing.T) {
		require.Error(t, Subject{Type: SubjectTypeUser, ID: ""}.Validate())
	})
	t.Run("bad type rejected", func(t *testing.T) {
		require.Error(t, Subject{Type: "robot", ID: "usr_x"}.Validate())
	})
}

func TestSubject_IsGroup(t *testing.T) {
	assert.True(t, Subject{Type: SubjectTypeGroup, ID: "grp_x"}.IsGroup())
	assert.False(t, Subject{Type: SubjectTypeUser, ID: "usr_x"}.IsGroup())
}

func TestNormalizeSubjects(t *testing.T) {
	// subjects[] is canonical; legacy single is a one-element projection.
	t.Run("subjects[] preferred — legacy single empty", func(t *testing.T) {
		subs := []Subject{{Type: SubjectTypeUser, ID: "usr_a"}, {Type: SubjectTypeGroup, ID: "grp_g"}}
		out, err := NormalizeSubjects(subs, "", "")
		require.NoError(t, err)
		require.Len(t, out, 2)
		assert.Equal(t, "usr_a", string(out[0].ID))
		assert.Equal(t, SubjectTypeGroup, out[1].Type)
	})
	t.Run("legacy single projects to one-element subjects[]", func(t *testing.T) {
		out, err := NormalizeSubjects(nil, SubjectTypeUser, "usr_a")
		require.NoError(t, err)
		require.Len(t, out, 1)
		assert.Equal(t, SubjectTypeUser, out[0].Type)
		assert.Equal(t, SubjectID("usr_a"), out[0].ID)
	})
	t.Run("subjects[] AND matching legacy single is accepted (single==subjects[0])", func(t *testing.T) {
		subs := []Subject{{Type: SubjectTypeUser, ID: "usr_a"}, {Type: SubjectTypeGroup, ID: "grp_g"}}
		out, err := NormalizeSubjects(subs, SubjectTypeUser, "usr_a")
		require.NoError(t, err)
		require.Len(t, out, 2)
	})
	t.Run("subjects[] AND conflicting legacy single → error", func(t *testing.T) {
		subs := []Subject{{Type: SubjectTypeUser, ID: "usr_a"}}
		_, err := NormalizeSubjects(subs, SubjectTypeGroup, "grp_g")
		require.Error(t, err)
	})
	t.Run("empty subjects[] and empty legacy single → error (1..32)", func(t *testing.T) {
		_, err := NormalizeSubjects(nil, "", "")
		require.Error(t, err)
	})
	t.Run("over 32 subjects → error", func(t *testing.T) {
		var subs []Subject
		for i := 0; i < 33; i++ {
			subs = append(subs, Subject{Type: SubjectTypeUser, ID: SubjectID("usr_" + string(rune('a'+i%26)) + string(rune('0'+i/26)))})
		}
		_, err := NormalizeSubjects(subs, "", "")
		require.Error(t, err)
	})
	t.Run("duplicate subject rejected", func(t *testing.T) {
		subs := []Subject{{Type: SubjectTypeUser, ID: "usr_a"}, {Type: SubjectTypeUser, ID: "usr_a"}}
		_, err := NormalizeSubjects(subs, "", "")
		require.Error(t, err)
	})
	t.Run("invalid subject in list rejected", func(t *testing.T) {
		subs := []Subject{{Type: "robot", ID: "x"}}
		_, err := NormalizeSubjects(subs, "", "")
		require.Error(t, err)
	})
}

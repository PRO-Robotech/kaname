// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package installruntime

import (
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestNativeEvidenceDoesNotInterpretTestIdentity(t *testing.T) {
	seen := map[string]bool{}
	for _, identity := range []string{"RID01/real standalone F0 -> verified O -> standing C -> full serve delivery", "a/b", "a-b", "a b", "a_b", "$(touch sentinel)", "`touch sentinel`", "a;touch sentinel", "O/новый D"} {
		dir, err := EvidenceDirectory("/private/native-evidence", identity)
		require.NoError(t, err)
		require.Equal(t, "/private/native-evidence", filepath.Dir(dir))
		require.NoError(t, validateStandPath(dir))
		require.False(t, seen[dir], "distinct test identities must not collapse into one evidence directory")
		seen[dir] = true
		again, err := EvidenceDirectory("/private/native-evidence", identity)
		require.NoError(t, err)
		require.Equal(t, dir, again)
	}
}

func TestNativeStandRejectsUnsafePathBeforePreparation(t *testing.T) {
	for _, path := range []string{"relative", "/private/../other", "/private/a b", "/private/a>b", "/private/$name", "/private/$(touch sentinel)", "/private/`touch sentinel`", "/private/a;b", "/private/a\nb", "/private/'quoted'"} {
		require.Error(t, validateStandPath(path))
		_, err := EvidenceDirectory(path, "RID01")
		require.Error(t, err)
	}
	require.NoError(t, validateStandPath("/private/.git/native-first-01_test"))
}

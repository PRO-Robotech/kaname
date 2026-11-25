// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

import (
	"github.com/stretchr/testify/require"
	"testing"
)

func TestFreshnessSignalSurvivesEveryNativeAssembler(t *testing.T) {
	for name, build := range map[string]func(string, bool) (string, error){
		"check": verdictQuerySQL, "batch": verdictManyQuerySQL, "list": listQuerySQL,
		"subjects": subjectsQuerySQL, "expand": expandQuerySQL, "administrative": administrativeQuerySQL,
	} {
		for _, nested := range []bool{false, true} {
			t.Run(name+nestingName(nested), func(t *testing.T) {
				query, err := build("kaname.projects", nested)
				require.NoError(t, err)
				require.Contains(t, query, factFreshSQL)
				require.NotContains(t, query, "{{")
			})
		}
	}
}

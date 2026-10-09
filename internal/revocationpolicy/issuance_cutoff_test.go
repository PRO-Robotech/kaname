// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package revocationpolicy_test

// issuance_cutoff_test.go — вердикт «выдавать» называет стоящую отсечку, по
// которой вынесен (kaname#684): выпуск кладёт `iat` строго позже неё. Прочие
// вердикты и принципалы без отсечки отсечки не называют.

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
	"github.com/PRO-Robotech/kaname/internal/service"
)

func TestAtIssuance_AllowedNamesTheStandingCutoff(t *testing.T) {
	ctx := context.Background()
	for _, c := range []struct {
		name      string
		store     *cutoffs
		principal service.ResolvedPrincipal
		want      revocationpolicy.Verdict
		wantCut   time.Time
	}{
		{"человек после отсечки — отсечка названа", &cutoffs{at: map[string]time.Time{"usr_a": cutoff}},
			person("usr_a", at(cutoff.Add(time.Microsecond))), revocationpolicy.Allowed, cutoff},
		{"человек без отсечки — нулевая", &cutoffs{at: map[string]time.Time{}},
			person("usr_a", at(cutoff)), revocationpolicy.Allowed, time.Time{}},
		{"человек не позже отсечки — отказ без отсечки", &cutoffs{at: map[string]time.Time{"usr_a": cutoff}},
			person("usr_a", at(cutoff)), revocationpolicy.Revoked, time.Time{}},
		{"машина — отсечки человека нет", &cutoffs{at: map[string]time.Time{"usr_a": cutoff}},
			service.ResolvedPrincipal{Kind: service.PrincipalServiceAccount}, revocationpolicy.Allowed, time.Time{}},
	} {
		t.Run(c.name, func(t *testing.T) {
			got, cut, err := revocationpolicy.AtIssuance(ctx, c.store, c.principal, time.Time{})
			require.NoError(t, err)
			require.Equal(t, c.want, got)
			require.True(t, c.wantCut.Equal(cut), "названная отсечка %s, ожидалась %s", cut, c.wantCut)
		})
	}
}

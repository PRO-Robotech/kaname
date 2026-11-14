// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"testing"
)

func TestAdministrativeIAMDirectHasNoMirrorAncestors(t *testing.T) {
	// Нет TX намеренно: IAM-direct producer не обращается к mirror ancestors.
	var sources *nativeAdministrativeSources
	for typ := range iamDirectScanSpecs {
		if domain.FeedSourceForType(typ) != domain.FeedIAMDirect {
			t.Fatalf("unexpected direct feed %s", typ)
		}
		ancestors, err := sources.currentAncestors(context.Background(), typ, "object", &relverdict.AdministrativeReadBudget{})
		if err != nil || ancestors != nil {
			t.Fatalf("%s gained mirror ancestors: %v %v", typ, ancestors, err)
		}
	}
}

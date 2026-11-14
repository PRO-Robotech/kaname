// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package internal_iam

import (
	"context"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestResourceExplicitNilReplacesLegacyBeginner(t *testing.T) {
	legacy := &smTxBeginner{}
	uc := (&RegisterResourceUseCase{txb: legacy}).WithResourceTxBeginner(nil)
	tx, err := uc.txb.Begin(context.Background())
	require.Error(t, err)
	require.Nil(t, tx)
	_, ok := uc.txb.(closedResourceBeginner)
	require.True(t, ok)
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
)

func loadGroupParticipationBundle(ctx context.Context, c config.AuthorityProtocolConfig, handoff kaname.AuthorityBundleHandoff, model preparedModel) (*granteffect.Bundle, error) {
	if err := c.Validate(); err != nil {
		return nil, err
	}
	if !c.Participant() {
		return nil, nil
	}
	if handoff == nil {
		return nil, fmt.Errorf("authority participant handoff is absent")
	}
	b, err := handoff.LoadAuthorityBundle(ctx, model.text, model.report.KeyTerms...)
	if err != nil {
		return nil, fmt.Errorf("authority participant bundle handoff: %w", err)
	}
	if err = b.Validate(); err != nil {
		return nil, err
	}
	return b, nil
}

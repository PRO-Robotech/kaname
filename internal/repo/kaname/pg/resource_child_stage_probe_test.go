// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"encoding/json"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
	"github.com/jackc/pgx/v5"
)

type UserChildStageProbe struct {
	Target           domain.UserChildRegistrationTarget
	ParentRegistered bool
	ChildRegistered  bool
	Hierarchies      []domain.ParentHierarchy
	OldScopes        []domain.ContainerScope
	NewScopes        []domain.ContainerScope
	Plan             kaname.AuthorityFencePlan
	Envelope         json.RawMessage
	SameLifetime     bool
	SourceSealed     bool
	Queries          []string
}

// Только наблюдение результата настоящего RR stage. Проба не добавляет
// источники и не выполняет private compiler, финализацию или запись.
func ProbeUserChildStage(ctx context.Context, tx pgx.Tx, bundle *granteffect.Bundle,
	input kaname.UserChildRegistrationInput, principal operations.Principal,
) (out UserChildStageProbe, err error) {
	lifetime, err := newResourceAttemptLifetime(tx.Conn(), bundle)
	if err != nil {
		return out, err
	}
	defer lifetime.close()
	observed := childAuthorizationObservedTx{Tx: tx, queries: &out.Queries}
	budget := &relverdict.AdministrativeReadBudget{}
	runner := &ResourceDecisionRunner{bundle: bundle}
	stage, err := runner.stageUserChildRegistration(ctx, observed, lifetime, input, principal, budget)
	if err != nil {
		return out, err
	}
	out.Target = stage.authorization.target
	out.ParentRegistered, out.ChildRegistered = stage.parentRegistered, stage.childRegistered
	out.Hierarchies, out.OldScopes, out.NewScopes = stage.hierarchies, stage.oldScopes, stage.newScopes
	out.SameLifetime = stage.source.lifetime == lifetime && stage.authorization.native.lifetime == lifetime &&
		stage.source.stageTX == observed && stage.source.budget == budget && stage.authorization.native.budget == budget
	out.SourceSealed = stage.source.sealed
	if stage.footprint == nil {
		return out, nil
	}
	out.Plan = stage.footprint.plan
	proposal, err := stage.proposal()
	if err != nil {
		return out, err
	}
	out.Envelope = proposal.payload
	return out, nil
}

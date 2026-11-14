// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later
package grantpolicy

import (
	"context"
	"testing"
	"time"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	"github.com/stretchr/testify/require"
)

type capturedPolicyRecord struct{}

func (capturedPolicyRecord) Validate(kaname.SemanticAuthorityWriter, domain.Subject, time.Time) error {
	return kaname.ErrSourceUnconfirmed
}
func TestCapturedCoverageRequiresEntireEffectAndInsufficiencyIsUnknown(t *testing.T) {
	bundle, err := granteffect.NewBundle(context.Background(), authzmodel.DSL, catalog.Halves{Live: catalog.Rows{Modules: []string{"iam"}, Resources: []catalog.ResourceRow{{Module: "iam", Resource: "account", ObjectType: "account"}}, Verbs: []catalog.VerbRow{{Module: "iam", Resource: "account", Verb: "get", PerObject: true}}}}, granteffect.ProjectorVersion)
	require.NoError(t, err)
	actor := domain.Subject{Type: domain.SubjectTypeUser, ID: "usr_actor"}
	binding := granteffect.Binding{SourceID: "proposal", Role: domain.Role{ID: "rol_read", Rules: domain.Rules{{Module: "iam", Resources: []string{"account"}, Verbs: []string{"get"}}}}, Scope: domain.ScopeAnchor{Type: "account", ID: "acc_a"}, Recipient: actor, Subjects: []domain.Subject{actor}, Target: domain.AccessTarget{AllInScope: true}, CapabilityVersion: 1}
	p := WitnessedLowerBound{bundle: bundle, effects: bundle.Compile(binding)}
	p.census.ProducerPopulation = capturedPolicyRecord{}
	require.NoError(t, requireCoverage(p, binding), "complete positive coverage remains usable without claiming complete original population")
	binding.Scope.ID = "acc_foreign"
	err = requireCoverage(p, binding)
	require.ErrorIs(t, err, kaname.ErrCapturedProducerInsufficient)
	require.ErrorIs(t, err, kaname.ErrAuthorityClassificationChanged)
	require.NotErrorIs(t, err, iamerr.ErrPermissionDenied)
	p.census.ProducerPopulation = nil
	require.ErrorIs(t, requireCoverage(p, binding), iamerr.ErrPermissionDenied, "historical mode retains its denial contract")
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// token_enrichment_minimal_claims_test.go — what the reduced claim set says
// about its bearer, and what the platform does with that.
//
// The set exists for ONE population: a human who has just authenticated at the
// identity provider and whose kacho mirror has not committed yet. Provisioning
// is asynchronous, so their first token can be requested before the User row
// exists. Everything else that fails to resolve is refused rather than sent
// here.
//
// The type stamped on that set is not decoration. Two platform controls read it
// and treat one particular value as "there is no person here": the
// interactive-authentication floor lifts for it, and sender-constrained binding
// is demanded of it. Naming this population with that value hands it an
// exemption built for machines and a requirement it cannot meet — the second
// one silently, because the control defaults off and would take effect only on
// the day it is switched on.
package service_test

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho/pkg/grpcsrv"
	"github.com/PRO-Robotech/kacho/services/iam/internal/service"
)

func minimalClaimsFor(t *testing.T, subject string) map[string]any {
	t.Helper()
	svc := service.NewTokenEnrichmentService(
		service.TokenEnrichmentConfig{Domain: "api.test.cloud", HydraIssuer: "https://hydra.test.cloud"},
		nil,
	)
	claims := svc.MinimalClaims(subject)
	require.NotNil(t, claims)
	return claims
}

// TestMinimalClaims_DoesNotBuyTheMachineExemption — the behaviour, decided by
// the platform's own rule rather than by reading the string back.
//
// EvaluateStepUp is THE step-up rule; both enforcement points call it and
// neither re-implements an arm. Fed the type this set carries, with no acr
// presented and a floor required, it must refuse. A verdict of allow here means
// a human who has been through no second factor — and whose kacho identity we
// cannot even name yet — clears an assurance floor by claiming to be a machine.
func TestMinimalClaims_DoesNotBuyTheMachineExemption(t *testing.T) {
	claims := minimalClaimsFor(t, "kratos-identity-just-registered")

	principalType, _ := claims["kacho_principal_type"].(string)
	verdict := grpcsrv.EvaluateStepUp(grpcsrv.StepUpInput{
		PrincipalType: principalType,
		PresentedACR:  "",
		RequiredACR:   "2",
	})

	assert.Equal(t, grpcsrv.StepUpDenyACR, verdict,
		"the not-yet-mirrored interactive population must face the interactive-authentication "+
			"floor like any other person; it presented type %q", principalType)
}

// TestMinimalClaims_IsNotTypedAsAMachine — the same value gates the other
// control, which lives at the edge and cannot be exercised from here: a
// principal of the machine type is required to present a sender-constrained
// token, and this population's tokens are ordinary bearers. The control is off
// by default, so the mismatch costs nothing today and rejects every first login
// on the day it is enabled.
func TestMinimalClaims_IsNotTypedAsAMachine(t *testing.T) {
	claims := minimalClaimsFor(t, "kratos-identity-just-registered")

	assert.NotEqual(t, grpcsrv.PrincipalTypeServiceAccount, claims["kacho_principal_type"],
		"a person whose mirror has not committed yet is not a machine")
}

// TestMinimalClaims_NameNoPrincipal — the invariant the set's own documentation
// rests on: it authorizes nothing.
//
// That holds only because the set names no kacho principal. Subject resolution
// at the edge reads exactly these keys, in this order, and needs a non-empty id
// from one of them; with none present it falls through to a diagnostic subject
// that the permission model has no object type for and therefore always denies.
// Adding any one of them here would turn the set from a label into a grant, and
// nothing at the edge would object.
func TestMinimalClaims_NameNoPrincipal(t *testing.T) {
	claims := minimalClaimsFor(t, "kratos-identity-just-registered")

	for _, key := range []string{
		"kacho_principal_id",
		"kacho_user_id",
		"kacho_sa_id",
		"kacho_workload_id",
	} {
		assert.Empty(t, claims[key],
			"%s is one of the keys a subject is resolved from; the reduced set must name no principal", key)
	}
	assert.Equal(t, "kratos-identity-just-registered", claims["kacho_external_id"],
		"the external subject is carried for correlation only — it is not a kacho identity")
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding_test

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/corelib/grpcsrv"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/stretchr/testify/require"
)

// Только установка изолированного Given до Prepare/Activate. Полномочие получает
// SA владельца probemod, никогда исследуемые usrD/usrE, их роли либо выдачи.
// Используется штатный installation plan, не SQL tuple/grant и не allowing checker.
func fbInstallResourceRegistrationWriter(t *testing.T, ctx context.Context, owner *kanamepg.Repository, pool *pgxpool.Pool, account domain.AccountID, existingVPCMirrors bool, disabled ...domain.DisabledRegistrationModule) moduleidentity.Roster {
	t.Helper()
	declared := []string{"modules/kacho-probemod=module-writer"}
	if existingVPCMirrors {
		declared = append(declared, "modules/kacho-vpc=module-writer")
	}
	roster, err := moduleidentity.Parse(declared)
	require.NoError(t, err)
	writer, err := owner.Writer(ctx)
	require.NoError(t, err)
	defer writer.Rollback(ctx)
	_, err = writer.ServiceAccountsW().Insert(ctx, domain.ServiceAccount{
		ID:        domain.ServiceAccountID(authzguard.ServiceAccountIDForService("probemod")),
		AccountID: account, Name: "kacho-probemod", Description: "full-bind fixture resource producer",
	})
	require.NoError(t, err)
	require.NoError(t, writer.Commit(ctx))
	plan := seed.RegistrationWriterPlan{
		Assignments: []domain.RegistrationAccountWriter{{AssignmentID: "fb-probemod-resource-producer", AccountID: string(account), Module: "probemod"}},
	}
	if existingVPCMirrors {
		// newSCWorld создал два vpc.network mirror в accA. Сценарий их не
		// регистрирует: объявляем штатное first-switch исключение без права SA.
		plan.Disabled = []domain.DisabledRegistrationModule{{AccountID: string(account), Module: "vpc", Reason: "existing newSCWorld vpc.network fixtures are not registration producers in this full-bind scenario"}}
	}
	// Дополнительные исключения задаёт конкретный Given по известным парам,
	// а не обход всех найденных модулей. Неописанная регистрация по-прежнему
	// останавливает штатный preflight; human actors никаких прав не получают.
	plan.Disabled = append(plan.Disabled, disabled...)
	require.NoError(t, seed.ApplyRegistrationAccountWriters(ctx, kanamepg.NewRegistrationAccountWriterStore(pool), roster, plan))
	return roster
}

// UC и prepared runner получают один gate с настоящим native checker/runtime
// repo/bundle. Только контекст вызова producer несёт declared module identity;
// контексты human actor/recipient и все их regression oracles остаются прежними.
func fbFullResourceRegistration(t *testing.T, ctx context.Context, repo *kanamepg.Repository, bundle *granteffect.Bundle, checker authzguard.RelationChecker, roster moduleidentity.Roster) (*kanamepg.ResourceDecisionRunner, *authzguard.RelationWriteGate, context.Context) {
	t.Helper()
	gate := authzguard.NewRelationWriteGate(checker).WithModuleRoster(roster)
	runner, err := kanamepg.NewResourceDecisionRunner(ctx, repo, bundle, gate)
	require.NoError(t, err)
	registrationContext := grpcsrv.WithCertIdentityIn(ctx, grpcsrv.NewTrustDomain("kaname.test"), "spiffe://kaname.test/ns/modules/sa/kacho-probemod", true)
	return runner, gate, registrationContext
}

// Lifecycle выполняет настоящий переход на FULL2 до создания writer factories.
// Обычный runtime LOGIN не становится owner: owner только Stage/Activate;
// tagged copy, связанная с тем же runtime pool/bundle, передаётся всем consumers.
func fbActivateFullResourceWriter(t *testing.T, ctx context.Context, owner, runtime *kanamepg.Repository, bundle *granteffect.Bundle) *kanamepg.Repository {
	t.Helper()
	require.NoError(t, owner.StageFullAuthorityBundle(ctx, bundle))
	require.NoError(t, owner.ActivateFullAuthorityBundle(ctx, bundle))
	contract, err := kanamepg.NewFullWriterContract(ctx, runtime, bundle)
	require.NoError(t, err)
	full, err := runtime.WithFullWriterContract(contract)
	require.NoError(t, err)
	return full
}

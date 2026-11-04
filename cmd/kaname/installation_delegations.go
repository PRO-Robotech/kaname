// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"log/slog"
	"time"

	"github.com/PRO-Robotech/corelib/operations"
	gdapp "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/grant_delegation"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/clients"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func hasInstallationDelegations(manifests []*manifest.Manifest) bool {
	for _, m := range manifests {
		if m != nil && m.Seed != nil && len(m.Seed.GrantDelegations) > 0 {
			return true
		}
	}
	return false
}

// installationReadSource — канонический первичный считыватель. Его настоящая зависимость BeginTx
// может оборачиваться независимо от репозитория изменений.
type installationReadSource interface {
	InstallationAccounts(context.Context, string, int) ([]domain.AccountID, domain.AccountID, error)
	InstallationReferences(context.Context, string, string, []string) (domain.ServiceAccountID, []string, error)
}

// Неизменяемое значение выдаётся только после завершения настоящей успешной Operation.
// Штатный запуск не передаёт наблюдателя; транзакция здесь не удерживается.
type installationCompletedPair struct {
	CompletedPairs                     int
	AccountID, DelegateID, OperationID string
}

func applyInstallationDelegations(ctx context.Context, logger *slog.Logger, authn *installationAuthentication, repo gdapp.Repo, reads installationReadSource, ops operations.Repo, cat catalog.Source, relations clients.RelationStore, plans *authzmodel.Plans, target string, pageSize int, manifests []*manifest.Manifest, afterCompleted ...func(context.Context, installationCompletedPair) error) error {
	if !hasInstallationDelegations(manifests) {
		return nil
	}
	accounts, _, err := reads.InstallationAccounts(ctx, target, pageSize)
	if err != nil {
		return failInstallation(logger, "census", "accounts", "", "", 0, shared.MapRepoErrAt(ctx, err))
	}
	logger.Info("installation delegation account snapshot", slog.Int("accounts", len(accounts)))
	create := gdapp.NewCreateGrantDelegationUseCase(repo, ops, cat).WithRelationStore(relations, logger).WithInstallationModel(plans)
	pairs := 0
	for _, m := range manifests {
		if m.Seed == nil {
			continue
		}
		for _, d := range m.Seed.GrantDelegations {
			delegate, roles, err := reads.InstallationReferences(ctx, d.Delegate.Account, d.Delegate.Name, d.RoleIDs)
			if err != nil {
				return failInstallation(logger, "delegation", "", "", "", pairs, shared.MapRepoErrAt(ctx, err))
			}
			for _, account := range accounts {
				verified, err := authn.Authenticate(ctx)
				if err != nil {
					return failInstallation(logger, "delegation", "", string(account), string(delegate), pairs, err)
				}
				if err := authzguard.RequireClusterAdmin(verified, relations); err != nil {
					return failInstallation(logger, "authority", "", string(account), string(delegate), pairs, err)
				}
				op, err := create.ExecuteInstallation(verified, gdapp.CreateInput{
					AccountID: string(account), DelegateType: "SUBJECT_TYPE_SERVICE_ACCOUNT", DelegateID: string(delegate),
					RoleIDs: roles, TargetTypes: d.TargetTypes, SubjectTypes: d.SubjectTypes,
				})
				if err != nil {
					return failInstallation(logger, "delegation", "", string(account), string(delegate), pairs, err)
				}
				if err := waitInstallationOperation(ctx, ops, op.ID); err != nil {
					return failInstallation(logger, "delegation", "", string(account), string(delegate), pairs, err)
				}
				pairs++
				if len(afterCompleted) > 0 && afterCompleted[0] != nil {
					if err := afterCompleted[0](ctx, installationCompletedPair{CompletedPairs: pairs, AccountID: string(account), DelegateID: string(delegate), OperationID: op.ID}); err != nil {
						// Внутренние ошибки наблюдателя/управления не являются результатами Writer установки или
						// проверки полномочий: результат установки никогда не выдумывается.
						return err
					}
				}
			}
		}
	}
	logger.Info("installation delegation stage complete", slog.Int("pairs", pairs), slog.Int("accounts", len(accounts)), slog.Any("installation", installationResult{Stage: "delegation", Code: "OK", CompletedPairs: pairs}))
	return nil
}

func waitInstallationOperation(ctx context.Context, repo operations.Repo, id string) error {
	ctx, cancel := context.WithTimeout(ctx, 2*time.Minute)
	defer cancel()
	ticker := time.NewTicker(20 * time.Millisecond)
	defer ticker.Stop()
	for {
		op, err := repo.Get(ctx, id)
		if err != nil {
			return shared.MapRepoErrAt(ctx, err)
		}
		if op.Done {
			if op.Error != nil {
				code := op.Error.Code
				if code < int32(codes.OK) || code > int32(codes.Unauthenticated) {
					code = int32(codes.Unknown)
				}
				return status.Error(codes.Code(code), op.Error.Message)
			}
			return nil
		}
		select {
		case <-ctx.Done():
			return shared.MapRepoErrAt(ctx, ctx.Err())
		case <-ticker.C:
		}
	}
}

func validateInstallationInput(input config.ModuleSeedInstallerConfig) error {
	if input.TenantAccountID != nil {
		if *input.TenantAccountID == "" {
			return shared.InvalidArg("tenantAccountId", "one tenant account ID is required")
		}
		return shared.ValidateResourceID(*input.TenantAccountID, domain.PrefixAccount, "account")
	}
	return nil
}

func installationTarget(input config.ModuleSeedInstallerConfig) string {
	if input.TenantAccountID == nil {
		return ""
	}
	return *input.TenantAccountID
}

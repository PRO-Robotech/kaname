// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/PRO-Robotech/corelib/migratorcli"
	"github.com/PRO-Robotech/corelib/migratorcli/cobraargs"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
	"github.com/PRO-Robotech/kaname/internal/granteffect"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kaname "github.com/PRO-Robotech/kaname/internal/repo/kaname"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

// kaname#1034: отдельный явный операторский вызов. Ни миграции, ни запуск
// службы не вызывают activation. Выполнение требует настоящего migration owner.
func newAuthorityBundleCmd(opts *rootOptions) *cobra.Command {
	root := &cobra.Command{Use: "authority-bundle", Short: "Явное управление согласованным bundle и drain", Args: cobraargs.OnlyKnownCommands,
		RunE: func(*cobra.Command, []string) error { return migratorcli.ErrNoCommand }}
	for _, action := range []string{"bootstrap", "stage", "activate", "verify", "stage-full", "activate-full", "verify-full", "close"} {
		var dir string
		var imageOnly bool
		var fromPublication bool
		full := action == "stage-full" || action == "activate-full" || action == "verify-full"
		var runtimeRole string
		cmd := &cobra.Command{Use: action, Args: cobraargs.NoExtraArguments, RunE: func(cmd *cobra.Command, _ []string) error {
			if action != "close" {
				sources := 0
				for _, selected := range []bool{dir != "", imageOnly, fromPublication} {
					if selected {
						sources++
					}
				}
				if sources != 1 {
					if full {
						return errors.New("укажите ровно один источник модели: --manifest-dir, --image-only или --publication")
					}
					return errors.New("укажите ровно один источник модели: --manifest-dir или --image-only")
				}
			}
			if action == "bootstrap" && strings.TrimSpace(runtimeRole) == "" {
				return errors.New("укажите --runtime-role существующего обычного LOGIN")
			}
			var manifests []*manifest.Manifest
			if dir != "" {
				delivery, err := manifest.LoadDelivered(dir)
				if err != nil {
					return err
				}
				manifests = delivery.Manifests
			}
			var source string
			var report modelcompose.Report
			if !fromPublication {
				var err error
				source, report, err = modelcompose.Compose(authzmodel.DSL, manifests)
				if err != nil {
					return err
				}
			}
			dsn, err := validatedMigrationDSN(opts)
			if err != nil {
				return err
			}
			ctx, cancel := context.WithTimeout(cmd.Context(), 30*time.Second)
			defer cancel()
			pool, err := pgxpool.New(ctx, dsn)
			if err != nil {
				return err
			}
			defer pool.Close()
			repository := kanamepg.New(pool, nil)
			if action == "close" {
				if err = repository.CloseAuthorityBundle(ctx); err != nil {
					return err
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(map[string]string{"action": action})
			}
			catalogReader := kanamepg.NewCatalogRepo(pool)
			if fromPublication {
				return publishedAuthorityAction(ctx, cmd, action, repository, catalogReader)
			}
			if action == "bootstrap" {
				if err := repository.ValidateMetadataBootstrapRuntime(ctx, runtimeRole); err != nil {
					return err
				}
				uninitialized, err := repository.MetadataAuthorityUninitialized(ctx)
				if err != nil {
					return err
				}
				if uninitialized {
					// Предварительное чтение не разрешает запись: адаптер заново
					// проверяет uninitialized под замками каждой транзакции каталога.
					applier := modulecatalog.NewApplier(kanamepg.NewMetadataBootstrapCatalogRepo(pool))
					census, err := applier.ApplyAll(ctx, manifests)
					if err != nil {
						return err
					}
					if len(census.SkippedStale) != 0 || len(census.RefusedConflict) != 0 {
						return kaname.ErrSemanticIdentityUnavailable
					}
				}
			}
			rows, err := catalogReader.ReadCatalogHalves(ctx)
			if err != nil {
				return err
			}
			bundle, editions, err := authorityDeliveredBundle(ctx, source, report.KeyTerms, manifests, rows)
			if err != nil {
				return err
			}
			switch action {
			case "bootstrap":
				// Установленный handoff не изменяем каталогом выше. Репозиторий
				// под drain доказывает первый stage либо точный готовый no-op;
				// transition, смена identity и активация сюда не входят.
				var bootstrapped bool
				bootstrapped, err = repository.BootstrapMetadataAuthority(ctx, bundle, runtimeRole, editions...)
				if err != nil {
					return err
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
					Action       string                 `json:"action"`
					Identity     grantcoverage.Identity `json:"identity"`
					Bootstrapped bool                   `json:"bootstrapped"`
				}{action, bundle.Identity(), bootstrapped})
			case "stage":
				err = repository.StageAuthorityBundle(ctx, bundle, editions...)
			case "activate":
				err = repository.ActivateAuthorityBundle(ctx, bundle, editions...)
			case "stage-full":
				err = repository.StageFullAuthorityBundle(ctx, bundle, editions...)
			case "activate-full":
				err = repository.ActivateFullAuthorityBundle(ctx, bundle, editions...)
			case "verify-full":
				err = repository.ValidateFullAuthorityBundle(ctx, bundle)
			case "verify":
				var handed *granteffect.Bundle
				handed, err = repository.LoadAuthorityBundle(ctx, source, report.KeyTerms...)
				if err == nil && handed.Identity() != bundle.Identity() {
					err = kaname.ErrSemanticIdentityUnavailable
				}
			}
			if err != nil {
				return err
			}
			// Только идентичность и завершённое действие: это не Ready/полная DoD.
			return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
				Action   string `json:"action"`
				Identity any    `json:"identity"`
			}{action, bundle.Identity()})
		}}
		if action != "close" {
			cmd.Flags().StringVar(&dir, "manifest-dir", "", "Каталог фактически доставленных манифестов")
			cmd.Flags().BoolVar(&imageOnly, "image-only", false, "Явно использовать только канон образа")
		}
		if full {
			cmd.Flags().BoolVar(&fromPublication, "publication", false, "Использовать головную редакцию из журнала публикаций PostgreSQL")
		}
		if action == "bootstrap" {
			cmd.Flags().StringVar(&runtimeRole, "runtime-role", "", "Существующий обычный LOGIN службы; роль и пароль не создаются")
		}
		root.AddCommand(cmd)
	}
	root.AddCommand(newFollowPublicationsCmd(opts))
	root.AddCommand(newBootstrapPublicationCmd(opts))
	return root
}

func publishedAuthorityAction(ctx context.Context, cmd *cobra.Command, action string, repo *kanamepg.Repository, catalogReader *kanamepg.CatalogRepo) error {
	publication, err := repo.LoadPublicationAuthorityBundle(ctx)
	if err != nil {
		return err
	}
	identity := publication.Bundle.Identity()
	switch action {
	case "stage-full":
		err = repo.StageFullPublicationAuthorityBundle(ctx, publication)
	case "activate-full":
		err = repo.ActivateFullPublicationAuthorityBundle(ctx, publication)
	case "verify-full":
		active, loadErr := catalogReader.LoadActivePublication(ctx)
		if loadErr != nil {
			return loadErr
		}
		if active.Revision != publication.Revision || active.Digest != publication.Digest || active.CatalogID != identity.CatalogID {
			return kaname.ErrSemanticIdentityUnavailable
		}
	default:
		return errors.New("источник --publication доступен только для действий с FULL-контрактом")
	}
	if err != nil {
		return err
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
		Action   string `json:"action"`
		Revision int64  `json:"revision"`
		Digest   string `json:"digest"`
		Identity any    `json:"identity"`
	}{action, publication.Revision, publication.Digest, identity})
}

type authorityCatalogHalves struct{ catalog.Halves }

func (s authorityCatalogHalves) ReadLiveCatalog(context.Context) (catalog.Rows, error) {
	return s.Live, nil
}
func (s authorityCatalogHalves) ReadRetiredCatalog(context.Context) (catalog.Rows, error) {
	return s.Retired, nil
}

// Модель проходит ту же композицию/admission, каталог — тот же паритет,
// что production startup. Репозиторий повторно сравнит actual bytes после drain.
func authorityDeliveredBundle(ctx context.Context, source string, keys []authzmodel.KeyTerm, manifests []*manifest.Manifest, rows catalog.Halves) (*granteffect.Bundle, []kaname.AuthorityModuleEdition, error) {
	bundle, err := granteffect.NewBundle(ctx, source, rows, granteffect.ProjectorVersion, keys...)
	if err != nil {
		return nil, nil, err
	}
	anchor, err := modulecatalog.AnchorOfDelivery(manifests)
	if err != nil {
		return nil, nil, err
	}
	if _, err = seed.AssertCatalogParity(ctx, authorityCatalogHalves{rows}, anchor); err != nil {
		return nil, nil, err
	}
	editions := make([]kaname.AuthorityModuleEdition, 0, len(manifests))
	for _, m := range manifests {
		pin := kaname.AuthorityModuleEdition{Module: m.Module}
		if edition := modulecatalog.DeclaredEdition(m); edition != nil {
			pin.Revision = edition.Revision
			pin.Digest = edition.Digest
		}
		editions = append(editions, pin)
	}
	return bundle, editions, nil
}

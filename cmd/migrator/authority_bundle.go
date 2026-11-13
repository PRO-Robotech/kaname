// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/PRO-Robotech/corelib/migratorcli"
	"github.com/PRO-Robotech/corelib/migratorcli/cobraargs"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/catalog"
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
	for _, action := range []string{"stage", "activate", "verify", "close"} {
		action := action
		var dir string
		var imageOnly bool
		cmd := &cobra.Command{Use: action, Args: cobraargs.NoExtraArguments, RunE: func(cmd *cobra.Command, _ []string) error {
			if action != "close" && ((dir == "") == !imageOnly) {
				return errors.New("укажите ровно один источник модели: --manifest-dir или --image-only")
			}
			var manifests []*manifest.Manifest
			if action != "close" && !imageOnly {
				delivery, err := manifest.LoadDelivered(dir)
				if err != nil {
					return err
				}
				manifests = delivery.Manifests
			}
			source, report, err := modelcompose.Compose(authzmodel.DSL, manifests)
			if err != nil {
				return err
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
			rows, err := kanamepg.NewCatalogRepo(pool).ReadCatalogHalves(ctx)
			if err != nil {
				return err
			}
			bundle, editions, err := authorityDeliveredBundle(ctx, source, report.KeyTerms, manifests, rows)
			if err != nil {
				return err
			}
			switch action {
			case "stage":
				err = repository.StageAuthorityBundle(ctx, bundle, editions...)
			case "activate":
				err = repository.ActivateAuthorityBundle(ctx, bundle, editions...)
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
		root.AddCommand(cmd)
	}
	return root
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

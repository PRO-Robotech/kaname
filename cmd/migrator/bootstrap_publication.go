// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/PRO-Robotech/corelib/migratorcli/cobraargs"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

func newBootstrapPublicationCmd(opts *rootOptions) *cobra.Command {
	var dir string
	var imageOnly bool
	cmd := &cobra.Command{
		Use:   "bootstrap-publication",
		Short: "Зафиксировать и активировать первую редакцию установленного каталога",
		Args:  cobraargs.NoExtraArguments,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if (dir != "") == imageOnly {
				return errors.New("укажите ровно один источник первой редакции: --manifest-dir или --image-only")
			}
			return bootstrapPublication(cmd, opts, dir)
		},
	}
	cmd.Flags().StringVar(&dir, "manifest-dir", "", "Каталог фактически применённых манифестов")
	cmd.Flags().BoolVar(&imageOnly, "image-only", false, "Использовать установленный канон образа")
	return cmd
}

func bootstrapPublication(cmd *cobra.Command, opts *rootOptions, dir string) error {
	var manifests []*manifest.Manifest
	var parts []modulecatalog.PublishedPart
	if dir != "" {
		delivery, err := manifest.LoadDeliveredDocuments(dir)
		if err != nil {
			return err
		}
		manifests = make([]*manifest.Manifest, 0, len(delivery))
		parts = make([]modulecatalog.PublishedPart, 0, len(delivery))
		for _, doc := range delivery {
			part, err := modulecatalog.NewBaselinePublishedPart(doc.Manifest.Module, doc.Bytes)
			if err != nil {
				return fmt.Errorf("подготовить манифест %s: %w", doc.Path, err)
			}
			manifests = append(manifests, doc.Manifest)
			parts = append(parts, part)
		}
	}
	model, report, err := modelcompose.Compose(authzmodel.DSL, manifests)
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
	rows, err := kanamepg.NewCatalogRepo(pool).ReadCatalogHalves(ctx)
	if err != nil {
		return err
	}
	bundle, _, err := authorityDeliveredBundle(ctx, model, report.KeyTerms, manifests, rows)
	if err != nil {
		return err
	}
	publication, err := kanamepg.New(pool, nil).BootstrapCatalogPublication(ctx, bundle, parts)
	if err != nil {
		return err
	}
	return json.NewEncoder(cmd.OutOrStdout()).Encode(struct {
		Action    string `json:"action"`
		Revision  int64  `json:"revision"`
		Digest    string `json:"digest"`
		CatalogID string `json:"catalog_id"`
	}{"bootstrap-publication", publication.Revision, publication.Digest, publication.CatalogID})
}

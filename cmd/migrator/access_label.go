// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/PRO-Robotech/corelib/migratorcli/cobraargs"
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	kanamepg "github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/spf13/cobra"
)

func newAddAccessLabelCmd(opts *rootOptions) *cobra.Command {
	var declaration kanamepg.AccessLabelDeclaration
	cmd := &cobra.Command{
		Use:   "add-access-label",
		Short: "Объявить ключ защищённой метки и добавить допустимые значения от имени владельца миграций",
		Example: "kaname-migrator authority-bundle add-access-label --account ACCOUNT_ID --project PROJECT_ID " +
			"--module vpc --resource network --key team --value blue --value green",
		Args: cobraargs.NoExtraArguments,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if cmd.Flags().Changed("project") && declaration.Project == "" {
				return errors.New("передан пустой идентификатор проекта")
			}
			dsn, err := validatedMigrationDSN(opts)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			pool, err := pgxpool.New(ctx, dsn)
			if err != nil {
				return err
			}
			defer pool.Close()
			result, err := kanamepg.New(pool, nil).AddAccessLabelValues(ctx, declaration)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(result)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&declaration.Account, "account", "", "Аккаунт, которому принадлежит определение или указанный проект")
	flags.StringVar(&declaration.Project, "project", "", "Проект внутри аккаунта; при пропуске ключ объявляется в аккаунте")
	flags.StringVar(&declaration.Module, "module", "", "Модуль из действующего каталога")
	flags.StringVar(&declaration.Resource, "resource", "", "Имя ресурса в модуле")
	flags.StringVar(&declaration.Key, "key", "", "Ключ защищённой метки")
	flags.StringArrayVar(&declaration.Values, "value", nil, "Допустимое значение; флаг можно повторить, существующие значения сохраняются")
	return cmd
}

func newIssueInitialAccessLabelApplyCmd(opts *rootOptions) *cobra.Command {
	var initial kanamepg.InitialAccessLabelApply
	var dir, definitionID string
	var imageOnly, fromPublication bool
	cmd := &cobra.Command{
		Use:   "issue-initial-access-label-apply",
		Short: "Выдать владельцу аккаунта первое отзывное полномочие на одно определение accessLabels",
		Args:  cobraargs.NoExtraArguments,
		RunE: func(cmd *cobra.Command, _ []string) error {
			sources := 0
			for _, selected := range []bool{dir != "", imageOnly, fromPublication} {
				if selected {
					sources++
				}
			}
			if sources != 1 {
				return errors.New("укажите ровно один источник модели: --manifest-dir, --image-only или --publication")
			}
			if cmd.Flags().Changed("project") && initial.Project == "" {
				return errors.New("передан пустой идентификатор проекта")
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
			repo := kanamepg.New(pool, nil)
			initial.DefinitionID = domain.AccessLabelDefinitionID(definitionID)
			if fromPublication {
				publication, err := repo.LoadPublicationAuthorityBundle(ctx)
				if err != nil {
					return err
				}
				issued, err := repo.IssueInitialPublishedAccessLabelApply(ctx, initial, publication)
				if err != nil {
					return err
				}
				return json.NewEncoder(cmd.OutOrStdout()).Encode(issued)
			}
			rows, err := kanamepg.NewCatalogRepo(pool).ReadCatalogHalves(ctx)
			if err != nil {
				return err
			}
			bundle, _, err := authorityDeliveredBundle(ctx, source, report.KeyTerms, manifests, rows)
			if err != nil {
				return err
			}
			issued, err := repo.IssueInitialAccessLabelApply(ctx, initial, bundle)
			if err != nil {
				return err
			}
			return json.NewEncoder(cmd.OutOrStdout()).Encode(issued)
		},
	}
	flags := cmd.Flags()
	flags.StringVar(&dir, "manifest-dir", "", "Каталог фактически доставленных манифестов")
	flags.BoolVar(&imageOnly, "image-only", false, "Явно использовать только канон образа")
	flags.BoolVar(&fromPublication, "publication", false, "Использовать активную редакцию журнала публикаций PostgreSQL")
	flags.StringVar(&initial.Account, "account", "", "Аккаунт владельца и определения")
	flags.StringVar(&initial.Project, "project", "", "Проект определения внутри аккаунта")
	flags.StringVar(&definitionID, "definition", "", "UUID уже объявленного определения")
	flags.Int64Var(&initial.ExpectedRevision, "expected-revision", 0, "Ожидаемая редакция определения")
	_ = cmd.MarkFlagRequired("account")
	_ = cmd.MarkFlagRequired("definition")
	_ = cmd.MarkFlagRequired("expected-revision")
	return cmd
}

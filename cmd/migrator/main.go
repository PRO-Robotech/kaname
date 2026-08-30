// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package main — отдельный binary `kacho-migrator`: единая точка сборки CLI
// миграций (cmd-binary не смешивает обязанности). Обслуживает миграции БД
// сервиса kacho-iam (схема `kacho_iam`).
//
// API совпадает с goose-flavour:
//
//	kacho-migrator up [--target <version>]
//	kacho-migrator down [--target <version>]
//	kacho-migrator status
//
// # Глагола `create` здесь НЕТ — и это решение, а не пропуск (#566)
//
// Он был и выдавал `goose.Create` без `SetSequential`. Имя миграции в этом
// дереве пишет АВТОР: форма номера — решение, а инструмент принял бы его молча
// и всегда одинаково.
//
// Действующая форма — метка времени заведения `YYYYMMDDHHMMSS_<что_делает>.sql`
// (`date -u +%Y%m%d%H%M%S`). Объявлена она в ОДНОМ месте и здесь НЕ
// переписывается: docs/architecture/migration-version-namespace.md. Своей
// редакции у справки быть не должно — две редакции об одном предмете расходятся
// молча, и расходились (#1026).
//
// Флаги верхнего уровня:
//
//	--dialect postgres                    (default; единственный поддерживаемый)
//	--dsn     <connection-string>         (или ENV KACHO_MIGRATOR_DSN)
//
// Если --dsn пуст и KACHO_MIGRATOR_DSN пуст — читаем `config.Load()` (viper)
// и берем `cfg.MigrateDSN()`. Это позволяет одному helm-values задавать
// БД-параметры для обоих binary, не дублируя DSN.
package main

import (
	"fmt"
	"io/fs"
	"os"
	"strings"

	_ "github.com/jackc/pgx/v5/stdlib" // регистрирует "pgx" driver для sql.Open
	"github.com/spf13/cobra"

	"github.com/PRO-Robotech/kacho/pkg/migratorcli"
	"github.com/PRO-Robotech/kacho/pkg/migratorcli/cobraargs"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/migrator"
	"github.com/PRO-Robotech/kacho/services/iam/internal/migrations"
)

const (
	defaultDialect       = "postgres"
	defaultMigrationsDir = "."
	// envDSN — имя переменной окружения второго приоритета. НЕ литерал: оно же
	// печатается в тексте отказа предусловий через общий пакет, и два места об
	// одном имени разошлись бы молча — оператор прочитал бы в подсказке одно, а
	// сервис читал бы другое (#1383).
	envDSN = migratorcli.EnvDSN
)

// rootOptions — shared параметры всех subcommand'ов, накапливаются persistent-флагами.
type rootOptions struct {
	dialect string
	dsn     string
}

func main() {
	if err := newRootCmd(migrations.FS).Execute(); err != nil {
		os.Exit(1)
	}
}

// newRootCmd собирает дерево команд. Вынесено в отдельный конструктор, чтобы
// тесты могли инстанцировать и парсить args без os.Exit.
// migrationsFS принимается параметром: в production — `internal/migrations.FS`,
// в тестах — пустая `fstest.MapFS{}`.
func newRootCmd(migrationsFS fs.FS) *cobra.Command {
	opts := &rootOptions{}

	root := &cobra.Command{
		Use:   "kacho-migrator",
		Short: "Database migrations runner for kacho-iam",
		Long: "kacho-migrator — отдельный CLI для управления миграциями БД сервиса kacho-iam.\n" +
			"Одна точка сборки на use-case (cmd-binary не смешивает обязанности).\n\n" +
			"Новая миграция заводится РУКОЙ: internal/migrations/YYYYMMDDHHMMSS_<что>.sql\n" +
			"(метка времени заведения: date -u +%Y%m%d%H%M%S).\n" +
			"Подробности — docs/architecture/migration-version-namespace.md.",
		SilenceUsage: true,
		// Пустая командная строка — ОТКАЗ, а не успех (#1461). Cobra при корне без
		// исполнения печатает помощь и выходит успехом; прямая форма отвечает
		// отказом. Скрипт или init-контейнер, потерявший аргумент, объявлялся бы
		// выполнившим накат — успех на невыполненной работе.
		//
		// Отказ по неизвестной подкоманде производит общий пакет — тем же текстом,
		// что и прямая форма, и с перечнем известных подкоманд.
		Args: cobraargs.OnlyKnownCommands,
		RunE: func(cmd *cobra.Command, args []string) error {
			_ = cmd.Help()
			// Сентинел общий: своя редакция того же текста разошлась бы молча.
			return migratorcli.ErrNoCommand
		},
	}
	root.PersistentFlags().StringVar(&opts.dialect, "dialect", defaultDialect,
		"SQL dialect (postgres)")
	root.PersistentFlags().StringVar(&opts.dsn, "dsn", "",
		"database DSN; if empty — read ENV "+envDSN+", then fall back to kacho-iam config (viper)")

	root.AddCommand(
		newUpCmd(opts, migrationsFS),
		newDownCmd(opts, migrationsFS),
		newStatusCmd(opts, migrationsFS),
	)
	// Дополнения оболочки cobra доводит сама; у прямой формы такой команды нет и
	// не будет. Перечень команд читает оператор — значит он тоже поверхность.
	cobraargs.HideShellCompletion(root)
	return root
}

func newUpCmd(opts *rootOptions, migrationsFS fs.FS) *cobra.Command {
	var target string
	cmd := &cobra.Command{
		Use: "up",
		// Лишний позиционный аргумент — отказ, а не молчаливый накат: у cobra
		// умолчание Args принимает произвольные, и `up 800001` (догадка о том, как
		// задать цель) уезжал накатывать до головы. Версия задаётся --target (#1461).
		// Текст отказа производит общий пакет — один на семь.
		Args:  cobraargs.NoExtraArguments,
		Short: "Apply migrations up to latest (or --target version)",
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := buildRunner(opts, migrationsFS)
			if err != nil {
				return err
			}
			return r.Up(target)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "stop at this version (inclusive); default — latest")
	return cmd
}

func newDownCmd(opts *rootOptions, migrationsFS fs.FS) *cobra.Command {
	var target string
	cmd := &cobra.Command{
		Use: "down",
		// Лишний позиционный аргумент — отказ, а не молчаливый накат: у cobra
		// умолчание Args принимает произвольные, и `up 800001` (догадка о том, как
		// задать цель) уезжал накатывать до головы. Версия задаётся --target (#1461).
		// Текст отказа производит общий пакет — один на семь.
		Args:  cobraargs.NoExtraArguments,
		Short: "Rollback the most recent migration (or down to --target)",
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := buildRunner(opts, migrationsFS)
			if err != nil {
				return err
			}
			return r.Down(target)
		},
	}
	cmd.Flags().StringVar(&target, "target", "", "rollback down to this version (inclusive); default — one step back")
	return cmd
}

func newStatusCmd(opts *rootOptions, migrationsFS fs.FS) *cobra.Command {
	return &cobra.Command{
		Use: "status",
		// Лишний позиционный аргумент — отказ, а не молчаливый накат: у cobra
		// умолчание Args принимает произвольные, и `up 800001` (догадка о том, как
		// задать цель) уезжал накатывать до головы. Версия задаётся --target (#1461).
		// Текст отказа производит общий пакет — один на семь.
		Args:  cobraargs.NoExtraArguments,
		Short: "Show migration status (applied / pending)",
		RunE: func(cmd *cobra.Command, args []string) error {
			r, err := buildRunner(opts, migrationsFS)
			if err != nil {
				return err
			}
			return r.Status(cmd.OutOrStdout())
		},
	}
}

// buildRunner собирает migrator.Runner из persistent-флагов + ENV + config-fallback.
//
// Источник DSN — приоритет: --dsn flag > ENV KACHO_MIGRATOR_DSN > viper-config
// (config.Load → cfg.MigrateDSN). Так одно helm-values покрывает оба binary, и
// можно явно перекрыть `--dsn` для cross-DB-инструментов и ad-hoc запусков.
func buildRunner(opts *rootOptions, migrationsFS fs.FS) (*migrator.Runner, error) {
	dialect, err := migrator.NewDialect(opts.dialect)
	if err != nil {
		return nil, err
	}

	dsn := strings.TrimSpace(opts.dsn)
	if dsn == "" {
		dsn = strings.TrimSpace(os.Getenv(envDSN))
	}
	if dsn == "" {
		// Fallback к kacho-iam viper-config: тот же DB_HOST/PORT/USER/PASSWORD/NAME/SSLMODE.
		// Если KACHO_IAM_DB_PASSWORD не выставлен — config.Load() Validate провалится
		// (что и есть желаемое UX — явное «set DSN или iam-creds», а не silent default).
		cfg, cerr := config.Load(os.Getenv("KACHO_IAM_CONFIG_PATH"))
		if cerr != nil {
			return nil, fmt.Errorf("dsn unset (--dsn / %s) and iam config load failed: %w", envDSN, cerr)
		}
		dsn = cfg.MigrateDSN()
	}

	return migrator.New(migrator.Config{
		Service:       "iam",
		Dialect:       dialect,
		DSN:           dsn,
		FS:            migrationsFS,
		MigrationsDir: defaultMigrationsDir,
	})
}

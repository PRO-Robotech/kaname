// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
// Приоритет источников DSN — один на семь точек наката и объявлен в общем пакете
// (`pkg/migratorcli.ResolveDSN`): --dsn > ENV KACHO_MIGRATOR_DSN > конфигурация
// сервиса. Запасная конфигурация здесь — `config.Load()` (viper), из неё берётся
// `cfg.MigrateDSN()`: одно helm-values задаёт БД-параметры обоим binary, не
// дублируя DSN. Своей редакции порядка тут быть не должно — две редакции об одном
// предмете расходятся молча, и разошлись: тексты отказа у iam, vpc и общего
// пакета называли РАЗНЫЕ подмножества собственных источников (#1544).
package main

import (
	"fmt"
	"io/fs"
	"os"

	_ "github.com/jackc/pgx/v5/stdlib" // регистрирует "pgx" driver для sql.Open
	"github.com/spf13/cobra"

	"github.com/PRO-Robotech/kacho/pkg/migratorcli"
	"github.com/PRO-Robotech/kacho/pkg/migratorcli/cobraargs"
	"github.com/PRO-Robotech/kacho/pkg/migratorrun"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
	"github.com/PRO-Robotech/kacho-iam/internal/migrations"
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

// serviceName — чью цепочку применяет эта точка наката. Живой счёт строк перед
// сносом называет им то, что стережёт, поэтому безымянной точки наката не
// бывает: предусловия отказывают ей в старте.
const serviceName = "iam"

// dsnExtraSources — чем ЭТА служба заполняет DSN СВЕРХ двух общих (`--dsn` и
// KACHO_MIGRATOR_DSN), в порядке убывания приоритета. Два общих здесь НЕ
// перечисляются намеренно: их печатает сам общий пакет, поэтому умолчать
// источник, который перебивает названные, нельзя by construction. Ровно это и
// случилось однажды — текст отказа называл третий источник и умалчивал второй.
var dsnExtraSources = []string{"kacho-iam config (KACHO_IAM_CONFIG_PATH)"}

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
			return r.Up(cmd.Context(), target)
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
			return r.Down(cmd.Context(), target)
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
			return r.Status(cmd.Context(), cmd.OutOrStdout())
		},
	}
}

// buildRunner собирает накат из persistent-флагов + ENV + config-fallback.
//
// Приоритет DSN живёт в общем пакете (`migratorcli.ResolveDSN`), а не здесь:
// --dsn > ENV KACHO_MIGRATOR_DSN > конфигурация сервиса. Сюда принадлежит только
// то, чем СВОЯ конфигурация читается, — имя переменной пути и способ достать из
// неё строку подключения; общий пакет не вправе называть оператору чужое имя.
func buildRunner(opts *rootOptions, migrationsFS fs.FS) (*migratorrun.Runner, error) {
	// ДИАЛЕКТ СВЕРЯЕТСЯ ПЕРВЫМ, и это порядок, а не стиль. Общий накат сверяет
	// его тоже — но уже приняв DSN, а до DSN лежит загрузка конфигурации службы.
	// Оператор, назвавший несуществующий диалект, получал бы тогда отказ
	// КОНФИГУРАЦИИ: длинный, про совсем другое и не называющий причины, по
	// которой запуск отвергнут. У прямой четвёрки этот порядок держит сам разбор
	// (migratorcli.Parse отвергает диалект до всего прочего); cobra такой
	// проверки не делает, поэтому здесь она стоит явно. Функция та же — двух
	// редакций одного текста не заводится.
	if _, err := migratorcli.ResolveDialectSpec(opts.dialect); err != nil {
		return nil, err
	}

	// Запасная конфигурация iam — тот же DB_HOST/PORT/USER/PASSWORD/NAME/SSLMODE,
	// что и у kacho-iam.
	//
	// ЗДЕСЬ СТОЯЛО «config.Load проваливает Validate» — это неверно, и неверно
	// было всё время. `config.Load` стража НЕ зовёт: его шапка прямо говорит, что
	// `Validate()` зовёт вызывающий, а вызывающий здесь — эта функция, и до
	// правки она его не звала. То есть комментарий обещал проверку, которой на
	// этом пути не существовало, а поставка ставит эту точку ПЕРВОЙ.
	//
	// Полного стража здесь по-прежнему нет, и это решение: в боевом режиме он
	// требует секретов поставщика личности, которых init-контейнер не несёт и
	// нести не должен. Судится ровно употребляемая величина — строка подключения,
	// ниже по тексту.
	dsn, err := migratorcli.ResolveDSN(opts.dsn, func() (string, error) {
		cfg, cerr := config.Load(os.Getenv("KACHO_IAM_CONFIG_PATH"))
		if cerr != nil {
			return "", cerr
		}
		return cfg.MigrateDSN(), nil
	})
	if err != nil {
		return nil, err
	}

	// АДРЕС БАЗЫ ОБЯЗАН НАЗЫВАТЬ ХОСТ — иначе ожидание её не сойдётся НИКОГДА.
	//
	// В поставке эта точка исполняется ПЕРВОЙ (init-контейнер чарта перед
	// службой), поэтому неверная настройка оператора разбивается о неё, а не о
	// стража службы. До этой проверки она адрес не судила вовсе: накат уходил
	// ждать базу по адресу без хоста и оставался в `running` с НУЛЁМ байт
	// журнала — оператор видел под в `Init:0/1` и ни одного слова о причине.
	//
	// Ожидание базы само по себе законно: она поднимается рядом и может быть не
	// готова. Незаконно НЕ РАЗЛИЧАТЬ «ещё не поднялась» (сходится само) и «адрес
	// не задан» (не сойдётся никогда).
	//
	// Проверка стоит ПОСЛЕ разрешения приоритета источников, поэтому покрывает
	// все три (`--dsn`, переменная окружения, конфигурация службы) и не заводит
	// четвёртого места, где порядок пришлось бы повторить. Предикат — ТОТ ЖЕ, что
	// зовёт страж службы: своя редакция разошлась бы молча.
	//
	// Полного `Config.Validate` здесь нет намеренно: в боевом режиме он требует
	// секретов поставщика личности, которых init-контейнер не несёт и нести не
	// должен — накат их не употребляет. Позвав его, мы уронили бы ШТАТНУЮ
	// установку.
	if !config.DSNNamesAHost(dsn) {
		return nil, fmt.Errorf("database address %q names no host: it is not set, and waiting for "+
			"the database would never converge; set --dsn, ENV %s, or the chart's db.host", config.RedactDSN(dsn), envDSN)
	}

	return migratorrun.New(migratorrun.Config{
		Service:         serviceName,
		Dialect:         opts.dialect,
		DSN:             dsn,
		FS:              migrationsFS,
		MigrationsDir:   defaultMigrationsDir,
		DSNExtraSources: dsnExtraSources,
	})
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package migrator — обертка над goose, которую дергает cmd/migrator/main.go.
//
// Embed FS (`internal/migrations/*.sql`) принимается параметром Config.FS,
// чтобы runner не тянул прямой импорт `internal/migrations` (зависимость
// одно-направленная: cmd/migrator → internal/apps/migrator + internal/migrations,
// `internal/apps/migrator` ни к чему iam-specific не привязан).
package migrator

import (
	"context"
	"io"
	"io/fs"
	"os"

	"github.com/PRO-Robotech/kacho/internal/dropguard"
	"github.com/PRO-Robotech/kacho/pkg/migratorcli"
)

// Config — параметры одного запуска runner'а.
type Config struct {
	// Service — имя сервиса, чью цепочку применяет этот runner. Обязательное:
	// без него живой счёт строк перед сносом не может назвать, что он стережёт,
	// а безымянный отказ в логе init-контейнера некому адресовать.
	Service       string
	Dialect       *Dialect
	DSN           string
	FS            fs.FS
	MigrationsDir string
}

// dsnExtraSources — чем ЭТОТ сервис заполняет DSN СВЕРХ двух общих (`--dsn` и
// [migratorcli.EnvDSN]), в порядке убывания приоритета. Два общих здесь НЕ
// перечисляются намеренно: их печатает сам пакет, поэтому умолчать источник,
// который перебивает названные, нельзя by construction. Ровно это и случилось
// однажды — текст отказа называл третий источник и умалчивал второй (#1383).
var dsnExtraSources = []string{"kacho-iam config (KACHO_IAM_CONFIG_PATH)"}

// Validate проверяет минимально необходимые поля перед обращением к диалекту.
//
// Проверки, их ПОРЯДОК и тексты отказа объявлены ОДИН раз на дерево —
// [migratorcli.RunnerPreconditions] (#1383). Здесь остаётся только сведение
// своего типа диалекта к двум значениям, которые общий предикат понимает:
// задан ли диалект и как называется его spec. Тип диалекта у сервисов разный, и
// его сведение ждёт своих проб (`docs/architecture/migrator-form.md`).
func (c Config) Validate() error {
	// Spec() читается ТОЛЬКО у заданного диалекта: на незаданном это
	// разыменование nil. Порядок проверок внутри общего предиката тот же и
	// закреплён его пробой.
	specName := ""
	if c.Dialect != nil {
		specName = c.Dialect.Spec().Name
	}
	return migratorcli.RunnerPreconditions{
		Service:         c.Service,
		DialectSet:      c.Dialect != nil,
		DialectSpecName: specName,
		DSN:             c.DSN,
		DSNExtraSources: dsnExtraSources,
		MigrationsFSSet: c.FS != nil,
		MigrationsDir:   c.MigrationsDir,
	}.Validate()
}

// Runner — высокоуровневая обертка над [Dialect].
type Runner struct {
	cfg Config
}

// New собирает Runner; cfg валидируется здесь же.
func New(cfg Config) (*Runner, error) {
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return &Runner{cfg: cfg}, nil
}

// Up прогоняет миграции вверх — сперва СОСЧИТАВ строки в таблицах, которые уронят
// ещё не применённые миграции В ПРЕДЕЛАХ ЭТОГО ПРОГОНА (см. preflightDrops), и
// лишь затем делегируя в Dialect-impl. Ненулевой счёт прекращает применение.
func (r *Runner) Up(target string) error {
	ctx := context.Background()
	// ГРАНИЦА ПРОГОНА разбирается ЗДЕСЬ, до счёта: страж обязан считать ровно те
	// сносы, которые этот прогон ВЫПОЛНИТ, а не все ещё не применённые. Прежде он
	// считал все, и прицельный прогон мог быть отвергнут из-за сноса, которого он
	// не сделает (#1487).
	//
	// Разбор — та же функция, которой читает цель диалект, поэтому двух редакций
	// одного числа завестись не может; заодно негодная цель отвергается до
	// соединения с базой, а не после него.
	//
	// Пустая цель даёт НУЛЕВОЕ значение dropguard.Target, то есть «считать всё».
	// Способа обойти счёт целиком у цели нет by construction: суженная цель сужает
	// ровно настолько же и применяемое.
	scope := dropguard.WholeChain()
	if target != "" {
		version, err := migratorcli.ParseTargetVersion(target)
		if err != nil {
			return err
		}
		scope = dropguard.UpTo(version)
	}
	// СЧЁТ ПЕРЕД СНОСОМ — здесь, а не в вызывающем, и это единственное место.
	// Шаг, который зовут отдельной строкой, однажды не позовут; отсюда его не
	// обойти, не обойдя сам Up. Ненулевой счёт возвращает ошибку — миграции не
	// применяются вовсе.
	if err := r.preflightDrops(ctx, scope); err != nil {
		return err
	}
	return r.cfg.Dialect.Up(ctx, r.cfg.DSN, r.cfg.FS, r.cfg.MigrationsDir, target)
}

// preflightDrops считает на ЖИВОЙ базе строки в каждой таблице, которую уронит
// ещё не применённая миграция В ПРЕДЕЛАХ scope — границы, до которой этот прогон
// доедет. Незаданная граница (нулевое значение) означает «считать всё».
//
// Измеряющий гейт в internal/migrations отвечает на другой вопрос — сколько сеет
// наша собственная цепочка, проигранная в пустую базу. Что записал арендатор, не
// знает ни один контейнер; узнать это можно только здесь и только сейчас, пока
// строки ещё существуют.
//
// Соединение своё и закрывается сразу: держать его до конца применения незачем, а
// dbready внутри openPgxDB заодно даёт барьер готовности до первого вопроса.
func (r *Runner) preflightDrops(ctx context.Context, scope dropguard.Target) error {
	db, err := openPgxDB(ctx, r.cfg.DSN, r.cfg.Dialect.Spec())
	if err != nil {
		return err
	}
	defer func() { _ = db.Close() }()
	return dropguard.Gate(ctx, db, r.cfg.Service, r.cfg.FS, os.Stderr, scope)
}

// Down откатывает миграции. Делегирует в Dialect-impl.
func (r *Runner) Down(target string) error {
	return r.cfg.Dialect.Down(context.Background(), r.cfg.DSN, r.cfg.FS, r.cfg.MigrationsDir, target)
}

// Status печатает примененные/непримененные миграции.
func (r *Runner) Status(out io.Writer) error {
	return r.cfg.Dialect.Status(context.Background(), r.cfg.DSN, r.cfg.FS, r.cfg.MigrationsDir, out)
}

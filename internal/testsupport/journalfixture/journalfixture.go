// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package journalfixture — инициатор журнала у ПОСЕВА проб.
//
// Отдельный пакет, а не файл `iampgtest`: тот импортирует репозиторий `pg`, и
// внутренние пробы пакетов, которые `pg` импортирует сам, получили бы цикл.
//
// # Зачем
//
// Строка ресурсного журнала без инициатора базой не принимается (NTF-3, Р2;
// `20261004160000_resource_journal_carries_the_initiator.sql`), а сотни проб
// заводят предусловие прямой вставкой в журналируемые таблицы — пользователя,
// аккаунт, привязку. Посев — не изменение, начатое субъектом; у него своя
// личность компонента, `system:kaname-fixture`, и база получает её настройкой
// РОЛИ контейнера проб: каждое соединение начинается с ней.
//
// # Почему это не маскирует продукт
//
// Пишущую транзакцию службы открывает только `journalwrite.Begin`, и он ПЕРВЫМ
// оператором выставляет инициатора локально к транзакции — значение принципала
// либо пустое при его отсутствии. Локальная настройка перекрывает ролевую,
// поэтому продукт ролевой не наследует: его запись без принципала отвергается
// базой и на контейнере проб. Держат это:
//
//   - `internal/journalwrite` `TestWriteOpener_InitiatorIsStatedLocallyInBothOutcomes`
//     — на соединении С ролевой настройкой транзакция продукта без принципала
//     её не наследует и отвергнута `23502`;
//   - гейт `internal/check` `TestWriteTransactionsOpenThroughTheJournalOpener` —
//     открытия пишущей транзакции мимо `journalwrite.Begin` и записи журналируемой
//     таблицы пулом мимо транзакции в не-тестовом дереве нет.
//
// Проба, утверждающая отказ базы без инициатора, выставляет его отсутствие
// сама, тем же оператором, что продукт.
//
// # Посев продуктовым писателем — [Writing], и только в посеве
//
// Посев, идущий продуктовым писателем (репозиторием, применителем),
// открывает транзакцию открывающим службы и потому несёт инициатора в
// принципале: `repo.Writer(journalfixture.Writing(ctx))`. Обёртку НЕ ставят в
// переходник пробы, через который продукт передаёт СВОЙ контекст своему же
// хранилищу (`pgStore.Writer` и подобные): там она приписала бы изменение
// посеву и спрятала бы отсутствие инициатора у продукта — ровно то, что
// пробы полосы входа (`TestLoginLaneJournalRowsCarryTheirInitiator`,
// `TestRegisterIntegration_JournalRowsCarryTheRegistrationLaneInitiator`)
// ловят.
package journalfixture

import (
	"context"
	"database/sql"
	"fmt"
	"io/fs"
	"testing"

	"github.com/PRO-Robotech/corelib/auth"
	"github.com/PRO-Robotech/corelib/journaltx"
	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/corelib/pgtest"
)

// Пара личности компонента посева проб и её инициатор.
const (
	fixtureService = "kaname"
	fixtureRole    = "fixture"
	// FixtureInitiator — личность посева проб в форме инициатора журнала.
	FixtureInitiator = "system:" + fixtureService + "-" + fixtureRole
)

// Ctx — контекст посева, идущего ПРОДУКТОВЫМ писателем (репозиторием,
// применителем): писатель открывает транзакцию открывающим службы и берёт
// инициатора у принципала, а ролевую настройку не наследует. Личность —
// та же, что у ролевой настройки, и строит её фундамент.
func Ctx(t testing.TB, ctx context.Context) context.Context {
	t.Helper()
	c, err := Context(ctx)
	if err != nil {
		t.Fatalf("фикстура: личность посева не поставлена: %v", err)
	}
	return c
}

// Writing — контекст ОТКРЫТИЯ пишущей транзакции продуктовым писателем в
// посеве пробы: `repo.Writer(journalfixture.Writing(ctx))`. Прочие операторы
// идут на контексте пробы. Отказ поставить личность здесь не глотается
// подменой: контекст отдаётся прежним, и запись в журналируемую таблицу
// отвергает база.
func Writing(ctx context.Context) context.Context {
	c, err := Context(ctx)
	if err != nil {
		return ctx
	}
	return c
}

// Context — то же для помощника посева, возвращающего ошибку, а не
// владеющего пробой. Контекст, чей принципал уже даёт инициатора (проба
// пишет от имени своего субъекта), отдаётся как есть: личность посева его не
// подменяет.
func Context(ctx context.Context) (context.Context, error) {
	if p, ok := operations.PrincipalFromContextOK(ctx); ok {
		if _, err := auth.InitiatorOf(p); err == nil {
			return ctx, nil
		}
	}
	return journaltx.AsComponent(ctx, fixtureService, fixtureRole)
}

// Migrate — цепь миграций шаблона и инициатор посева на роли контейнера.
func Migrate(fsys fs.FS) func(context.Context, string) error {
	goose := pgtest.Goose(fsys)
	return func(ctx context.Context, dsn string) error {
		if err := goose(ctx, dsn); err != nil {
			return err
		}
		return FixtureInitiatorOnRole()(ctx, dsn)
	}
}

// FixtureInitiatorOnRole — только инициатор посева на роли контейнера, без
// миграций: для пакетов, которые цепь проигрывают сами.
func FixtureInitiatorOnRole() func(context.Context, string) error {
	return func(ctx context.Context, dsn string) error {
		db, err := sql.Open("pgx", dsn)
		if err != nil {
			return fmt.Errorf("fixture initiator: open: %w", err)
		}
		defer func() { _ = db.Close() }()
		// ALTER ROLE не принимает параметров; оба значения — константы.
		stmt := fmt.Sprintf(`ALTER ROLE CURRENT_USER SET %s = '%s'`,
			journaltx.SettingInitiator, FixtureInitiator)
		if _, err := db.ExecContext(ctx, stmt); err != nil {
			return fmt.Errorf("fixture initiator: %w", err)
		}
		return nil
	}
}

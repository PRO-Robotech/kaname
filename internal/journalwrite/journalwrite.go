// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package journalwrite — ЕДИНСТВЕННАЯ точка открытия пишущей транзакции
// службы доступа (NTF-3, Р2; сценарий NTF3-63).
//
// Пакет листовой (фундамент и pgx): его импортируют и репозиторий `pg`, и
// посев, который репозиторий сам импортирует, — открывающий, живущий в `pg`,
// посеву был бы недоступен.
//
// # Зачем одна точка
//
// Семь таблиц ресурсов и три подтаблицы состава пишут ресурсный журнал
// триггером, и строка журнала без инициатора базой не принимается
// (`20261004160000_resource_journal_carries_the_initiator.sql`). Значение даёт
// умолчание колонки из настройки транзакции `kacho_journal.initiator`, и
// выставить её может только тот, кто транзакцию открывает. Какая транзакция
// заденет журнальную таблицу — через репозиторий, каскад или функцию базы, —
// по месту открытия не видно; поэтому настройку выставляет КАЖДАЯ пишущая
// транзакция, и открывается она только здесь.
//
// # Два исхода, и оба выставлены явно
//
//   - у принципала контекста есть форма инициатора (`auth.InitiatorOf`) —
//     транзакцию открывает помощник фундамента `journaltx.Begin`, и строка
//     журнала несёт `user:…`, `service_account:…` либо `system:<служба>-<роль>`;
//   - принципала нет либо формы у него нет (анонимная полоса входа,
//     `{system, *}`) — транзакция открывается, и ПЕРВЫМ оператором отсутствие
//     инициатора выставляется локально к ней пустым значением. Запись в
//     журнальную таблицу такой транзакцией база отвергает `23502` с именем
//     колонки — подстановки инициатора нет ни здесь, ни в базе.
//
// Отсутствие выставляется оператором, а не умалчивается: настройка, оставшаяся
// на соединении от кого-то ещё (сессионная, ролевая), иначе стала бы
// инициатором этой транзакции. Локальная настройка перекрывает любую
// сессионную, поэтому ни одна пишущая транзакция службы инициатора не
// наследует.
//
// Держатели: `journalwrite_integration_test.go` (оба исхода, отказ базы на
// анонимной транзакции поверх унаследованной настройки) и гейт
// `internal/check` `TestWriteTransactionsOpenThroughTheJournalOpener`.
package journalwrite

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/corelib/auth"
	"github.com/PRO-Robotech/corelib/journaltx"
	"github.com/PRO-Robotech/corelib/operations"
)

// journalOptions — флаг ленты модуля для помощника.
//
// У службы доступа своей ленты уведомлений нет: настройку `kacho_feed.enabled`
// читает только функция базы `resource-event`, а в схеме службы её нет.
// Значение `false` — утверждение об этом, а не незаданная ручка; построено
// `NewOptions`, поэтому помощник его принимает.
var journalOptions = journaltx.NewOptions(false)

// Begin открывает пишущую транзакцию, выставив ей инициатора журнала
// (либо его отсутствие) первым оператором. Других способов открыть пишущую
// транзакцию у службы нет.
func Begin(ctx context.Context, src journaltx.TxStarter) (pgx.Tx, error) {
	return BeginTx(ctx, src, pgx.TxOptions{})
}

// BeginTx — то же с параметрами транзакции (уровень изоляции); режим
// доступа «только чтение» сюда не приходит — у читающей транзакции журнала нет.
func BeginTx(ctx context.Context, src journaltx.TxStarter, opts pgx.TxOptions) (pgx.Tx, error) {
	if opts.AccessMode == pgx.ReadOnly {
		return nil, fmt.Errorf("journalwrite: read-only transaction is not opened by the journal opener")
	}
	if p, ok := operations.PrincipalFromContextOK(ctx); ok {
		if _, err := auth.InitiatorOf(p); err == nil {
			return journaltx.Begin(ctx, withOptions{src: src, opts: opts}, journalOptions)
		}
	}
	tx, err := src.BeginTx(ctx, opts)
	if err != nil {
		return nil, err
	}
	if _, err := tx.Exec(ctx, `SELECT set_config($1, '', true)`, journaltx.SettingInitiator); err != nil {
		_ = tx.Rollback(ctx)
		return nil, fmt.Errorf("journalwrite: state the absent journal initiator: %w", err)
	}
	return tx, nil
}

// InTx исполняет fn под ОДНОЙ пишущей транзакцией, открытой [Begin]:
// фиксирует её, когда fn вернул nil, и откатывает при ошибке либо панике fn.
//
// Форма «исполнитель над пулом» нужна писателям, которые отдают транзакцию
// применителю (посев модулей, каталог модулей): прежде они брали исполнителя
// фундамента `corelib/db.Transactor`, а тот открывает транзакцию сам, мимо
// этого пакета, — и инициатора журнала она не несла (kaname#484). Других
// исполнителей пишущей транзакции у службы нет; держит гейт `internal/check`
// (W4).
func InTx(ctx context.Context, src journaltx.TxStarter, fn func(pgx.Tx) error) error {
	tx, err := Begin(ctx, src)
	if err != nil {
		return err
	}
	// Откат после фиксации — пустой ход; здесь он закрывает выход ошибкой и
	// паникой. Контекст без отмены: транзакция отменённого запроса откатывается,
	// а не остаётся висеть на соединении до его возврата.
	defer func() { _ = tx.Rollback(context.WithoutCancel(ctx)) }()
	if err := fn(tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}

// withOptions передаёт помощнику параметры транзакции вызывающего: помощник
// открывает транзакцию с нулевыми, а уровень изоляции у некоторых писателей
// несущий.
type withOptions struct {
	src  journaltx.TxStarter
	opts pgx.TxOptions
}

func (s withOptions) BeginTx(ctx context.Context, _ pgx.TxOptions) (pgx.Tx, error) {
	return s.src.BeginTx(ctx, s.opts)
}

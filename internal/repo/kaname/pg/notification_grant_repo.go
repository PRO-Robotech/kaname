// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// notification_grant_repo.go — запись выдачи пространства уведомлений и запись
// шаблона (приёмка NTF-1 Р5; замысел З18; таблицы — миграция
// 20261004113000_notification_grants.sql).
//
// Чтение решения — ОДИН оператор (`LEFT JOIN` записи шаблона к записи
// пространства). «Не найдено» различается ровно в одном месте —
// `errors.Is(err, pgx.ErrNoRows)`; любая иная ошибка уходит вызывающему как
// есть, и тот отвечает `UNAVAILABLE`, а не «права ещё нет» (NTF1-F23).
//
// Переходы — CAS одним оператором. Ноль строк — одно чтение ПОСЛЕ неудачной
// записи в той же транзакции, классификация «записи нет» против «не то
// состояние». Чтения состояния с последующей безусловной записью нет (NTF1-F18).
// Момент перехода — `clock_timestamp()`: момент записи, а не начала
// транзакции, которая могла ждать замка строки.

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"google.golang.org/protobuf/types/known/anypb"

	"github.com/PRO-Robotech/corelib/operations"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/service"
)

// NotificationGrantRepo — чтение решения и CAS-переходы записи выдачи.
type NotificationGrantRepo struct {
	pool *pgxpool.Pool
}

// NewNotificationGrantRepo — конструктор над пулом службы.
func NewNotificationGrantRepo(pool *pgxpool.Pool) *NotificationGrantRepo {
	return &NotificationGrantRepo{pool: pool}
}

// ReadSendState — состояние записи пространства и записи шаблона строки одним
// оператором. found == false — записи пространства нет.
func (r *NotificationGrantRepo) ReadSendState(ctx context.Context, namespace, template string) (domain.NotificationGrantState, bool, error) {
	var st domain.NotificationGrantState
	var cutoff, templateCutoff *time.Time
	err := r.pool.QueryRow(ctx, `
		SELECT g.revoked_at IS NOT NULL, g.cutoff_at,
		       coalesce(t.revoked_at IS NOT NULL, false), t.cutoff_at
		  FROM kaname.notification_grants g
		  LEFT JOIN kaname.notification_template_grants t
		         ON t.namespace = g.namespace AND t.template = $2
		 WHERE g.namespace = $1`, namespace, template).
		Scan(&st.Revoked, &cutoff, &st.TemplateRevoked, &templateCutoff)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.NotificationGrantState{}, false, nil
	}
	if err != nil {
		return domain.NotificationGrantState{}, false, fmt.Errorf("read notification grant: %w", err)
	}
	st.Cutoff, st.TemplateCutoff = cutoff, templateCutoff
	return st, true, nil
}

// RevokeNamespace — надгробие на записи пространства (CAS по `revoked_at IS NULL`).
func (r *NotificationGrantRepo) RevokeNamespace(ctx context.Context, tx service.Tx, namespace string) error {
	return casTransition(ctx, txAsPgx(tx), namespace, `
		UPDATE kaname.notification_grants
		   SET revoked_at = clock_timestamp()
		 WHERE namespace = $1 AND revoked_at IS NULL
		RETURNING 1`, namespace)
}

// RestoreNamespace — снимает надгробие и ставит отсечку (CAS по
// `revoked_at IS NOT NULL`).
func (r *NotificationGrantRepo) RestoreNamespace(ctx context.Context, tx service.Tx, namespace string) error {
	return casTransition(ctx, txAsPgx(tx), namespace, `
		UPDATE kaname.notification_grants
		   SET revoked_at = NULL, cutoff_at = clock_timestamp()
		 WHERE namespace = $1 AND revoked_at IS NOT NULL
		RETURNING 1`, namespace)
}

// RevokeTemplate — надгробие на записи шаблона; запись заводится первым
// вызовом. Вставка идёт из записи пространства: нет её — строк ноль, и
// внешний ключ не нарушается вовсе.
func (r *NotificationGrantRepo) RevokeTemplate(ctx context.Context, tx service.Tx, namespace, template string) error {
	return casTransition(ctx, txAsPgx(tx), namespace, `
		INSERT INTO kaname.notification_template_grants AS t (namespace, template, revoked_at)
		SELECT g.namespace, $2, clock_timestamp()
		  FROM kaname.notification_grants g
		 WHERE g.namespace = $1
		ON CONFLICT (namespace, template) DO UPDATE
		   SET revoked_at = clock_timestamp()
		 WHERE t.revoked_at IS NULL
		RETURNING 1`, namespace, template)
}

// RestoreTemplate — снимает надгробие записи шаблона и ставит её отсечку.
func (r *NotificationGrantRepo) RestoreTemplate(ctx context.Context, tx service.Tx, namespace, template string) error {
	return casTransition(ctx, txAsPgx(tx), namespace, `
		UPDATE kaname.notification_template_grants
		   SET revoked_at = NULL, cutoff_at = clock_timestamp()
		 WHERE namespace = $1 AND template = $2 AND revoked_at IS NOT NULL
		RETURNING 1`, namespace, template)
}

// casTransition исполняет переход и, если строк ноль, одним чтением
// классифицирует отказ: записи пространства нет — ErrNotificationGrantNotFound,
// есть — ErrNotificationGrantState.
func casTransition(ctx context.Context, tx pgx.Tx, namespace, query string, args ...any) error {
	var one int
	err := tx.QueryRow(ctx, query, args...).Scan(&one)
	if err == nil {
		return nil
	}
	if !errors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("notification grant transition: %w", err)
	}
	var exists bool
	if err := tx.QueryRow(ctx,
		`SELECT EXISTS (SELECT 1 FROM kaname.notification_grants WHERE namespace = $1)`, namespace).
		Scan(&exists); err != nil {
		return fmt.Errorf("notification grant classify: %w", err)
	}
	if !exists {
		return domain.ErrNotificationGrantNotFound
	}
	return domain.ErrNotificationGrantState
}

// OperationTxCreator — запись завершённой операции В ТРАНЗАКЦИИ перехода:
// принятый переход и его операция коммитятся вместе, отказ не оставляет ни
// той, ни другой.
type OperationTxCreator struct {
	repo operations.TxWriter
}

// NewOperationTxCreator — конструктор над репозиторием операций, обёрнутым
// надстройкой текста отказа в композиционном корне.
func NewOperationTxCreator(repo operations.TxWriter) *OperationTxCreator {
	return &OperationTxCreator{repo: repo}
}

// CreateDoneTx — операция `done=true` с ответом в транзакции tx.
func (c *OperationTxCreator) CreateDoneTx(ctx context.Context, tx service.Tx, op operations.Operation,
	p operations.Principal, response *anypb.Any) error {
	return c.repo.CreateDoneTx(ctx, txAsPgx(tx), op, p, response)
}

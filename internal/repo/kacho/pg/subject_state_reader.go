// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// subject_state_reader.go — читает СОСТОЯНИЕ субъекта, которому собираются
// выдать право уровня кластера.
//
// Прежняя редакция спрашивала только «есть ли такая строка» и возвращала
// `error`, поэтому вызывающий физически не мог узнать ничего сверх факта
// наличия. Между тем состояние здесь и есть предмет решения: заблокированному
// пользователю и отключённой служебной учётке право выдавать нельзя — оно
// переживёт запрет и материализуется в тот момент, когда запрет снимут.
//
// Состояние возвращается вместе с ответом, а не отдельным вызовом: иначе
// решение можно принять по полю, которого этот запрос не выбрал (bool `enabled`
// в незаполненной структуре — «false» для каждой учётки на свете, и проверка
// против него отказывает всем, выглядя рабочим гейтом).
//
// Почему не FK: `cluster_admin_grants.subject_id` полиморфен
// (`subject_type ∈ {user, service_account}`), а частичных/условных внешних
// ключей в PostgreSQL нет. Чтение идёт по request-path, до открытия
// writer-транзакции, чтобы отказ был синхронным.

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// SubjectStateReader — тонкий read-адаптер над kacho_iam.{users,service_accounts}.
type SubjectStateReader struct {
	pool *pgxpool.Pool
}

// NewSubjectStateReader — конструктор.
func NewSubjectStateReader(pool *pgxpool.Pool) *SubjectStateReader {
	return &SubjectStateReader{pool: pool}
}

// UserInviteStatus — состояние пользовательской строки.
//
// Строки нет → ErrInvalidArg «User %s not found» (тон контракта сохранён:
// вызывающий назвал субъекта, которого не существует). Строка есть → её
// состояние, каким бы оно ни было; судит его вызывающий.
func (c *SubjectStateReader) UserInviteStatus(ctx context.Context, userID string) (domain.InviteStatus, error) {
	var st string
	err := c.pool.QueryRow(ctx,
		`SELECT invite_status FROM kacho_iam.users WHERE id = $1`, userID).Scan(&st)
	if err == nil {
		return domain.InviteStatus(st), nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return "", iamerr.Wrapf(iamerr.ErrInvalidArg, "User %s not found", userID)
	}
	return "", fmt.Errorf("user state read: %w", err)
}

// ServiceAccountEnabled — состояние машинной строки: вправе ли эта служебная
// учётка аутентифицироваться. Строки нет → ErrInvalidArg
// «ServiceAccount %s not found».
func (c *SubjectStateReader) ServiceAccountEnabled(ctx context.Context, svaID string) (bool, error) {
	var enabled bool
	err := c.pool.QueryRow(ctx,
		`SELECT enabled FROM kacho_iam.service_accounts WHERE id = $1`, svaID).Scan(&enabled)
	if err == nil {
		return enabled, nil
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "ServiceAccount %s not found", svaID)
	}
	return false, fmt.Errorf("service account state read: %w", err)
}

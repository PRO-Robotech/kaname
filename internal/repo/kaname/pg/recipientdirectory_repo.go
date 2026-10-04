// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// recipientdirectory_repo.go — чтения справочника адресов (приёмка NTF-3 Р7):
// запись получателя, владелец аккаунта и аудитория проекта. Только чтение;
// каждое — один оператор. «Не найдено» различается ровно в одном месте —
// `errors.Is(err, pgx.ErrNoRows)`; любая иная ошибка уходит вызывающему, и тот
// отвечает `UNAVAILABLE` фиксированным текстом.

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// RecipientDirectoryRepo — чтения справочника над пулом службы.
type RecipientDirectoryRepo struct {
	pool *pgxpool.Pool
}

// NewRecipientDirectoryRepo — конструктор над пулом службы.
func NewRecipientDirectoryRepo(pool *pgxpool.Pool) *RecipientDirectoryRepo {
	return &RecipientDirectoryRepo{pool: pool}
}

// ReadRecipient — запись получателя вида kind. found == false — записи нет.
func (r *RecipientDirectoryRepo) ReadRecipient(ctx context.Context, kind domain.RecipientKind, id string) (
	domain.RecipientRecord, bool, error,
) {
	var rec domain.RecipientRecord
	var err error
	switch kind {
	case domain.RecipientKindUser:
		err = r.pool.QueryRow(ctx, `
			SELECT invite_status = 'ACTIVE', email, email_verified_at IS NOT NULL
			  FROM kaname.users
			 WHERE id = $1`, id).Scan(&rec.Active, &rec.Email, &rec.EmailVerified)
	case domain.RecipientKindServiceAccount:
		// У учётной записи службы адреса нет никогда: читается только её
		// существование.
		var one int
		err = r.pool.QueryRow(ctx, `SELECT 1 FROM kaname.service_accounts WHERE id = $1`, id).Scan(&one)
	default:
		return domain.RecipientRecord{}, false, fmt.Errorf("read recipient: unknown recipient kind %d", kind)
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.RecipientRecord{}, false, nil
	}
	if err != nil {
		return domain.RecipientRecord{}, false, fmt.Errorf("read recipient: %w", err)
	}
	return rec, true, nil
}

// ReadAccountOwner — id пользователя-владельца аккаунта. found == false —
// аккаунта нет.
func (r *RecipientDirectoryRepo) ReadAccountOwner(ctx context.Context, accountID string) (string, bool, error) {
	var owner string
	err := r.pool.QueryRow(ctx, `SELECT owner_user_id FROM kaname.accounts WHERE id = $1`, accountID).Scan(&owner)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("read account owner: %w", err)
	}
	if owner == "" {
		return "", false, nil
	}
	return owner, true, nil
}

// ListProjectUsers — id пользователей с действующей прямой привязкой на
// `project:<projectID>`, строго больше afterID, по возрастанию, не больше
// limit. Действующая — ACTIVE (не отозвана, не ожидает) и не истекла к моменту
// запроса. Пользователь с несколькими привязками — один элемент.
//
// Субъекты привязки — строки `access_binding_subjects` (привязка с несколькими
// субъектами — несколько строк); группы не раскрываются: субъект-группа сюда
// не попадает по `subject_type`.
func (r *RecipientDirectoryRepo) ListProjectUsers(ctx context.Context, projectID, afterID string, limit int) ([]string, error) {
	rows, err := r.pool.Query(ctx, `
		SELECT DISTINCT s.subject_id
		  FROM kaname.access_bindings b
		  JOIN kaname.access_binding_subjects s ON s.binding_id = b.id
		 WHERE b.resource_type = 'project' AND b.resource_id = $1
		   AND b.status = 'ACTIVE'
		   AND (b.expires_at IS NULL OR b.expires_at > now())
		   AND s.subject_type = 'user'
		   AND s.subject_id > $2
		 ORDER BY s.subject_id
		 LIMIT $3`, projectID, afterID, limit)
	if err != nil {
		return nil, fmt.Errorf("list project audience: %w", err)
	}
	ids, err := pgx.CollectRows(rows, pgx.RowTo[string])
	if err != nil {
		return nil, fmt.Errorf("list project audience: %w", err)
	}
	return ids, nil
}

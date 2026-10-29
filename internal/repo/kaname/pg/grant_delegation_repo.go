// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// grant_delegation_repo.go — хранилище делегирований права выдавать (задача
// PRO-Robotech/kaname#986). Читатель и писатель живут на транзакции выдач
// (`abReader.GrantDelegations`, `abWriter.GrantDelegationsW`): делегирование —
// часть домена выдач, и его отзыв вместе с отзывом выдач по нему, равно как
// запись выдачи делегатом под замком строки делегирования, идут ОДНОЙ
// транзакцией писателя.

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/grant_delegation"
)

type gdReader struct {
	tx pgx.Tx
}

type gdWriter struct {
	gdReader
}

// GrantDelegations — читатель делегирований на транзакции читателя выдач.
func (r *abReader) GrantDelegations() grant_delegation.ReaderIface {
	return &gdReader{tx: r.tx}
}

// GrantDelegationsW — писатель делегирований на транзакции писателя выдач.
func (w *abWriter) GrantDelegationsW() grant_delegation.WriterIface {
	return &gdWriter{gdReader{tx: w.tx}}
}

// gdCols — столбцы делегирования; SELECT и RETURNING интерполируют одну
// константу, порядок назначений объявлен один раз — `scanGrantDelegation`.
const gdCols = "id, account_id, delegate_id, role_ids, target_types, subject_types, module, status, " +
	"delegated_by_type, delegated_by_id, created_at, revoked_at, " +
	"COALESCE(revoked_by_type, '') AS revoked_by_type, COALESCE(revoked_by_id, '') AS revoked_by_id"

func scanGrantDelegation(row scanner) (domain.GrantDelegation, error) {
	var (
		d                        domain.GrantDelegation
		roles, types, subjects   []string
		revokedAt                sql.NullTime
		revokedByType, revokedBy string
	)
	if err := row.Scan(
		(*string)(&d.ID),
		(*string)(&d.AccountID),
		(*string)(&d.DelegateID),
		&roles,
		&types,
		&subjects,
		&d.Module,
		(*string)(&d.Status),
		&d.DelegatedBy.Type,
		&d.DelegatedBy.ID,
		&d.CreatedAt,
		&revokedAt,
		&revokedByType,
		&revokedBy,
	); err != nil {
		return domain.GrantDelegation{}, err
	}
	for _, r := range roles {
		d.RoleIDs = append(d.RoleIDs, domain.RoleID(r))
	}
	d.TargetTypes = types
	for _, s := range subjects {
		d.SubjectTypes = append(d.SubjectTypes, domain.SubjectType(s))
	}
	if revokedAt.Valid {
		t := revokedAt.Time
		d.RevokedAt = &t
	}
	if revokedByType != "" || revokedBy != "" {
		d.RevokedBy = &domain.GrantDelegationActor{Type: revokedByType, ID: revokedBy}
	}
	return d, nil
}

func grantDelegationNotFound(id domain.GrantDelegationID) error {
	return iamerr.Wrapf(iamerr.ErrNotFound, "GrantDelegation %s not found", id)
}

// Get — делегирование по идентификатору.
func (r *gdReader) Get(ctx context.Context, id domain.GrantDelegationID) (domain.GrantDelegation, error) {
	d, err := scanGrantDelegation(r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM kaname.grant_delegations WHERE id = $1`, gdCols), string(id)))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.GrantDelegation{}, grantDelegationNotFound(id)
	}
	if err != nil {
		return domain.GrantDelegation{}, mapErr(err, "", string(id))
	}
	return d, nil
}

// ActiveFor — действующее делегирование пары «аккаунт, делегат» по частичному
// уникальному индексу `grant_delegations_active_pair_uniq`.
func (r *gdReader) ActiveFor(ctx context.Context, accountID domain.AccountID, delegate domain.ServiceAccountID) (domain.GrantDelegation, error) {
	d, err := scanGrantDelegation(r.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM kaname.grant_delegations
		              WHERE account_id = $1 AND delegate_id = $2 AND status = 'ACTIVE'`, gdCols),
		string(accountID), string(delegate)))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.GrantDelegation{}, iamerr.Wrapf(iamerr.ErrNotFound,
			"no active grant delegation to service account %s in account %s", delegate, accountID)
	}
	if err != nil {
		return domain.GrantDelegation{}, mapErr(err, "", string(delegate))
	}
	return d, nil
}

// List — делегирования аккаунта курсором `(created_at, id)` по возрастанию.
// Моменты хранятся усечёнными до секунды (`Insert`), поэтому порядок страницы
// совпадает с порядком, который видит клиент по усечённому `createdAt`.
func (r *gdReader) List(ctx context.Context, accountID domain.AccountID, f grant_delegation.PageFilter) ([]domain.GrantDelegation, string, error) {
	pageSize, err := effectivePageSize(f.PageSize)
	if err != nil {
		return nil, "", err
	}
	conditions := []string{"account_id = $1"}
	args := []any{string(accountID)}
	if f.PageToken != "" {
		ts, id, derr := decodePageToken(f.PageToken)
		if derr != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token")
		}
		conditions = append(conditions, "(created_at, id) > ($2, $3)")
		args = append(args, ts, id)
	}
	args = append(args, pageSize+1)
	q := fmt.Sprintf(`SELECT %s FROM kaname.grant_delegations WHERE %s ORDER BY created_at ASC, id ASC LIMIT $%d`,
		gdCols, strings.Join(conditions, " AND "), len(args))
	rows, err := r.tx.Query(ctx, q, args...)
	if err != nil {
		return nil, "", mapErr(err, "", "")
	}
	defer rows.Close()
	var out []domain.GrantDelegation
	for rows.Next() {
		d, serr := scanGrantDelegation(rows)
		if serr != nil {
			return nil, "", mapErr(serr, "", "")
		}
		out = append(out, d)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "", "")
	}
	var next string
	if int64(len(out)) > pageSize {
		last := out[pageSize-1]
		next = encodePageToken(last.CreatedAt, string(last.ID))
		out = out[:pageSize]
	}
	return out, next, nil
}

// targetObjectAccountSQL — регистрация объекта цели и аккаунт его проекта.
//
// Имя типа приходит словарём КАТАЛОГА (`registry.registries`), им названа строка
// регистрации `resource_mirror`; цепь предков `resource_scope_edge` названа
// словарём МОДЕЛИ, перевод — живая строка каталога (`catalog_resource`), как у
// вердикта (relverdict, `catalogTypeName`). Цепь читается обходом вверх, а не
// одним звеном: владельцы ресурсов шлют короткую цепь, и у репозитория реестра
// проект — второе звено (репозиторий → реестр → проект). Предел глубины — тот
// же, что у вердикта.
const targetObjectAccountSQL = `
WITH RECURSIVE
model AS (
    SELECT COALESCE((SELECT r.object_type FROM kaname.catalog_resource r
                      WHERE r.dotted = $1::text ORDER BY r.live DESC, r.object_type LIMIT 1), $1::text) AS t
),
chain(s_type, s_id, depth) AS (
    SELECT (SELECT t FROM model), $2::text, 0
  UNION
    SELECT e.parent_type, e.parent_id, c.depth + 1
      FROM chain c
      CROSS JOIN LATERAL (
             SELECT pe.parent_type, pe.parent_id
               FROM kaname.resource_scope_edge pe
              WHERE pe.object_type = c.s_type AND pe.object_id = c.s_id
              ORDER BY pe.depth
              LIMIT 4
           ) e
     WHERE c.depth < 4
)
SELECT EXISTS (SELECT 1 FROM kaname.resource_mirror m WHERE m.object_type = $1::text AND m.object_id = $2::text),
       COALESCE((SELECT p.account_id
                   FROM chain c JOIN kaname.projects p ON p.id = c.s_id
                  WHERE c.s_type = 'project'
                  ORDER BY c.depth
                  LIMIT 1), '')`

// TargetObjectAccount — зарегистрирован ли объект цели и аккаунт его проекта (Д7).
func (r *gdReader) TargetObjectAccount(ctx context.Context, ref domain.ResourceRef) (bool, domain.AccountID, error) {
	var (
		registered bool
		account    string
	)
	if err := r.tx.QueryRow(ctx, targetObjectAccountSQL, ref.Type, ref.ID).Scan(&registered, &account); err != nil {
		return false, "", mapErr(err, "", ref.ID)
	}
	return registered, domain.AccountID(account), nil
}

// Insert — заведение делегирования. Моменты усекаются до секунды на записи:
// порядок перечня (`created_at`, id) тогда совпадает с порядком по усечённому
// `createdAt` ответа.
func (w *gdWriter) Insert(ctx context.Context, d domain.GrantDelegation) (domain.GrantDelegation, error) {
	roles := make([]string, 0, len(d.RoleIDs))
	for _, r := range d.RoleIDs {
		roles = append(roles, string(r))
	}
	subjects := make([]string, 0, len(d.SubjectTypes))
	for _, s := range d.SubjectTypes {
		subjects = append(subjects, string(s))
	}
	created := d.CreatedAt
	if created.IsZero() {
		created = time.Now().UTC()
	}
	out, err := scanGrantDelegation(w.tx.QueryRow(ctx, fmt.Sprintf(`
		INSERT INTO kaname.grant_delegations (
			id, account_id, delegate_id, active_delegate_id, role_ids, target_types, subject_types,
			module, status, delegated_by_type, delegated_by_id, created_at
		) VALUES ($1, $2, $3, $3, $4, $5, $6, $7, 'ACTIVE', $8, $9, $10)
		RETURNING %s`, gdCols),
		string(d.ID), string(d.AccountID), string(d.DelegateID), roles, d.TargetTypes, subjects,
		d.Module, d.DelegatedBy.Type, d.DelegatedBy.ID, created.Truncate(time.Second)))
	if err != nil {
		return domain.GrantDelegation{}, mapErr(err, "", string(d.DelegateID)+"|"+string(d.AccountID))
	}
	return out, nil
}

// LockForRevoke — строка делегирования под `FOR UPDATE`.
func (w *gdWriter) LockForRevoke(ctx context.Context, id domain.GrantDelegationID) (domain.GrantDelegation, error) {
	d, err := scanGrantDelegation(w.tx.QueryRow(ctx,
		fmt.Sprintf(`SELECT %s FROM kaname.grant_delegations WHERE id = $1 FOR UPDATE`, gdCols), string(id)))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.GrantDelegation{}, grantDelegationNotFound(id)
	}
	if err != nil {
		return domain.GrantDelegation{}, mapErr(err, "", string(id))
	}
	return d, nil
}

// MarkRevoked — CAS `ACTIVE → REVOKED`: ссылка на учётку-делегата снимается тем же
// оператором (`grant_delegations_active_delegate_ck`), и учётка больше не держится
// отозванным делегированием (Д8).
func (w *gdWriter) MarkRevoked(ctx context.Context, id domain.GrantDelegationID, by domain.GrantDelegationActor, at time.Time) (domain.GrantDelegation, error) {
	d, err := scanGrantDelegation(w.tx.QueryRow(ctx, fmt.Sprintf(`
		UPDATE kaname.grant_delegations
		   SET status = 'REVOKED', active_delegate_id = NULL,
		       revoked_at = $2, revoked_by_type = $3, revoked_by_id = $4
		 WHERE id = $1 AND status = 'ACTIVE'
		RETURNING %s`, gdCols), string(id), at.Truncate(time.Second), by.Type, by.ID))
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.GrantDelegation{}, iamerr.Wrapf(iamerr.ErrFailedPrecondition,
			"grant delegation %s is already revoked", id)
	}
	if err != nil {
		return domain.GrantDelegation{}, mapErr(err, "GrantDelegation.Revoke", string(id))
	}
	return d, nil
}

// ActiveBindingIDs — действующие выдачи делегирования под `FOR UPDATE` по
// возрастанию id, по частичному индексу `access_bindings_delegation_live_idx`.
func (w *gdWriter) ActiveBindingIDs(ctx context.Context, id domain.GrantDelegationID) ([]domain.AccessBindingID, error) {
	rows, err := w.tx.Query(ctx, `
		SELECT id FROM kaname.access_bindings
		 WHERE delegation_id = $1 AND revoked_at IS NULL
		 ORDER BY id
		   FOR UPDATE`, string(id))
	if err != nil {
		return nil, mapErr(err, "", string(id))
	}
	defer rows.Close()
	var out []domain.AccessBindingID
	for rows.Next() {
		var b string
		if err := rows.Scan(&b); err != nil {
			return nil, mapErr(err, "", string(id))
		}
		out = append(out, domain.AccessBindingID(b))
	}
	if err := rows.Err(); err != nil {
		return nil, mapErr(err, "", string(id))
	}
	return out, nil
}

// RevokeBindingForDelegation — CAS отзыва выдачи с причиной DELEGATION_REVOKED.
// Защита от удаления условием не является: отзыв делегирования снимает и
// защищённую выдачу, как снятие регистрации (kaname#963, URG-11).
func (w *gdWriter) RevokeBindingForDelegation(ctx context.Context, id domain.AccessBindingID, revokedBy domain.UserID, at time.Time) (bool, error) {
	tag, err := w.tx.Exec(ctx, `
		UPDATE kaname.access_bindings
		   SET status = 'REVOKED', revoked_at = $2, revoked_by_user_id = $3,
		       revocation_reason = 'DELEGATION_REVOKED'
		 WHERE id = $1 AND revoked_at IS NULL`, string(id), at, string(revokedBy))
	if err != nil {
		return false, mapErr(err, "AccessBinding.RevokeForDelegation", string(id))
	}
	return tag.RowsAffected() == 1, nil
}

// HoldActive — строка делегирования под `FOR SHARE` по захваченному id с
// перепроверкой `status = 'ACTIVE'`. Внешнего ключа выдачи мало: он берёт
// `FOR KEY SHARE`, а смена состояния — не ключевое обновление, и эти замки не
// конфликтуют (условие CE-09). `FOR SHARE` конфликтует с `FOR UPDATE` отзыва:
// запись выдачи ждёт его фиксации и перечитывает строку уже отозванной.
func (w *gdWriter) HoldActive(ctx context.Context, id domain.GrantDelegationID) (domain.AccountID, bool, error) {
	var acc string
	err := w.tx.QueryRow(ctx,
		`SELECT account_id FROM kaname.grant_delegations WHERE id = $1 AND status = 'ACTIVE' FOR SHARE`, string(id)).Scan(&acc)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, mapErr(err, "", string(id))
	}
	return domain.AccountID(acc), true, nil
}

// AccountOf — аккаунт делегирования.
func (w *gdWriter) AccountOf(ctx context.Context, id domain.GrantDelegationID) (domain.AccountID, error) {
	var acc string
	err := w.tx.QueryRow(ctx, `SELECT account_id FROM kaname.grant_delegations WHERE id = $1`, string(id)).Scan(&acc)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", grantDelegationNotFound(id)
	}
	if err != nil {
		return "", mapErr(err, "", string(id))
	}
	return domain.AccountID(acc), nil
}

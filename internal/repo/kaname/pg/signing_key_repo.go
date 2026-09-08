// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// SigningKeyRepo — ключница подписных ключей платформы (задача #897).
//
// # Что здесь держит инвариант, а что только его выражает
//
// «Подписывает ровно один» держит ЧАСТИЧНЫЙ УНИКАЛЬНЫЙ ИНДЕКС
// token_signing_keys_one_active, а не код ниже (ban #10). Смена подписывающего
// идёт одной транзакцией из двух операторов — понижение действующего и
// повышение названного, — и проигравшая под конкуренцией получает нарушение
// уникальности от базы, а не тихо перезаписывает победителя.
//
// # Почему не «прочитать → убедиться → записать»
//
// Потому что под конкуренцией такая последовательность даёт двух подписывающих,
// и это состояние ничем не отличимо от исправного, пока кто-нибудь не спросит.
type SigningKeyRepo struct {
	pool *pgxpool.Pool
}

// NewSigningKeyRepo — построитель.
func NewSigningKeyRepo(pool *pgxpool.Pool) *SigningKeyRepo {
	return &SigningKeyRepo{pool: pool}
}

// signingKeyColumns — проекция чтения. Перечень выписан ОДИН раз: две копии
// разошлись бы, и разошлись бы молча — на колонке, которую забыли выбрать.
const signingKeyColumns = `kid, algorithm, state, public_key_pem, private_key_wrapped,
	created_at, not_after, activated_at, retired_at, removed_at, compromised_at`

// Insert записывает порождённый ключ.
func (r *SigningKeyRepo) Insert(ctx context.Context, rec domain.SigningKeyRecord) error {
	if err := rec.KID.Validate(); err != nil {
		return fmt.Errorf("%w: %s", iamerr.ErrInvalidArg, err)
	}
	const q = `INSERT INTO kaname.token_signing_keys
		(kid, algorithm, state, public_key_pem, private_key_wrapped,
		 created_at, not_after, activated_at, retired_at, removed_at, compromised_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`
	_, err := r.pool.Exec(ctx, q,
		string(rec.KID), string(rec.Algorithm), string(rec.State),
		rec.PublicKeyPEM, rec.PrivateKeyWrapped,
		rec.CreatedAt, rec.NotAfter,
		rec.ActivatedAt, rec.RetiredAt, rec.RemovedAt, rec.CompromisedAt)
	if err != nil {
		return wrapPgErr(err, "SigningKey", string(rec.KID))
	}
	return nil
}

// Get читает строку по идентификатору ключа.
func (r *SigningKeyRepo) Get(ctx context.Context, kid domain.KeyID) (domain.SigningKeyRecord, error) {
	q := `SELECT ` + signingKeyColumns + ` FROM kaname.token_signing_keys WHERE kid = $1`
	row := r.pool.QueryRow(ctx, q, string(kid))
	rec, err := scanSigningKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.SigningKeyRecord{}, fmt.Errorf("%w: SigningKey %s", iamerr.ErrNotFound, kid)
	}
	if err != nil {
		return domain.SigningKeyRecord{}, wrapPgErr(err, "SigningKey", string(kid))
	}
	return rec, nil
}

// Active возвращает подписывающий ключ.
//
// Отсутствие подписывающего — ОТКАЗ, а не нулевая структура: «подписали ничем»
// обязано быть невыразимо, а не отловлено вызывающим.
func (r *SigningKeyRepo) Active(ctx context.Context) (domain.SigningKeyRecord, error) {
	q := `SELECT ` + signingKeyColumns + ` FROM kaname.token_signing_keys WHERE state = 'ACTIVE'`
	row := r.pool.QueryRow(ctx, q)
	rec, err := scanSigningKey(row)
	if errors.Is(err, pgx.ErrNoRows) {
		return domain.SigningKeyRecord{}, fmt.Errorf("%w: no active signing key", iamerr.ErrFailedPrecondition)
	}
	if err != nil {
		return domain.SigningKeyRecord{}, wrapPgErr(err, "SigningKey", "")
	}
	return rec, nil
}

// KeySet возвращает ключи, попадающие в публикуемый набор.
//
// Отбор идёт ПО СОСТОЯНИЮ, а не «все строки»: набор, отдающий строки подряд,
// отдал бы и снятый, и скомпрометированный ключ.
func (r *SigningKeyRepo) KeySet(ctx context.Context) ([]domain.SigningKeyRecord, error) {
	q := `SELECT ` + signingKeyColumns + ` FROM kaname.token_signing_keys
		WHERE state IN ('PUBLISHED','ACTIVE','RETIRED')
		ORDER BY created_at, kid`
	rows, err := r.pool.Query(ctx, q)
	if err != nil {
		return nil, wrapPgErr(err, "SigningKey", "")
	}
	defer rows.Close()
	var out []domain.SigningKeyRecord
	for rows.Next() {
		rec, err := scanSigningKey(rows)
		if err != nil {
			return nil, wrapPgErr(err, "SigningKey", "")
		}
		out = append(out, rec)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr(err, "SigningKey", "")
	}
	return out, nil
}

// Activate делает названный ключ подписывающим.
//
// Одна транзакция, два оператора: действующий понижается, названный
// повышается. Наружу промежуточного состояния не существует — читатель видит
// либо прежнего подписывающего, либо нового, но никогда ни ноль, ни два.
//
// Повышение допускается ТОЛЬКО из PUBLISHED (и из ACTIVE — идемпотентно):
// переход в подпись из REMOVED и COMPROMISED не выражается ни здесь, ни в
// машине состояний домена.
func (r *SigningKeyRepo) Activate(ctx context.Context, kid domain.KeyID, at time.Time) error {
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return wrapPgErr(err, "SigningKey", string(kid))
	}
	defer func() { _ = tx.Rollback(ctx) }()

	const demote = `UPDATE kaname.token_signing_keys
		SET state = 'RETIRED', retired_at = $1
		WHERE state = 'ACTIVE' AND kid <> $2`
	if _, err := tx.Exec(ctx, demote, at, string(kid)); err != nil {
		return wrapPgErr(err, "SigningKey", string(kid))
	}

	const promote = `UPDATE kaname.token_signing_keys
		SET state = 'ACTIVE', activated_at = COALESCE(activated_at, $1)
		WHERE kid = $2 AND state IN ('PUBLISHED','ACTIVE')
		RETURNING kid`
	var got string
	if err := tx.QueryRow(ctx, promote, at, string(kid)).Scan(&got); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			// Ноль строк означает одно из двух и оба — отказ: ключа нет либо
			// его состояние перехода не допускает. Различать их здесь значило
			// бы сообщать предъявителю, существует ли строка.
			return fmt.Errorf("%w: SigningKey %s cannot become the signing key", iamerr.ErrFailedPrecondition, kid)
		}
		return wrapPgErr(err, "SigningKey", string(kid))
	}
	if err := tx.Commit(ctx); err != nil {
		// Нарушение уникальности приезжает ИМЕННО СЮДА, когда конкурент успел
		// зафиксировать своё повышение: это и есть инвариант базы, делающий
		// свою работу. Маршрутизируем через тот же преобразователь SQLSTATE.
		return wrapPgErr(err, "SigningKey", string(kid))
	}
	return nil
}

// Retire выводит ключ из подписи, оставляя его в наборе на отсрочку.
func (r *SigningKeyRepo) Retire(ctx context.Context, kid domain.KeyID, at time.Time) error {
	return r.transition(ctx, kid, `UPDATE kaname.token_signing_keys
		SET state = 'RETIRED', retired_at = $1
		WHERE kid = $2 AND state IN ('PUBLISHED','ACTIVE') RETURNING kid`, at)
}

// Remove снимает ключ из набора: отсрочка истекла.
func (r *SigningKeyRepo) Remove(ctx context.Context, kid domain.KeyID, at time.Time) error {
	return r.transition(ctx, kid, `UPDATE kaname.token_signing_keys
		SET state = 'REMOVED', removed_at = $1
		WHERE kid = $2 AND state = 'RETIRED' RETURNING kid`, at)
}

// Compromise объявляет ключ утёкшим: он покидает набор немедленно.
//
// Отдельный глагол, а не ветка вывода из ротации: оператор, выводящий ключ, и
// оператор, объявляющий его утёкшим, принимают решения разной цены.
func (r *SigningKeyRepo) Compromise(ctx context.Context, kid domain.KeyID, at time.Time) error {
	return r.transition(ctx, kid, `UPDATE kaname.token_signing_keys
		SET state = 'COMPROMISED', compromised_at = $1
		WHERE kid = $2 AND state <> 'COMPROMISED' RETURNING kid`, at)
}

func (r *SigningKeyRepo) transition(ctx context.Context, kid domain.KeyID, q string, at time.Time) error {
	var got string
	if err := r.pool.QueryRow(ctx, q, at, string(kid)).Scan(&got); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return fmt.Errorf("%w: SigningKey %s cannot take this transition", iamerr.ErrFailedPrecondition, kid)
		}
		return wrapPgErr(err, "SigningKey", string(kid))
	}
	return nil
}

// rowScanner — общий вид pgx.Row и pgx.Rows для одной функции разбора.
type rowScanner interface{ Scan(dest ...any) error }

func scanSigningKey(row rowScanner) (domain.SigningKeyRecord, error) {
	var (
		rec   domain.SigningKeyRecord
		kid   string
		alg   string
		state string
	)
	err := row.Scan(&kid, &alg, &state, &rec.PublicKeyPEM, &rec.PrivateKeyWrapped,
		&rec.CreatedAt, &rec.NotAfter, &rec.ActivatedAt, &rec.RetiredAt,
		&rec.RemovedAt, &rec.CompromisedAt)
	if err != nil {
		return domain.SigningKeyRecord{}, err
	}
	rec.KID = domain.KeyID(kid)
	rec.Algorithm = domain.SigningAlgorithm(alg)
	rec.State = domain.SigningKeyState(state)
	return rec, nil
}

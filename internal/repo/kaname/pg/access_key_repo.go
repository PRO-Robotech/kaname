// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// access_key_repo.go — адаптер хранилища КЛЮЧЕЙ ДОСТУПА и ИСПЫТАНИЙ их
// церемоний (iam Ф7, PRO-Robotech/kacho#1273; приёмка
// `docs/engineering/acceptance/access-keys-are-ours.md`, Р1, Р6, Р8, Р11).
// Исполняет порты `access_keys.Store` / `access_keys.Writer`.
//
// # Что держит база, а не адаптер
//
//   - уникальность идентификатора удостоверения — ключ уникальности (23505 →
//     ALREADY_EXISTS), Ф7-05/Ф7-15;
//   - слот потолка `iam.user.accessKey` — триггер списания на вставке и возврат
//     на удалении, в той же транзакции (KQ001/KQ002 → отказ учёта), Ф7-37/38;
//   - однократность испытания — ОДИН условный оператор (Ф7-03/Ф7-53);
//   - сдвиг счётчика — ОДИН условный оператор на прежнее значение (Р6, Ф7-20);
//   - «сосчитать способы — снять» — строки человека под замком до конца
//     транзакции (Ф7-26).
//
// Идентификатор удостоверения, открытый ключ и рукоятка хранятся байтами как
// приняты; индекс по идентификатору — сам ключ уникальности: по нему ищет
// проверка утверждения (Ф7-08, Ф7-09).
//
// Рукоятка ЧЕЛОВЕКА (`user_ceremony_handles`, Ф13 Р3) заводится одним
// оператором с разрешением конфликта: «завести, если нет, иначе вернуть то,
// что есть» — исход держит ключ строки, а не сравнение прочитанного (ban #10).

import (
	"context"
	stderrors "errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/access_keys"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// AccessKeyRepo — хранилище ключей и испытаний.
type AccessKeyRepo struct{ pool *pgxpool.Pool }

// NewAccessKeyRepo — построение над пулом.
func NewAccessKeyRepo(pool *pgxpool.Pool) *AccessKeyRepo { return &AccessKeyRepo{pool: pool} }

const accessKeyCols = `id, user_id, credential_id, public_key, algorithm, sign_count, user_handle, name, description, created_at, last_used_at`

func scanAccessKey(row pgx.Row) (domain.AccessKey, error) {
	var (
		k         domain.AccessKey
		signCount int64
		used      *time.Time
	)
	if err := row.Scan(&k.ID, &k.UserID, &k.CredentialID, &k.PublicKey, &k.Algorithm, &signCount, &k.UserHandle,
		&k.Name, &k.Description, &k.CreatedAt, &used); err != nil {
		return domain.AccessKey{}, err
	}
	// Схема держит счётчик в `[0, 2^32-1]`, поэтому сужение без потерь.
	k.SignCount = uint32(signCount) // #nosec G115 -- ограничение схемы user_access_keys_sign_count_check
	k.LastUsedAt = used
	return k, nil
}

// UserOf — человек одним чтением (аккаунт, состояние, адрес, имя).
func (r *AccessKeyRepo) UserOf(ctx context.Context, id domain.UserID) (domain.User, error) {
	if id == "" {
		return domain.User{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument user_id: required")
	}
	var u domain.User
	err := r.pool.QueryRow(ctx, `
		SELECT id, account_id, email, display_name, invite_status, created_at
		  FROM users WHERE id = $1`, string(id)).Scan(&u.ID, &u.AccountID, &u.Email, &u.DisplayName, &u.InviteStatus, &u.CreatedAt)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return domain.User{}, iamerr.Wrapf(iamerr.ErrNotFound, "User %s not found", id)
	}
	if err != nil {
		return domain.User{}, mapErr(err, "AccessKey.UserOf", "")
	}
	return u, nil
}

// KeyByCredentialID — строка по идентификатору удостоверения; found=false —
// строки нет (снятый и никогда не заведённый — одно состояние, Ф13 Р15).
func (r *AccessKeyRepo) KeyByCredentialID(ctx context.Context, credentialID []byte) (domain.AccessKey, bool, error) {
	k, err := scanAccessKey(r.pool.QueryRow(ctx, `SELECT `+accessKeyCols+` FROM user_access_keys WHERE credential_id = $1`, credentialID))
	if stderrors.Is(err, pgx.ErrNoRows) {
		return domain.AccessKey{}, false, nil
	}
	if err != nil {
		return domain.AccessKey{}, false, mapErr(err, "AccessKey.ByCredential", "")
	}
	return k, true, nil
}

// KeyOwnedByID — строка ключа по паре (человек, ключ) для резолвера
// осиротевших операций (регистрация — присутствие, снятие — отсутствие).
// Чужой ключ и несуществующий отвечают одинаково «нет строки» (Ф7-27): по
// идентификатору ключа нельзя узнать, есть ли он у другого человека.
func (r *AccessKeyRepo) KeyOwnedByID(ctx context.Context, userID domain.UserID, id domain.AccessKeyID) (domain.AccessKey, bool, error) {
	k, err := scanAccessKey(r.pool.QueryRow(ctx,
		`SELECT `+accessKeyCols+` FROM user_access_keys WHERE user_id = $1 AND id = $2`, userID, id))
	if stderrors.Is(err, pgx.ErrNoRows) {
		return domain.AccessKey{}, false, nil
	}
	if err != nil {
		return domain.AccessKey{}, false, mapErr(err, "AccessKey.OwnedByID", "")
	}
	return k, true, nil
}

// KeysOf — перечень человека курсором `(created_at, id)`; мусорный курсор и
// величина страницы вне `[0..1000]` — отказ формы, а не молчаливая обрезка.
func (r *AccessKeyRepo) KeysOf(ctx context.Context, userID domain.UserID, pageToken string, pageSize int32) ([]domain.AccessKey, string, error) {
	limit, err := effectivePageSize(pageSize)
	if err != nil {
		return nil, "", err
	}
	var (
		afterTS time.Time
		afterID string
	)
	if pageToken != "" {
		afterTS, afterID, err = decodePageToken(pageToken)
		if err != nil {
			return nil, "", iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument page_token: invalid format")
		}
	}
	rows, err := r.pool.Query(ctx, `
		SELECT `+accessKeyCols+`
		  FROM user_access_keys
		 WHERE user_id = $1 AND (created_at, id) > ($2::timestamptz, $3::text)
		 ORDER BY created_at, id
		 LIMIT $4`, string(userID), afterTS, afterID, limit+1)
	if err != nil {
		return nil, "", mapErr(err, "AccessKey.KeysOf", "")
	}
	defer rows.Close()
	var out []domain.AccessKey
	for rows.Next() {
		k, err := scanAccessKey(rows)
		if err != nil {
			return nil, "", mapErr(err, "AccessKey.KeysOf", "")
		}
		out = append(out, k)
	}
	if err := rows.Err(); err != nil {
		return nil, "", mapErr(err, "AccessKey.KeysOf", "")
	}
	next := ""
	if int64(len(out)) > limit {
		last := out[limit-1]
		next = encodePageToken(last.CreatedAt, string(last.ID))
		out = out[:limit]
	}
	return out, next, nil
}

// CredentialIDsOf — идентификаторы удостоверений человека для `allowCredentials`.
func (r *AccessKeyRepo) CredentialIDsOf(ctx context.Context, userID domain.UserID) ([][]byte, error) {
	rows, err := r.pool.Query(ctx, `SELECT credential_id FROM user_access_keys WHERE user_id = $1 ORDER BY created_at, id`, string(userID))
	if err != nil {
		return nil, mapErr(err, "AccessKey.Credentials", "")
	}
	defer rows.Close()
	var out [][]byte
	for rows.Next() {
		var c []byte
		if err := rows.Scan(&c); err != nil {
			return nil, mapErr(err, "AccessKey.Credentials", "")
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// Challenge — выданное испытание, привязанное к вызывающему и процедуре;
// чужое и невыданное неразличимы — found=false у обоих.
func (r *AccessKeyRepo) Challenge(ctx context.Context, challenge []byte, userID domain.UserID, purpose domain.AccessKeyChallengePurpose) (domain.AccessKeyChallenge, bool, error) {
	var c domain.AccessKeyChallenge
	err := r.pool.QueryRow(ctx, `
		SELECT challenge, user_id, purpose, issued_at, expires_at, consumed_at
		  FROM access_key_challenges
		 WHERE challenge = $1 AND user_id = $2 AND purpose = $3`, challenge, string(userID), string(purpose)).
		Scan(&c.Challenge, &c.UserID, &c.Purpose, &c.IssuedAt, &c.ExpiresAt, &c.ConsumedAt)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return domain.AccessKeyChallenge{}, false, nil
	}
	if err != nil {
		return domain.AccessKeyChallenge{}, false, mapErr(err, "AccessKey.Challenge", "")
	}
	return c, true, nil
}

// SweepUnservableChallenges — уборка (форма Ф-ж): испытания, которые ни одна
// процедура уже не обслужит — истёкшие и предъявленные — старше порога.
// Порог держит различимость трёх состояний отказа регистрации (Ф7-34): пока
// строка хранится, «предъявлено» и «просрочено» отличимы от «не выдавалось».
func (r *AccessKeyRepo) SweepUnservableChallenges(ctx context.Context, grace time.Duration, batch int) (int64, bool, error) {
	if batch <= 0 {
		return 0, false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument batch: must be positive")
	}
	tag, err := r.pool.Exec(ctx, `
		DELETE FROM access_key_challenges
		 WHERE ctid IN (
		       SELECT ctid FROM access_key_challenges
		        WHERE (expires_at <= now() - $1::interval)
		           OR (consumed_at IS NOT NULL AND consumed_at <= now() - $1::interval)
		        LIMIT $2)`, grace, batch)
	if err != nil {
		return 0, false, mapErr(err, "AccessKey.SweepChallenges", "")
	}
	return tag.RowsAffected(), tag.RowsAffected() >= int64(batch), nil
}

// Writer открывает транзакцию записи.
func (r *AccessKeyRepo) Writer(ctx context.Context) (access_keys.Writer, error) {
	tx, err := r.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return nil, mapErr(err, "AccessKey.Writer", "")
	}
	return &accessKeyWriter{tx: tx}, nil
}

// RevokeWriter — транзакция снятия ключа (см. порт): открыта ОТКРЫТИЕМ
// писателя сессии (`beginHumanSessionWriter` — уровень изоляции писателей
// церемонии, перепись `ceremony_writer_openers_test.go`), и ПЕРВЫМ оператором
// взята строка личности замком писателя нескольких сессий
// (`holdPersonForSessionSet`) — раньше строк ключей, которые затем берёт
// `LockKeysOf`. Писатель ключа и писатель сессии — над ОДНОЙ `pgx.Tx`.
func (r *AccessKeyRepo) RevokeWriter(ctx context.Context, userID domain.UserID) (access_keys.RevokeWriter, error) {
	return r.openRevokeWriter(ctx, userID, "AccessKey.RevokeWriter")
}

// openRevokeWriter — открытие транзакции под замком строки личности, общее у
// снятия ключа и сброса ключей: одна дверь, один порядок «личность → дети».
func (r *AccessKeyRepo) openRevokeWriter(ctx context.Context, userID domain.UserID, site string) (*accessKeyRevokeWriter, error) {
	sessions, err := beginHumanSessionWriter(ctx, r.pool)
	if err != nil {
		return nil, mapErr(err, site, "")
	}
	if err := sessions.holdPersonForSessionSet(ctx, userID); err != nil {
		_ = sessions.tx.Rollback(ctx)
		return nil, err
	}
	return &accessKeyRevokeWriter{accessKeyWriter: accessKeyWriter{tx: sessions.tx}, sessions: sessions}, nil
}

// AccessKeysResetTx — транзакция СБРОСА ключей человека администратором облака
// (kaname#638; приёмка `cloud-administrator-resets-login-methods.md`, Р3, Р5,
// Р7): та же дверь, что у снятия ключа, — открытие писателем сессии и строка
// личности под замком ПЕРВЫМ оператором, — и два своих оператора. Исполняет
// порт `user.AccessKeysResetWriter` (соответствие закрепляет корень композиции).
//
// # Порядок операторов — несущий (Р7)
//
// Испытания регистрации снимаются РАНЬШЕ строк ключей. Регистрация потребляет
// испытание условным оператором (`ConsumeChallenge`) и вставляет строку ключа
// той же транзакцией. Если её потребление стоит раньше снятия испытаний,
// снятие ждёт её фиксации и строку, уже потреблённую, не трогает
// (`consumed_at IS NULL` перепроверяется после ожидания); следующий оператор —
// снятие ключей — исполняется новым снимком (`read committed` писателя сессии)
// и видит зафиксированную строку ключа. Если раньше стоит снятие испытаний, то
// потребление ждёт фиксации сброса и находит ноль строк — регистрация
// отказывает. В обоих порядках строки ключа после обоих исходов нет; проверки
// «прочитать — решить» нет ни на одной стороне (ban #10).
type AccessKeysResetTx struct{ *accessKeyRevokeWriter }

// AccessKeysResetWriter — см. [AccessKeysResetTx].
func (r *AccessKeyRepo) AccessKeysResetWriter(ctx context.Context, userID domain.UserID) (*AccessKeysResetTx, error) {
	w, err := r.openRevokeWriter(ctx, userID, "AccessKey.ResetWriter")
	if err != nil {
		return nil, err
	}
	return &AccessKeysResetTx{accessKeyRevokeWriter: w}, nil
}

// RetireRegistrationChallenges — выданные и не предъявленные испытания
// регистрации человека сняты одним оператором; строки, потреблённые
// регистрацией, остаются — их предмет уже исполнен, и уборка снимет их сроком.
func (w *AccessKeysResetTx) RetireRegistrationChallenges(ctx context.Context, userID domain.UserID) (int64, error) {
	if userID == "" {
		return 0, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument user_id: required")
	}
	tag, err := w.tx.Exec(ctx, `
		DELETE FROM access_key_challenges
		 WHERE user_id = $1 AND purpose = $2 AND consumed_at IS NULL`, string(userID), string(domain.ChallengeForRegistration))
	if err != nil {
		return 0, mapErr(err, "AccessKey.RetireRegistrationChallenges", "")
	}
	return tag.RowsAffected(), nil
}

// DeleteAccessKeysOf — все строки ключей человека одним оператором; слоты
// потолка возвращает триггер на удалении в той же транзакции.
func (w *AccessKeysResetTx) DeleteAccessKeysOf(ctx context.Context, userID domain.UserID) (int64, error) {
	if userID == "" {
		return 0, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument user_id: required")
	}
	tag, err := w.tx.Exec(ctx, `DELETE FROM user_access_keys WHERE user_id = $1`, string(userID))
	if err != nil {
		return 0, mapErr(err, "AccessKey.DeleteAllOf", "")
	}
	return tag.RowsAffected(), nil
}

type accessKeyWriter struct{ tx pgx.Tx }

// accessKeyRevokeWriter — писатель ключа и писатель сессии над одной
// транзакцией: записи сессии снимает ДВЕРЬ писателя сессии
// (`EndOtherSessions` → `endSessionsAndRevokeWhatTheyHold`), а не свой
// оператор — снятие без отзыва выданного было бы половиной действия.
type accessKeyRevokeWriter struct {
	accessKeyWriter
	sessions *humanSessionWriter
}

// EndOtherSessions — см. порт; пустой `keep` не равен ни одному
// идентификатору, исключать ему нечего.
func (w *accessKeyRevokeWriter) EndOtherSessions(ctx context.Context, userID domain.UserID, keep domain.HumanSessionID, at time.Time, reason string) (int, error) {
	return w.sessions.EndOtherSessions(ctx, userID, keep, at, reason)
}

// sessionOfFamilySQL — сессия церемонии семейства $1, если семейство
// принадлежит личности $2: выпуск ЧУЖОЙ личности не отвечает ничем.
const sessionOfFamilySQL = `SELECT session_id FROM kaname.token_families WHERE id = $1 AND user_id = $2`

// SessionOfCredential — см. порт.
func (w *accessKeyRevokeWriter) SessionOfCredential(ctx context.Context, userID domain.UserID, credentialID string) (domain.HumanSessionID, bool, error) {
	// Выпуск → семейство — единственным читателем записи выпуска
	// (`issuanceOf`); семейство → сессия — строкой семейства.
	iss, found, err := issuanceOf(ctx, w.tx, credentialID)
	if err != nil || !found {
		return "", false, err
	}
	var id string
	err = w.tx.QueryRow(ctx, sessionOfFamilySQL, iss.familyID, string(userID)).Scan(&id)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return "", false, nil
	}
	if err != nil {
		return "", false, mapErr(err, "AccessKey.SessionOfCredential", "")
	}
	return domain.HumanSessionID(id), true, nil
}

// FirstAuthentication — см. порт.
func (w *accessKeyRevokeWriter) FirstAuthentication(ctx context.Context, userID domain.UserID) (time.Time, bool, error) {
	return w.sessions.FirstAuthentication(ctx, userID)
}

// UpsertCutoff — см. порт.
func (w *accessKeyRevokeWriter) UpsertCutoff(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error {
	return w.sessions.UpsertCutoff(ctx, u, revokedBy)
}

func (w *accessKeyWriter) InsertChallenge(ctx context.Context, c domain.AccessKeyChallenge) error {
	if err := c.Validate(); err != nil {
		return iamerr.Wrapf(iamerr.ErrInvalidArg, "%v", err)
	}
	_, err := w.tx.Exec(ctx, `
		INSERT INTO access_key_challenges (challenge, user_id, purpose, issued_at, expires_at)
		VALUES ($1, $2, $3, $4, $5)`, c.Challenge, string(c.UserID), string(c.Purpose), c.IssuedAt, c.ExpiresAt)
	if err != nil {
		return mapErr(err, "AccessKey.InsertChallenge", "")
	}
	return nil
}

// EnsureCeremonyHandle — рукоятка человека ОДНИМ оператором. `DO UPDATE` с
// присваиванием того же ключа значения не меняет, но делает существующую
// строку видимой `RETURNING`: без него проигравший конкуренцию получил бы ноль
// строк там, где ответ уже есть. Смены значения нет и быть не может —
// рукоятка уже лежит в аутентификаторе держателя.
func (w *accessKeyWriter) EnsureCeremonyHandle(ctx context.Context, userID domain.UserID, minted domain.CeremonyHandle) (domain.CeremonyHandle, error) {
	if userID == "" {
		return domain.CeremonyHandle{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument user_id: required")
	}
	if err := minted.Validate(); err != nil {
		return domain.CeremonyHandle{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "%v", err)
	}
	var stored []byte
	err := w.tx.QueryRow(ctx, `
		INSERT INTO user_ceremony_handles (user_id, handle)
		VALUES ($1, $2)
		ON CONFLICT (user_id) DO UPDATE SET user_id = EXCLUDED.user_id
		RETURNING handle`, string(userID), minted.Bytes()).Scan(&stored)
	if err != nil {
		return domain.CeremonyHandle{}, mapErr(err, "AccessKey.EnsureCeremonyHandle", "")
	}
	handle, err := domain.RestoreCeremonyHandle(stored)
	if err != nil {
		return domain.CeremonyHandle{}, iamerr.Wrapf(iamerr.ErrInternal, "stored ceremony handle: %v", err)
	}
	return handle, nil
}

// ConsumeChallenge — ОДИН оператор однократности: строка вызывающего этой
// процедуры, не потреблённая и не истёкшая на now, получает отметку.
func (w *accessKeyWriter) ConsumeChallenge(ctx context.Context, challenge []byte, userID domain.UserID, purpose domain.AccessKeyChallengePurpose, now time.Time) (bool, error) {
	tag, err := w.tx.Exec(ctx, `
		UPDATE access_key_challenges
		   SET consumed_at = $4
		 WHERE challenge = $1 AND user_id = $2 AND purpose = $3
		   AND consumed_at IS NULL AND expires_at > $4`, challenge, string(userID), string(purpose), now)
	if err != nil {
		return false, mapErr(err, "AccessKey.ConsumeChallenge", "")
	}
	return tag.RowsAffected() == 1, nil
}

// InsertKey — строка ключа; уникальность и слот держит база.
func (w *accessKeyWriter) InsertKey(ctx context.Context, k domain.AccessKey) (domain.AccessKey, error) {
	if err := k.Validate(); err != nil {
		return domain.AccessKey{}, iamerr.Wrapf(iamerr.ErrInvalidArg, "%v", err)
	}
	var handle []byte
	if len(k.UserHandle) > 0 {
		handle = k.UserHandle
	}
	row := w.tx.QueryRow(ctx, `
		INSERT INTO user_access_keys (id, user_id, credential_id, public_key, algorithm, sign_count, user_handle, name, description, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
		RETURNING `+accessKeyCols,
		string(k.ID), string(k.UserID), k.CredentialID, k.PublicKey, k.Algorithm, int64(k.SignCount), handle,
		string(k.Name), string(k.Description), k.CreatedAt)
	got, err := scanAccessKey(row)
	if err != nil {
		return domain.AccessKey{}, mapErr(err, "AccessKey.Insert", "")
	}
	return got, nil
}

// LockKeysOf — строки человека под замком до конца транзакции.
func (w *accessKeyWriter) LockKeysOf(ctx context.Context, userID domain.UserID) ([]domain.AccessKey, error) {
	rows, err := w.tx.Query(ctx, `SELECT `+accessKeyCols+` FROM user_access_keys WHERE user_id = $1 ORDER BY created_at, id FOR UPDATE`, string(userID))
	if err != nil {
		return nil, mapErr(err, "AccessKey.Lock", "")
	}
	defer rows.Close()
	var out []domain.AccessKey
	for rows.Next() {
		k, err := scanAccessKey(rows)
		if err != nil {
			return nil, mapErr(err, "AccessKey.Lock", "")
		}
		out = append(out, k)
	}
	return out, rows.Err()
}

// DeleteOwnedByID — ОДИН оператор, суженный владельцем: чужой и несуществующий
// дают ноль строк одинаково (Ф7-27). Слот возвращает триггер.
func (w *accessKeyWriter) DeleteOwnedByID(ctx context.Context, userID domain.UserID, id domain.AccessKeyID) (domain.AccessKey, bool, error) {
	k, err := scanAccessKey(w.tx.QueryRow(ctx, `
		DELETE FROM user_access_keys WHERE user_id = $1 AND id = $2 RETURNING `+accessKeyCols, string(userID), string(id)))
	if stderrors.Is(err, pgx.ErrNoRows) {
		return domain.AccessKey{}, false, nil
	}
	if err != nil {
		return domain.AccessKey{}, false, mapErr(err, "AccessKey.Delete", "")
	}
	return k, true, nil
}

// AdvanceSignCount — атомарный сдвиг с условием на прежнее значение (Р6):
// проигравший конкуренции получает ноль строк. При `0 → 0` двигается только
// момент предъявления (ноль не судится, Ф7-19).
func (w *accessKeyWriter) AdvanceSignCount(ctx context.Context, id domain.AccessKeyID, expected, reported uint32, usedAt time.Time) (bool, error) {
	var (
		tag interface{ RowsAffected() int64 }
		err error
	)
	if expected == 0 && reported == 0 {
		tag, err = w.tx.Exec(ctx, `UPDATE user_access_keys SET last_used_at = $2 WHERE id = $1 AND sign_count = 0`, string(id), usedAt)
	} else {
		tag, err = w.tx.Exec(ctx, `
			UPDATE user_access_keys SET sign_count = $3, last_used_at = $4
			 WHERE id = $1 AND sign_count = $2 AND $3 > sign_count`, string(id), int64(expected), int64(reported), usedAt)
	}
	if err != nil {
		return false, mapErr(err, "AccessKey.Advance", "")
	}
	return tag.RowsAffected() == 1, nil
}

func (w *accessKeyWriter) EmitAudit(ctx context.Context, ev outboxtypes.AuditEvent) error {
	return insertAuditEventTx(ctx, w.tx, ev)
}

func (w *accessKeyWriter) Commit(ctx context.Context) error {
	if err := w.tx.Commit(ctx); err != nil {
		return mapErr(err, "", "")
	}
	return nil
}

func (w *accessKeyWriter) Rollback(ctx context.Context) error {
	err := w.tx.Rollback(ctx)
	if err != nil && !stderrors.Is(err, pgx.ErrTxClosed) {
		return mapErr(err, "", "")
	}
	return nil
}

// HumanSessionFreshness — порт свежести над хранилищем сессий: самое свежее
// предъявление среди ЖИВЫХ сессий человека (граница названа у порта).
type HumanSessionFreshness struct{ pool *pgxpool.Pool }

// NewHumanSessionFreshness — построение над пулом.
func NewHumanSessionFreshness(pool *pgxpool.Pool) *HumanSessionFreshness {
	return &HumanSessionFreshness{pool: pool}
}

// LastPresentedAt — max(last_presented_at) по живым сессиям; found=false —
// живых сессий нет.
func (f *HumanSessionFreshness) LastPresentedAt(ctx context.Context, userID domain.UserID) (time.Time, bool, error) {
	var at *time.Time
	err := f.pool.QueryRow(ctx, `
		SELECT max(last_presented_at) FROM human_sessions
		 WHERE user_id = $1 AND ended_at IS NULL AND expires_at > now()`, string(userID)).Scan(&at)
	if err != nil {
		return time.Time{}, false, mapErr(err, "AccessKey.Freshness", "")
	}
	if at == nil {
		return time.Time{}, false, nil
	}
	return at.UTC(), true, nil
}

// HasPassword — есть ли у человека способ входа паролем (порт
// `access_keys.LoginMethods` над хранилищем способов).
func (r *LoginMethodRepo) HasPassword(ctx context.Context, userID domain.UserID) (bool, error) {
	_, err := r.Get(ctx, userID, domain.LoginMethodPassword)
	if err == nil {
		return true, nil
	}
	if stderrors.Is(err, iamerr.ErrNotFound) {
		return false, nil
	}
	return false, err
}

// accessKeyEnrolled — есть ли у человека хоть одна строка ключа доступа. Один
// оператор на оба носителя чтения — пул (`LoginMethodRepo.AccessKeyEnrolled`)
// и транзакцию записи сессии (`humanSessionWriter.AccessKeyEnrolled`): таблицу
// ключей называет только этот файл.
func accessKeyEnrolled(ctx context.Context, q loginMethodQuerier, userID domain.UserID) (bool, error) {
	if userID == "" {
		return false, iamerr.Wrapf(iamerr.ErrInvalidArg, "Illegal argument user_id: required")
	}
	var has bool
	if err := q.QueryRow(ctx, `SELECT EXISTS (SELECT 1 FROM user_access_keys WHERE user_id = $1)`, string(userID)).Scan(&has); err != nil {
		return false, mapErr(err, "AccessKey.Enrolled", string(userID))
	}
	return has, nil
}

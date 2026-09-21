// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// oauth_ceremony_repo.go — слой доступа СОБСТВЕННОЙ ЦЕРЕМОНИИ OAuth: код
// авторизации, семейство выданного по нему, обновляющий токен и согласие
// субъекта (задача PRO-Robotech/kaname#313; миграции
// `20260920175117_authorization_code_is_our_record.sql`,
// `20260920175118_interactive_client_carries_its_secret_verifier.sql`,
// `20260920175119_consent_is_our_record.sql`).
//
// # ОДНА ИНСТРУКЦИЯ — ЭТО ИНВАРИАНТ, А НЕ АККУРАТНОСТЬ
//
// «Жив ли код» и «погасить его» здесь НЕДЕЛИМЫ, и неделимыми их делает сам
// движок: условие на ПРЕЖНЕЕ состояние стоит в `WHERE` того же `UPDATE`,
// который пишет новое, и строчный замок держит обоих. Пара «SELECT, потом
// UPDATE» была бы ровно тем check-then-act, который запрещает ban #10: две
// одновременные копии запроса промахнулись бы обе мимо чужой ещё не
// зафиксированной записи и выдали бы по одному коду ДВА набора токенов.
//
// Дефект этот НЕЗАМЕТЕН по положительному пути: последовательный прогон такой
// реализации зелен целиком. Отличает её только проба с конкурирующими
// транзакциями — `oauth_ceremony_race_integration_test.go`.
//
// # НОЛЬ ЗАТРОНУТЫХ СТРОК — ЭТО ТРИ РАЗНЫХ ИСХОДА, А НЕ ОДИН
//
// Ноль строк означает, что условие не выполнилось; ПОЧЕМУ — говорит разбор,
// идущий ПОСЛЕ отката транзакции выдачи:
//
//   - строки нет вовсе → `domain.ErrAuthorizationCodeUnknown`;
//   - строка есть и НЕАКТИВНА → ПОВТОР. Кодом уже воспользовались, второй
//     предъявитель — либо похититель, либо тот, у кого похитили, и различить их
//     нельзя. Поэтому отзывается ВСЁ семейство (RFC 6819 §5.2.1.1);
//   - строка активна, но срок вышел → истечение. Отзыва не влечёт: это не
//     признак похищения.
//
// Ради этого различения использованный код и отротированный токен ПОМЕЧАЮТСЯ
// неактивными и ЖИВУТ до истечения. Удалить строку значило бы сделать повтор
// неотличимым от неизвестного кода — то есть снять отзыв семейства с
// единственного признака, по которому похищение вообще наблюдаемо.
//
// # ЧТО ДЕРЖИТ БАЗА, А НЕ ЭТОТ ФАЙЛ
//
//   - неделимость обмена и ротации — условный `UPDATE … RETURNING`;
//   - согласие контекста церемонии между семейством, кодом и токеном —
//     СОСТАВНОЙ внешний ключ по четырём столбцам сразу;
//   - «одно поколение на номер в семействе» — `refresh_tokens_generation_uk`;
//   - «одно согласие на тройку субъект-клиент-область» —
//     `consent_grants_subject_client_scope_uk`;
//   - форма свёрток, испытания PKCE и словари причин — ограничения схемы.

import (
	"context"
	stderrors "errors"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// consentIDPrefix — префикс идентификатора согласия; форма закрыта
// ограничением `consent_grants_id_form_ck`.
const consentIDPrefix = "cg"

// refuseNoSuchClient — ЕДИНСТВЕННЫЙ производитель отказа «интерактивного
// клиента с таким идентификатором в реестре нет».
//
// Отказ несёт ПРИЗНАК `iamerr.ErrNotFound`, а не только текст. Причина
// прикладная: снятие клиента идёт ПОСЛЕ удаления его строки, поэтому
// «строки нет» — ожидаемое состояние, а не неполадка, и отличить его от
// неполадки хранилища вызывающий обязан машинно. Разбор прозы вместо признака
// сделал бы идемпотентность снятия зависящей от формулировки.
func refuseNoSuchClient(clientID string) error {
	return iamerr.Wrapf(iamerr.ErrNotFound, "interactive client %s: not found", clientID)
}

// OAuthCeremonyRepo — хранилище собственной церемонии.
type OAuthCeremonyRepo struct{ pool *pgxpool.Pool }

// NewOAuthCeremonyRepo — построение над пулом.
func NewOAuthCeremonyRepo(pool *pgxpool.Pool) *OAuthCeremonyRepo {
	return &OAuthCeremonyRepo{pool: pool}
}

// NewAuthorizationCode — что нужно знать, чтобы завести код и его семейство.
type NewAuthorizationCode struct {
	Context             domain.CeremonyContext
	CodeDigest          string
	RedirectURI         string
	CodeChallenge       string
	CodeChallengeMethod string
	// TTL — срок жизни кода. Приходит ВХОДОМ, а не константой этого файла: у
	// величины нет владельца в слое доступа, и копия разошлась бы с политикой.
	TTL time.Duration
}

// CodeExchange — предъявление кода к обмену вместе со свёрткой обновляющего
// токена, который встанет в семейство ПЕРВЫМ поколением.
//
// Свёртка преемника приходит ВХОДОМ, а не чеканится здесь: сам токен уходит
// вызывающему, и слой доступа его не видит — он видит только свёртку.
type CodeExchange struct {
	CodeDigest         string
	RefreshTokenDigest string
	RefreshTokenTTL    time.Duration
}

// RefreshRotation — предъявление обновляющего токена к ротации.
type RefreshRotation struct {
	PresentedDigest string
	SuccessorDigest string
	TTL             time.Duration
}

// IssueAuthorizationCode заводит семейство и его код ОДНОЙ транзакцией.
//
// Одной, а не двумя: семейство без кода — сирота, которую не обменяет никто и
// не уберёт ничто, а код без семейства схема попросту отвергает составным
// ключом. Промежуточного состояния, наблюдаемого читателем, здесь не бывает.
func (r *OAuthCeremonyRepo) IssueAuthorizationCode(ctx context.Context, in NewAuthorizationCode) error {
	if err := in.Context.Validate(); err != nil {
		return err
	}
	if err := domain.ValidateCeremonyDigest("authorization_code.code_digest", in.CodeDigest); err != nil {
		return err
	}
	if err := domain.ValidatePKCEChallenge(in.CodeChallenge, in.CodeChallengeMethod); err != nil {
		return err
	}
	if in.RedirectURI == "" {
		return fmt.Errorf("Illegal argument authorization_code.redirect_uri: required")
	}
	if in.TTL <= 0 {
		return fmt.Errorf("Illegal argument authorization_code.ttl: must be positive")
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return wrapPgErr(err, "AuthorizationCode", in.Context.FamilyID)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err = tx.Exec(ctx, `
		INSERT INTO kaname.token_families (id, client_id, user_id, session_id, scope)
		VALUES ($1,$2,$3,$4,$5)`,
		in.Context.FamilyID, in.Context.ClientID, in.Context.UserID,
		in.Context.SessionID, in.Context.Scope); err != nil {
		return wrapPgErr(err, "TokenFamily", in.Context.FamilyID)
	}
	if _, err = tx.Exec(ctx, `
		INSERT INTO kaname.authorization_codes
		       (code_digest, family_id, client_id, user_id, session_id, scope, redirect_uri,
		        code_challenge, code_challenge_method, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9, now() + make_interval(secs => $10))`,
		in.CodeDigest, in.Context.FamilyID, in.Context.ClientID, in.Context.UserID,
		in.Context.SessionID, in.Context.Scope, in.RedirectURI,
		in.CodeChallenge, in.CodeChallengeMethod, in.TTL.Seconds()); err != nil {
		return wrapPgErr(err, "AuthorizationCode", in.Context.FamilyID)
	}
	if err = tx.Commit(ctx); err != nil {
		return wrapPgErr(err, "AuthorizationCode", in.Context.FamilyID)
	}
	return nil
}

// exchangeCodeSQL — ТОТ САМЫЙ оператор: условие на прежнее состояние и возврат
// затронутой строки. Стоит ОДНОЙ константой: второе написание разошлось бы с
// первым молча, а разойтись ему есть куда — условие здесь и есть инвариант.
const exchangeCodeSQL = `
UPDATE kaname.authorization_codes AS c
   SET active = false, deactivated_at = now(), deactivated_reason = 'redeemed'
 WHERE c.code_digest = $1
   AND c.active
   AND c.expires_at > now()
   AND NOT EXISTS (SELECT 1 FROM kaname.token_families f
                    WHERE f.id = c.family_id AND f.revoked_at IS NOT NULL)
RETURNING c.family_id, c.client_id, c.user_id, c.session_id, c.scope,
          c.redirect_uri, c.code_challenge, c.code_challenge_method`

// ExchangeAuthorizationCode обменивает код на первое поколение обновляющего
// токена семейства.
//
// Гашение и выдача идут ОДНОЙ транзакцией: ноль затронутых строк означает
// откат ВСЕЙ транзакции выдачи — токена в семействе не появляется. Разбор
// причины идёт ПОСЛЕ отката, по пулу: откаченная транзакция читать уже не
// вправе, а держать её открытой ради разбора значило бы держать замок на время
// разбора.
func (r *OAuthCeremonyRepo) ExchangeAuthorizationCode(ctx context.Context, in CodeExchange) (domain.RedeemedCode, error) {
	if err := domain.ValidateCeremonyDigest("authorization_code.code_digest", in.CodeDigest); err != nil {
		return domain.RedeemedCode{}, err
	}
	if err := domain.ValidateCeremonyDigest("refresh_token.token_digest", in.RefreshTokenDigest); err != nil {
		return domain.RedeemedCode{}, err
	}
	if in.RefreshTokenTTL <= 0 {
		return domain.RedeemedCode{}, fmt.Errorf("Illegal argument refresh_token.ttl: must be positive")
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.RedeemedCode{}, wrapPgErr(err, "AuthorizationCode", "")
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var out domain.RedeemedCode
	err = tx.QueryRow(ctx, exchangeCodeSQL, in.CodeDigest).Scan(
		&out.Context.FamilyID, &out.Context.ClientID, &out.Context.UserID,
		&out.Context.SessionID, &out.Context.Scope,
		&out.RedirectURI, &out.CodeChallenge, &out.CodeChallengeMethod)
	if stderrors.Is(err, pgx.ErrNoRows) {
		// Транзакция выдачи откачена ЗДЕСЬ, до разбора: разбор идёт по пулу.
		_ = tx.Rollback(ctx)
		return domain.RedeemedCode{}, r.refuseCode(ctx, in.CodeDigest)
	}
	if err != nil {
		return domain.RedeemedCode{}, wrapPgErr(err, "AuthorizationCode", "")
	}

	if _, err = tx.Exec(ctx, `
		INSERT INTO kaname.refresh_tokens
		       (token_digest, family_id, client_id, user_id, session_id, scope, generation, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,0, now() + make_interval(secs => $7))`,
		in.RefreshTokenDigest, out.Context.FamilyID, out.Context.ClientID, out.Context.UserID,
		out.Context.SessionID, out.Context.Scope, in.RefreshTokenTTL.Seconds()); err != nil {
		return domain.RedeemedCode{}, wrapPgErr(err, "RefreshToken", out.Context.FamilyID)
	}
	if err = tx.Commit(ctx); err != nil {
		return domain.RedeemedCode{}, wrapPgErr(err, "AuthorizationCode", out.Context.FamilyID)
	}
	return out, nil
}

// refuseCode называет ПРИЧИНУ, по которой условие обмена не выполнилось, и —
// если это ПОВТОР — отзывает всё семейство.
//
// Корзины «прочее» у разбора нет: строка либо отсутствует, либо неактивна,
// либо истекла, либо её семейство отозвано. Четвёртого исхода на сегодняшней
// схеме не существует, и пятый означал бы, что условие обмена и этот разбор
// разошлись — поэтому он отдельный ГРОМКИЙ отказ, а не тихое «повтор».
func (r *OAuthCeremonyRepo) refuseCode(ctx context.Context, digest string) error {
	var (
		active        bool
		expired       bool
		familyID      string
		familyRevoked bool
	)
	err := r.pool.QueryRow(ctx, `
		SELECT c.active, c.expires_at <= now(), c.family_id, f.revoked_at IS NOT NULL
		  FROM kaname.authorization_codes c
		  JOIN kaname.token_families f ON f.id = c.family_id
		 WHERE c.code_digest = $1`, digest).Scan(&active, &expired, &familyID, &familyRevoked)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: digest not found", domain.ErrAuthorizationCodeUnknown)
	}
	if err != nil {
		return wrapPgErr(err, "AuthorizationCode", "")
	}
	switch {
	case !active:
		// ПОВТОР. Отзыв семейства — следствие, неотделимое от решения: вернуть
		// «повтор», не отозвав, значило бы объявить похищение и ничего по нему
		// не сделать.
		if rErr := r.RevokeFamily(ctx, familyID, domain.FamilyRevokedByCodeReplay); rErr != nil {
			return fmt.Errorf("authorization code replay on family %s: revoking the family: %w", familyID, rErr)
		}
		return fmt.Errorf("%w: family %s revoked", domain.ErrAuthorizationCodeReplayed, familyID)
	case familyRevoked:
		return fmt.Errorf("%w: family %s", domain.ErrTokenFamilyRevoked, familyID)
	case expired:
		return fmt.Errorf("%w: family %s", domain.ErrAuthorizationCodeExpired, familyID)
	default:
		return fmt.Errorf("authorization code %s: exchange affected no row while the row is live, "+
			"unexpired and its family is not revoked — the exchange condition and this "+
			"adjudication have diverged", familyID)
	}
}

// rotateRefreshSQL — ТОТ ЖЕ механизм, что у обмена кода: условие на прежнее
// состояние и возврат затронутой строки.
const rotateRefreshSQL = `
UPDATE kaname.refresh_tokens AS t
   SET active = false, deactivated_at = now(), deactivated_reason = 'rotated',
       successor_digest = $2
 WHERE t.token_digest = $1
   AND t.active
   AND t.expires_at > now()
   AND NOT EXISTS (SELECT 1 FROM kaname.token_families f
                    WHERE f.id = t.family_id AND f.revoked_at IS NOT NULL)
RETURNING t.family_id, t.client_id, t.user_id, t.session_id, t.scope, t.generation`

// RotateRefreshToken ротирует обновляющий токен: предъявленный помечается
// отротированным, преемник встаёт следующим поколением — ОДНОЙ транзакцией.
func (r *OAuthCeremonyRepo) RotateRefreshToken(ctx context.Context, in RefreshRotation) (domain.RotatedRefreshToken, error) {
	if err := domain.ValidateCeremonyDigest("refresh_token.token_digest", in.PresentedDigest); err != nil {
		return domain.RotatedRefreshToken{}, err
	}
	if err := domain.ValidateCeremonyDigest("refresh_token.successor_digest", in.SuccessorDigest); err != nil {
		return domain.RotatedRefreshToken{}, err
	}
	if in.PresentedDigest == in.SuccessorDigest {
		return domain.RotatedRefreshToken{}, fmt.Errorf(
			"Illegal argument refresh_token.successor_digest: must differ from the presented one")
	}
	if in.TTL <= 0 {
		return domain.RotatedRefreshToken{}, fmt.Errorf("Illegal argument refresh_token.ttl: must be positive")
	}

	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return domain.RotatedRefreshToken{}, wrapPgErr(err, "RefreshToken", "")
	}
	defer func() { _ = tx.Rollback(ctx) }()

	var out domain.RotatedRefreshToken
	err = tx.QueryRow(ctx, rotateRefreshSQL, in.PresentedDigest, in.SuccessorDigest).Scan(
		&out.Context.FamilyID, &out.Context.ClientID, &out.Context.UserID,
		&out.Context.SessionID, &out.Context.Scope, &out.Generation)
	if stderrors.Is(err, pgx.ErrNoRows) {
		_ = tx.Rollback(ctx)
		return domain.RotatedRefreshToken{}, r.refuseRefresh(ctx, in.PresentedDigest)
	}
	if err != nil {
		return domain.RotatedRefreshToken{}, wrapPgErr(err, "RefreshToken", "")
	}

	if _, err = tx.Exec(ctx, `
		INSERT INTO kaname.refresh_tokens
		       (token_digest, family_id, client_id, user_id, session_id, scope, generation, expires_at)
		VALUES ($1,$2,$3,$4,$5,$6,$7, now() + make_interval(secs => $8))`,
		in.SuccessorDigest, out.Context.FamilyID, out.Context.ClientID, out.Context.UserID,
		out.Context.SessionID, out.Context.Scope, out.Generation+1, in.TTL.Seconds()); err != nil {
		return domain.RotatedRefreshToken{}, wrapPgErr(err, "RefreshToken", out.Context.FamilyID)
	}
	if err = tx.Commit(ctx); err != nil {
		return domain.RotatedRefreshToken{}, wrapPgErr(err, "RefreshToken", out.Context.FamilyID)
	}
	out.Generation++
	return out, nil
}

// refuseRefresh — разбор нуля затронутых строк ротации, тот же по устройству,
// что и у обмена кода.
func (r *OAuthCeremonyRepo) refuseRefresh(ctx context.Context, digest string) error {
	var (
		active        bool
		expired       bool
		familyID      string
		familyRevoked bool
	)
	err := r.pool.QueryRow(ctx, `
		SELECT t.active, t.expires_at <= now(), t.family_id, f.revoked_at IS NOT NULL
		  FROM kaname.refresh_tokens t
		  JOIN kaname.token_families f ON f.id = t.family_id
		 WHERE t.token_digest = $1`, digest).Scan(&active, &expired, &familyID, &familyRevoked)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return fmt.Errorf("%w: digest not found", domain.ErrRefreshTokenUnknown)
	}
	if err != nil {
		return wrapPgErr(err, "RefreshToken", "")
	}
	switch {
	case !active:
		if rErr := r.RevokeFamily(ctx, familyID, domain.FamilyRevokedByRefreshReplay); rErr != nil {
			return fmt.Errorf("refresh token replay on family %s: revoking the family: %w", familyID, rErr)
		}
		return fmt.Errorf("%w: family %s revoked", domain.ErrRefreshTokenReplayed, familyID)
	case familyRevoked:
		return fmt.Errorf("%w: family %s", domain.ErrTokenFamilyRevoked, familyID)
	case expired:
		return fmt.Errorf("%w: family %s", domain.ErrRefreshTokenExpired, familyID)
	default:
		return fmt.Errorf("refresh token of family %s: rotation affected no row while the row is "+
			"live, unexpired and its family is not revoked — the rotation condition and this "+
			"adjudication have diverged", familyID)
	}
}

// RevokeFamily отзывает семейство целиком ОДНОЙ транзакцией: отметка на
// семействе и снятие всего живого, что по нему выдано.
//
// Отзыв ИДЕМПОТЕНТЕН: условие `revoked_at IS NULL` делает повторный отзыв
// пустым, а не вторым. Два одновременных обнаружения повтора — обычное дело
// (проигравших гонку больше одного), и второй из них не вправе ни отказать, ни
// переписать причину первого.
func (r *OAuthCeremonyRepo) RevokeFamily(ctx context.Context, familyID string, reason domain.FamilyRevocationReason) error {
	if familyID == "" {
		return fmt.Errorf("Illegal argument token_family.id: required")
	}
	if err := reason.Validate(); err != nil {
		return err
	}
	tx, err := r.pool.Begin(ctx)
	if err != nil {
		return wrapPgErr(err, "TokenFamily", familyID)
	}
	defer func() { _ = tx.Rollback(ctx) }()

	if _, err = tx.Exec(ctx, `
		UPDATE kaname.token_families
		   SET revoked_at = now(), revoked_reason = $2
		 WHERE id = $1 AND revoked_at IS NULL`, familyID, string(reason)); err != nil {
		return wrapPgErr(err, "TokenFamily", familyID)
	}
	// Снятие идёт по ЖИВЫМ строкам: уже снятую отметку — и её причину — второй
	// отзыв не переписывает.
	if _, err = tx.Exec(ctx, `
		UPDATE kaname.authorization_codes
		   SET active = false, deactivated_at = now(), deactivated_reason = 'family-revoked'
		 WHERE family_id = $1 AND active`, familyID); err != nil {
		return wrapPgErr(err, "AuthorizationCode", familyID)
	}
	if _, err = tx.Exec(ctx, `
		UPDATE kaname.refresh_tokens
		   SET active = false, deactivated_at = now(), deactivated_reason = 'family-revoked'
		 WHERE family_id = $1 AND active`, familyID); err != nil {
		return wrapPgErr(err, "RefreshToken", familyID)
	}
	if err = tx.Commit(ctx); err != nil {
		return wrapPgErr(err, "TokenFamily", familyID)
	}
	return nil
}

// revokeFamiliesOfSessionsTx отзывает семейства, привязанные к НАЗВАННЫМ
// сессиям, — в транзакции вызывающего.
//
// # ПОЧЕМУ ЭТОТ ПИСАТЕЛЬ ОБЯЗАН СУЩЕСТВОВАТЬ
//
// Привязка семейства к сессии есть внешний ключ с каскадом НА УДАЛЕНИИ строки.
// Снятие сессии строку не удаляет — оно ставит отметку, а удаляет строку уборка
// спустя порог удержания. Значит без этого писателя обновляющий токен снятой
// сессии живёт и ротируется в свежие, а окно равно величине УДЕРЖАНИЯ, то есть
// настройке хранения, а не решению о безопасности.
//
// Словарь причин отзыва объявлен ЗАКРЫТЫМ, и до этой полосы у четырёх его
// значений не было ни одного писателя. Объявленная возможность, которой никто
// не исполняет, — долг, а не будущее: она читается как работающая и не
// работает ни при каком входе.
//
// # ПОРЯДОК ОПЕРАТОРОВ НЕСУЩИЙ
//
// Семейства выбираются ПЕРВЫМИ и по ним же снимается выданное: пометь мы
// семейства раньше, чем выберем их, условие живости опустошило бы выборку — и
// коды с токенами остались бы живыми при отозванном семействе.
//
// # ИДЕМПОТЕНТНОСТЬ — УСЛОВИЕМ, А НЕ ПРОВЕРКОЙ
//
// Уже снятую отметку и её причину повтор не переписывает: условие `revoked_at
// IS NULL` делает второй отзыв пустым, а не вторым.
func revokeFamiliesOfSessionsTx(ctx context.Context, tx pgx.Tx,
	sessionIDs []string, reason domain.FamilyRevocationReason,
) (int, error) {
	if len(sessionIDs) == 0 {
		return 0, nil
	}
	if err := reason.Validate(); err != nil {
		return 0, err
	}
	// КУРСОР ЗАКРЫВАЕТСЯ РУКАМИ, А НЕ `defer`, И ЭТО НЕ НЕБРЕЖНОСТЬ: следом на
	// ТОЙ ЖЕ транзакции исполняются ещё операторы, а pgx не допускает работы с
	// соединением, пока курсор открыт. Отложенное закрытие сработало бы ПОСЛЕ
	// них — то есть слишком поздно.
	rows, err := tx.Query(ctx, `
		SELECT id FROM kaname.token_families
		 WHERE session_id = ANY($1) AND revoked_at IS NULL`, sessionIDs)
	if err != nil {
		return 0, wrapPgErr(err, "TokenFamily", "")
	}
	var families []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return 0, wrapPgErr(err, "TokenFamily", "")
		}
		families = append(families, id)
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return 0, wrapPgErr(err, "TokenFamily", "")
	}
	if len(families) == 0 {
		return 0, nil
	}

	if _, err := tx.Exec(ctx, `
		UPDATE kaname.token_families
		   SET revoked_at = now(), revoked_reason = $2
		 WHERE id = ANY($1) AND revoked_at IS NULL`, families, string(reason)); err != nil {
		return 0, wrapPgErr(err, "TokenFamily", "")
	}
	if _, err := tx.Exec(ctx, `
		UPDATE kaname.authorization_codes
		   SET active = false, deactivated_at = now(), deactivated_reason = 'family-revoked'
		 WHERE family_id = ANY($1) AND active`, families); err != nil {
		return 0, wrapPgErr(err, "AuthorizationCode", "")
	}
	if _, err := tx.Exec(ctx, `
		UPDATE kaname.refresh_tokens
		   SET active = false, deactivated_at = now(), deactivated_reason = 'family-revoked'
		 WHERE family_id = ANY($1) AND active`, families); err != nil {
		return 0, wrapPgErr(err, "RefreshToken", "")
	}
	return len(families), nil
}

// ── Согласие ────────────────────────────────────────────────────────────────

// GrantConsent записывает согласие человека клиенту на перечисленные области.
//
// ИДЕМПОТЕНТНО и ОДНИМ оператором на весь перечень: уникальность тройки держит
// `consent_grants_subject_client_scope_uk`, и конфликт по ней — не отказ, а
// «согласие уже стоит»: отметка отзыва снимается, момент согласия обновляется
// на ТОЙ ЖЕ строке. Пара «посмотреть, есть ли согласие — записать» дала бы под
// гонкой две строки на одну тройку, после чего отзыв снимал бы ОДНУ из них.
func (r *OAuthCeremonyRepo) GrantConsent(ctx context.Context, userID, clientID string, scopes []string) error {
	if userID == "" {
		return fmt.Errorf("Illegal argument consent_grant.user_id: required")
	}
	if clientID == "" {
		return fmt.Errorf("Illegal argument consent_grant.client_id: required")
	}
	if len(scopes) == 0 {
		return fmt.Errorf("Illegal argument consent_grant.scope: required")
	}
	// Повтор области в перечне — ОДНА область, а не две: `ON CONFLICT DO UPDATE`
	// не вправе задеть одну и ту же строку дважды в одном операторе и ответил бы
	// отказом хранилища на то, что отказом не является. Свёртка повторов идёт
	// здесь, ДО оператора, а не разбором его отказа.
	unique := make([]string, 0, len(scopes))
	seen := make(map[string]bool, len(scopes))
	for i, s := range scopes {
		if s == "" {
			return fmt.Errorf("Illegal argument consent_grant.scope[%d]: must not be empty", i)
		}
		if seen[s] {
			continue
		}
		seen[s] = true
		unique = append(unique, s)
	}
	rowIDs := make([]string, 0, len(unique))
	for range unique {
		rowIDs = append(rowIDs, ids.NewHyphenID(consentIDPrefix))
	}
	// Идентификаторы чеканятся на КАЖДУЮ область, но лягут только те, чья
	// строка заводится впервые: конфликтующая строка сохраняет свой.
	if _, err := r.pool.Exec(ctx, `
		INSERT INTO kaname.consent_grants (id, user_id, client_id, scope)
		SELECT s.id, $2, $3, s.scope
		  FROM unnest($1::text[], $4::text[]) AS s(id, scope)
		ON CONFLICT (user_id, client_id, scope)
		DO UPDATE SET revoked_at = NULL, granted_at = now()`,
		rowIDs, userID, clientID, unique); err != nil {
		return wrapPgErr(err, "ConsentGrant", userID)
	}
	return nil
}

// WithdrawConsent отзывает согласие на одну область: ОТМЕТКА на той же строке.
//
// Строка остаётся: «согласия не было» и «согласие отозвано» — разные ответы, и
// удалённая строка их не различает.
func (r *OAuthCeremonyRepo) WithdrawConsent(ctx context.Context, userID, clientID, scope string) error {
	if userID == "" || clientID == "" || scope == "" {
		return fmt.Errorf("Illegal argument consent_grant: user_id, client_id and scope are required")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE kaname.consent_grants
		   SET revoked_at = now()
		 WHERE user_id = $1 AND client_id = $2 AND scope = $3 AND revoked_at IS NULL`,
		userID, clientID, scope)
	if err != nil {
		return wrapPgErr(err, "ConsentGrant", userID)
	}
	if tag.RowsAffected() == 0 {
		// Отзывать нечего — и это НЕ отказ: согласия либо не было, либо оно уже
		// отозвано, и в обоих случаях состояние ровно то, которого просили.
		return nil
	}
	return nil
}

// ConsentedScopes — области, на которые согласие ДЕЙСТВУЕТ, в устойчивом
// порядке. Отозванные не попадают: отметка отзыва и есть предикат.
func (r *OAuthCeremonyRepo) ConsentedScopes(ctx context.Context, userID, clientID string) ([]string, error) {
	if userID == "" || clientID == "" {
		return nil, fmt.Errorf("Illegal argument consent_grant: user_id and client_id are required")
	}
	rows, err := r.pool.Query(ctx, `
		SELECT scope FROM kaname.consent_grants
		 WHERE user_id = $1 AND client_id = $2 AND revoked_at IS NULL
		 ORDER BY scope`, userID, clientID)
	if err != nil {
		return nil, wrapPgErr(err, "ConsentGrant", userID)
	}
	defer rows.Close()
	out := make([]string, 0, 8)
	for rows.Next() {
		var s string
		if err := rows.Scan(&s); err != nil {
			return nil, wrapPgErr(err, "ConsentGrant", userID)
		}
		out = append(out, s)
	}
	if err := rows.Err(); err != nil {
		return nil, wrapPgErr(err, "ConsentGrant", userID)
	}
	return out, nil
}

// ── Проверочное значение секрета интерактивного клиента ─────────────────────

// SetClientSecretVerifier кладёт проверочное значение секрета клиента.
//
// Материал уходит в базу АРГУМЕНТОМ оператора и в этом файле больше нигде не
// участвует: разрешение на выход `domain.LoginVerifier.Reveal` дано ЭТОМУ файлу
// с причиной в `internal/check/login_verifier_containment_test.go`.
//
// Снятие значения — отдельный глагол (`ClearClientSecretVerifier`), а не пустой
// вход сюда: «положить пустое» и «снять» читались бы одинаково, и опечатка
// вызывающего молча разоружала бы клиента.
func (r *OAuthCeremonyRepo) SetClientSecretVerifier(ctx context.Context, clientID string, verifier domain.LoginVerifier) error {
	if clientID == "" {
		return fmt.Errorf("Illegal argument interactive_client.client_id: required")
	}
	if verifier.IsZero() {
		return fmt.Errorf("Illegal argument interactive_client.secret_verifier: required")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE kaname.interactive_clients
		   SET secret_verifier = $2, secret_verifier_set_at = now()
		 WHERE client_id = $1`, clientID, verifier.Reveal())
	if err != nil {
		return wrapPgErr(err, "InteractiveClient", clientID)
	}
	if tag.RowsAffected() == 0 {
		return refuseNoSuchClient(clientID)
	}
	return nil
}

// ClearClientSecretVerifier снимает проверочное значение: клиент становится
// публичным, и секрета у него нет.
func (r *OAuthCeremonyRepo) ClearClientSecretVerifier(ctx context.Context, clientID string) error {
	if clientID == "" {
		return fmt.Errorf("Illegal argument interactive_client.client_id: required")
	}
	tag, err := r.pool.Exec(ctx, `
		UPDATE kaname.interactive_clients
		   SET secret_verifier = '', secret_verifier_set_at = NULL
		 WHERE client_id = $1`, clientID)
	if err != nil {
		return wrapPgErr(err, "InteractiveClient", clientID)
	}
	if tag.RowsAffected() == 0 {
		return refuseNoSuchClient(clientID)
	}
	return nil
}

// ClientSecretVerifier — проверочное значение клиента и признак «секрет есть».
//
// Признак отдельным значением, а не «пустая строка означает нет»: отсутствие
// представимо отдельно от значения, и вызывающий, забывший его прочесть, не
// уйдёт сверять предъявленный секрет с пустым материалом.
func (r *OAuthCeremonyRepo) ClientSecretVerifier(ctx context.Context, clientID string) (domain.LoginVerifier, bool, error) {
	if clientID == "" {
		return domain.LoginVerifier{}, false, fmt.Errorf("Illegal argument interactive_client.client_id: required")
	}
	var material string
	err := r.pool.QueryRow(ctx, `
		SELECT secret_verifier FROM kaname.interactive_clients WHERE client_id = $1`,
		clientID).Scan(&material)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return domain.LoginVerifier{}, false, refuseNoSuchClient(clientID)
	}
	if err != nil {
		return domain.LoginVerifier{}, false, wrapPgErr(err, "InteractiveClient", clientID)
	}
	if material == "" {
		return domain.LoginVerifier{}, false, nil
	}
	verifier, vErr := domain.NewLoginVerifier(material)
	if vErr != nil {
		return domain.LoginVerifier{}, false, vErr
	}
	return verifier, true, nil
}

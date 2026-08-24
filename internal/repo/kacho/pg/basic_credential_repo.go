// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package pg

import (
	"context"
	"database/sql"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/kacho/pkg/credsecret"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// BasicCredentialRepo — АВТОРИТЕТ О ПРЕДЪЯВЛЕННОМ БАЗОВОМ СЕКРЕТЕ
// (задача #1142, приёмка BAT-1 §5, §6).
//
// ─────────────────────────────────────────────────────────────────────────────
// ОТЗЫВ ДОХОДИТ ДО ПРЕДЪЯВЛЕНИЯ КОНСТРУКЦИЕЙ, А НЕ ВТОРЫМ МЕХАНИЗМОМ
//
// Отзыв есть СНЯТИЕ строки. Резолв ищет строку по ПЕРВИЧНОМУ КЛЮЧУ одним
// оператором, чей предикат включает существование строки, вид `SECRET`,
// непросроченность и активность владельца. Нет строки — нет удостоверения.
//
// Отсюда бесплатно получаются поводы, о которых глагол отзыва не знает: снятие
// владельца, снятие участия, каскад по внешнему ключу. Перечень ОБЯЗАННЫХ
// ПИСАТЬ разошёлся бы с деревом молча; повод, привязанный к самому снятию, —
// нет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СВЕРКА ХЕША В Go, А НЕ В ПРЕДИКАТЕ ОПЕРАТОРА
//
// Оператор остаётся ОДИН — он читает строку по первичному ключу вместе с её
// хешем и состоянием владельца. Сама сверка идёт `subtle.ConstantTimeCompare`:
// сравнение в предикате базы постоянного времени не даёт и дало бы измеримую
// разницу между «строки нет» и «строка есть, хеш не тот». Наблюдаемый исход у
// обоих случаев ОДИН И ТОТ ЖЕ — `domain.ErrBasicCredentialRefused`.
type BasicCredentialRepo struct {
	pool *pgxpool.Pool
}

// NewBasicCredentialRepo конструирует.
func NewBasicCredentialRepo(pool *pgxpool.Pool) *BasicCredentialRepo {
	return &BasicCredentialRepo{pool: pool}
}

// Резолв строки удостоверения ЛИЧНОСТИ. Состояние владельца — часть ЭТОГО ЖЕ
// оператора: вторым запросом оно дало бы окно, в котором человек уже заблокирован,
// а его секрет ещё проходит.
// #nosec G101 -- это текст SQL-запроса, а не удостоверение: слово `secret_hash`
// здесь — ИМЯ КОЛОНКИ, в которой лежит хеш. Сам секрет в этом файле не
// появляется ни в каком виде и хранению не подлежит by construction.
const resolveUserCredentialSQL = `
SELECT c.id, c.secret_hash, c.expires_at, u.id, u.display_name
  FROM user_oauth_clients c
  JOIN users u ON u.id = c.user_id
 WHERE c.id = $1
   AND c.credential_kind = 'SECRET'
   AND c.expires_at IS NOT NULL
   AND c.expires_at > now()
   AND u.invite_status = 'ACTIVE'`

// Резолв строки удостоверения СЛУЖЕБНОЙ УЧЁТКИ.
// #nosec G101 -- то же: имя колонки в тексте запроса, не значение.
const resolveSACredentialSQL = `
SELECT c.id, c.secret_hash, c.expires_at, s.id, s.name
  FROM service_account_oauth_clients c
  JOIN service_accounts s ON s.id = c.sva_id
 WHERE c.id = $1
   AND c.credential_kind = 'SECRET'
   AND c.expires_at IS NOT NULL
   AND c.expires_at > now()
   AND s.enabled = true`

// ResolveBasic отвечает на ОДИН вопрос: годно ли предъявленное СЕЙЧАС и чей это
// принципал.
//
// Разбор строки — в объявленном месте (`pkg/credsecret`), второй копии
// предиката здесь не заводится. Полоса ТЕРМИНАЛЬНА: строка, несущая нашу марку,
// получает вердикт здесь и дальше как «удостоверения нет вовсе» не уходит.
func (r *BasicCredentialRepo) ResolveBasic(ctx context.Context, presented string) (domain.BasicCredential, error) {
	// Уровень 2 отсева: форма и контрольная сумма. Обращения к базе нет —
	// обрезанный, опечатанный и подделанный наугад вход не оплачивается
	// запросом.
	p, err := credsecret.Parse(presented)
	if err != nil {
		return domain.BasicCredential{}, domain.ErrBasicCredentialRefused
	}

	// Полоса выбирается по СОБСТВЕННОМУ префиксу нашего идентификатора, а не
	// перебором таблиц: перебор означал бы запасной путь, срабатывающий на
	// неудаче, и «не нашлось у личности» становилось бы входом второй полосы.
	var (
		query         string
		principalType string
	)
	switch {
	case strings.HasPrefix(p.CredentialID, domain.PrefixUserOAuthClient):
		query, principalType = resolveUserCredentialSQL, "user"
	case strings.HasPrefix(p.CredentialID, domain.PrefixSAOAuthClient):
		query, principalType = resolveSACredentialSQL, "service_account"
	default:
		return domain.BasicCredential{}, domain.ErrBasicCredentialRefused
	}

	var (
		credID      string
		storedHash  []byte
		expiresAt   sql.NullTime
		principalID string
		displayName string
	)
	err = r.pool.QueryRow(ctx, query, p.CredentialID).
		Scan(&credID, &storedHash, &expiresAt, &principalID, &displayName)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Строки нет: отозвано, истекло, владелец неактивен либо её не было
		// никогда. Наружу — ОДИН отказ; различать эти случаи значило бы
		// завести оракул.
		return domain.BasicCredential{}, domain.ErrBasicCredentialRefused
	case err != nil:
		// Недоступность авторитета — ОТДЕЛЬНЫЙ исход, и он не подменяется
		// отказом в удостоверении: вызывающему нечего исправлять сменой
		// удостоверения.
		return domain.BasicCredential{}, err
	}

	if !credsecret.Verify(p.CredentialID, p.SecretPart, storedHash) {
		return domain.BasicCredential{}, domain.ErrBasicCredentialRefused
	}

	var exp time.Time
	if expiresAt.Valid {
		exp = expiresAt.Time
	}
	return domain.BasicCredential{
		PrincipalType: principalType,
		PrincipalID:   principalID,
		DisplayName:   displayName,
		CredentialID:  credID,
		ExpiresAt:     exp,
	}, nil
}

// TouchLastUsed отмечает предъявление ОДНИМ оператором с предикатом дросселя:
// «не чаще, чем раз в окно». Это не «прочитать и записать» (ban #10), и на
// горячем пути чтение не превращается в запись — зовётся ТОЛЬКО на промахе кэша
// вердикта у края.
func (r *BasicCredentialRepo) TouchLastUsed(ctx context.Context, credentialID string, throttle time.Duration) error {
	var table string
	switch {
	case strings.HasPrefix(credentialID, domain.PrefixUserOAuthClient):
		table = "user_oauth_clients"
	case strings.HasPrefix(credentialID, domain.PrefixSAOAuthClient):
		table = "service_account_oauth_clients"
	default:
		return nil
	}
	_, err := r.pool.Exec(ctx,
		`UPDATE `+table+` SET last_used_at = now()
		  WHERE id = $1
		    AND (last_used_at IS NULL OR last_used_at < now() - $2::interval)`,
		credentialID, throttle.String())
	return err
}

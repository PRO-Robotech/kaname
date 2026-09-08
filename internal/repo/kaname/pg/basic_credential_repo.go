// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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
	"github.com/PRO-Robotech/kaname/internal/domain"
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

// ПРЕДИКАТ ЖИВОСТИ ОБЪЯВЛЕН ОДИН РАЗ НА ПОЛОСУ (задача #1450).
//
// Спрашивающих про живость двое: ПРЕДЪЯВИТЕЛЬ (резолв по секрету) и ОТКРЫТОЕ
// СОЕДИНЕНИЕ (проверка по идентификатору). Вопрос у них один и тот же —
// действует ли строка СЕЙЧАС, — и разъехаться эти два предиката не вправе:
// строже у полосы идентификатора значит закрывать живые соединения, мягче —
// не закрывать отозванные, то есть вернуть дефект, ради которого полоса
// заведена.
//
// Поэтому предикат СКЛЕИВАЕТСЯ, а не переписывается. Расхождение становится
// непредставимым by construction; сверх того интеграционная проба сличает обе
// полосы на каждом состоянии строки — гейт на случай, если склейку разберут.
//
// Предикатов ЗДЕСЬ ДВА — по одному на носителя, — поэтому и разъезжаются они
// порознь, и сверка одного носителя о втором не утверждает ничего. Проба
// сличает полосы у КАЖДОГО носителя, а перечень носителей спрашивает у схемы:
// таблица, несущая и вид удостоверения, и его хеш. Носитель, заведённый позже
// без своей полосы в пробе, становится находкой, а не невидимостью.
// #nosec G101 -- `SECRET` здесь ЗНАЧЕНИЕ КОЛОНКИ вида удостоверения в тексте
// SQL, а не секрет: сравнение идёт с перечислением `credential_kind`.
const liveUserCredentialPredicate = `
   AND c.credential_kind = 'SECRET'
   AND c.expires_at IS NOT NULL
   AND c.expires_at > now()
   AND u.invite_status = 'ACTIVE'`

// То же для служебной учётки: у неё своё состояние владельца.
// #nosec G101 -- то же: значение колонки вида в тексте запроса, не значение секрета.
const liveSACredentialPredicate = `
   AND c.credential_kind = 'SECRET'
   AND c.expires_at IS NOT NULL
   AND c.expires_at > now()
   AND s.enabled = true`

// Резолв строки удостоверения ЛИЧНОСТИ. Состояние владельца — часть ЭТОГО ЖЕ
// оператора: вторым запросом оно дало бы окно, в котором человек уже заблокирован,
// а его секрет ещё проходит.
// Слово `secret_hash` здесь — ИМЯ КОЛОНКИ, в которой лежит хеш. Сам секрет в
// этом файле не появляется ни в каком виде и хранению не подлежит by construction.
const resolveUserCredentialSQL = `
SELECT c.id, c.secret_hash, c.expires_at, u.id, u.display_name
  FROM user_oauth_clients c
  JOIN users u ON u.id = c.user_id
 WHERE c.id = $1` + liveUserCredentialPredicate

// Резолв строки удостоверения СЛУЖЕБНОЙ УЧЁТКИ.
// То же: имя колонки в тексте запроса, не значение.
const resolveSACredentialSQL = `
SELECT c.id, c.secret_hash, c.expires_at, s.id, s.name
  FROM service_account_oauth_clients c
  JOIN service_accounts s ON s.id = c.sva_id
 WHERE c.id = $1` + liveSACredentialPredicate

// ЖИВОСТЬ, СПРОШЕННАЯ ПО ИДЕНТИФИКАТОРУ. Хеш не читается вовсе: спрашивающий
// секрета не предъявляет и предъявить не может, а лишняя колонка в проекции —
// это значение, которое кто-нибудь однажды вернёт наружу.
const liveUserCredentialSQL = `
SELECT 1
  FROM user_oauth_clients c
  JOIN users u ON u.id = c.user_id
 WHERE c.id = $1` + liveUserCredentialPredicate

const liveSACredentialSQL = `
SELECT 1
  FROM service_account_oauth_clients c
  JOIN service_accounts s ON s.id = c.sva_id
 WHERE c.id = $1` + liveSACredentialPredicate

// credentialLane — куда идти с этим идентификатором и как назвать принципала.
type credentialLane struct {
	resolveSQL    string
	liveSQL       string
	principalType string
}

// laneOfCredentialID выбирает полосу по СОБСТВЕННОМУ префиксу нашего
// идентификатора, а не перебором таблиц: перебор означал бы запасной путь,
// срабатывающий на неудаче, и «не нашлось у личности» становилось бы входом
// второй полосы.
//
// Выбор объявлен ОДИН РАЗ на оба вопроса. Две копии этого switch разошлись бы
// молча — и разошлись бы там, где расхождение не видно: обе отвечают верно на
// известном префиксе.
func laneOfCredentialID(credentialID string) (credentialLane, bool) {
	switch {
	case strings.HasPrefix(credentialID, domain.PrefixUserOAuthClient):
		return credentialLane{resolveUserCredentialSQL, liveUserCredentialSQL, "user"}, true
	case strings.HasPrefix(credentialID, domain.PrefixSAOAuthClient):
		return credentialLane{resolveSACredentialSQL, liveSACredentialSQL, "service_account"}, true
	default:
		return credentialLane{}, false
	}
}

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

	lane, known := laneOfCredentialID(p.CredentialID)
	if !known {
		return domain.BasicCredential{}, domain.ErrBasicCredentialRefused
	}
	query, principalType := lane.resolveSQL, lane.principalType

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

// CheckBasicLive отвечает на ОДИН вопрос: действует ли ЭТА строка удостоверения
// СЕЙЧАС. Спрашивается по идентификатору, без предъявления секрета (#1450).
//
// # Кто спрашивает и почему не резолвом
//
// Открытое длинное соединение края. Секрет оно видело однажды, при открытии, и
// хранить его весь срок соединения ради возможности переспросить значило бы
// завести поверхность хранения ради контроля. Резолв по секрету такому
// спрашивающему недоступен by construction — не потому, что дорог, а потому, что
// предъявлять ему нечего.
//
// # Что здесь НЕ проверяется и почему это правильно
//
// Владение. Спрашивающий уже установил его при открытии соединения; повторять
// проверку нечем и незачем. Отсюда следствие, названное вслух: вопрос отвечается
// всякому, кто дошёл до внутреннего слушателя, и потому ответ — БИНАРНЫЙ. Ни
// принципала, ни срока, ни имени: сведения, добытые по одному идентификатору,
// были бы оракулом.
//
// # Исходы
//
// nil — живо. domain.ErrBasicCredentialRefused — не живо, и ЕДИНЫМ отказом:
// неизвестный идентификатор, чужой префикс, мусор, отозванное, истёкшее,
// неактивный владелец — один исход, иначе по различию узнают, существует ли
// удостоверение. Любая иная ошибка — авторитет не смог ответить; это НЕ «не
// живо», и подменять одно другим значило бы закрывать соединения на собственной
// неисправности.
func (r *BasicCredentialRepo) CheckBasicLive(ctx context.Context, credentialID string) error {
	// Уровень 1 отсева: полоса. Пустое, мусор и чужой префикс не оплачиваются
	// обращением к базе.
	lane, known := laneOfCredentialID(credentialID)
	if !known {
		return domain.ErrBasicCredentialRefused
	}

	var one int
	err := r.pool.QueryRow(ctx, lane.liveSQL, credentialID).Scan(&one)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return domain.ErrBasicCredentialRefused
	case err != nil:
		// Недоступность авторитета — ОТДЕЛЬНЫЙ исход. Слить её с отказом значило
		// бы закрывать открытые соединения каждый раз, когда база моргнула.
		return err
	}
	return nil
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

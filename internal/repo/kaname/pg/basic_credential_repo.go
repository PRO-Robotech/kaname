// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/credsecret"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/revocationpolicy"
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
// ОТСЕЧКА ВЛАДЕЛЬЦА — ЧАСТЬ ТОГО ЖЕ ОПЕРАТОРА (задача kaname#379)
//
// Один повод строку НЕ снимает: человек, выведенный отовсюду, получает отсечку
// отзыва-всех, а его удостоверения остаются лежать. Долговременное
// удостоверение, выданное не позже отсечки, есть ровно то, что «выйти отовсюду»
// обязано прекратить, — поэтому отсечка владельца читается ТЕМ ЖЕ оператором,
// что строка удостоверения. Второй запрос дал бы то же окно, что и состояние
// владельца вторым запросом.
//
// Решение — не своё сравнение, а общее правило полос удостоверений человека
// (`revocationpolicy.Forbids`) с якорем в момент выдачи строки: граница
// включительна, и расхождение с полосами выдачи токена непредставимо. Нет
// отсечки — нет запрета. Отсечку прочитать не удалось — оператор не выполнился
// целиком, и это исход «авторитет не ответил», а не отказ и не пропуск.
//
// У служебной учётки отсечки человека нет by construction: её операторы
// отдают на месте отсечки NULL, и решение для обоих носителей одно.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СВЕРКА ХЕША В Go, А НЕ В ПРЕДИКАТЕ ОПЕРАТОРА
//
// Оператор остаётся ОДИН — он читает строку по первичному ключу вместе с её
// хешем и состоянием владельца. Сама сверка идёт `subtle.ConstantTimeCompare`:
// сравнение в предикате базы постоянного времени не даёт и дало бы измеримую
// разницу между «строки нет» и «строка есть, хеш не тот». Наблюдаемый исход у
// обоих случаев ОДИН И ТОТ ЖЕ — `domain.ErrBasicCredentialRefused`. Причину
// отказ несёт ВНУТРЬ ([domain.RefuseBasicCredential]): «строки нет», «секрет не
// тот» и отсечка владельца различимы для счётчика и журнала вызывающего и
// неразличимы ни текстом ошибки, ни ответом на проводе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДЕЛ ОБРАЩЕНИЯ К БАЗЕ — У ОПЕРАТОРА, А НЕ У ВЫЗЫВАЮЩЕГО (задача kaname#379)
//
// Вызывающих у авторитета больше одного: глаголы внутреннего слушателя и полоса
// докер-реестра. Предел, выставленный у каждого по отдельности, у одного из них
// рано или поздно не появится — молча, потому что отсутствие предела выглядит
// как его наличие ровно до того дня, когда база перестаёт отвечать. Поэтому
// предел подаётся конструктору, без него авторитет не собирается, и КАЖДОЕ
// обращение к базе идёт под ним. Величину объявляет композиционный корень —
// та же, что у полос выдачи токена: оператор полосы для строки человека читает
// и отсечку отзыва-всех, а одно чтение одной строки несёт один предел на любой
// полосе.
type BasicCredentialRepo struct {
	pool        *pgxpool.Pool
	callTimeout time.Duration
}

// NewBasicCredentialRepo конструирует авторитет с объявленным пределом ОДНОГО
// обращения к базе.
//
// Непредставленный предел — отказ построения, а не «разумное умолчание»:
// авторитет без предела висит на неотвечающей базе, пока не кончатся
// горутины вызывающего, и узнаётся это не на старте, а на первом отказе базы.
func NewBasicCredentialRepo(pool *pgxpool.Pool, callTimeout time.Duration) (*BasicCredentialRepo, error) {
	if callTimeout <= 0 {
		return nil, fmt.Errorf("pg: basic credential authority: the per-call limit of a database round trip "+
			"must be declared as a positive duration, got %s", callTimeout)
	}
	return &BasicCredentialRepo{pool: pool, callTimeout: callTimeout}, nil
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
// Склеивается и источник строки вместе с отсечкой владельца
// ([userBasicRowSource]), и решение по ней ([ownerCutoffForbids]).
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

// Источник строки удостоверения ЛИЧНОСТИ — вместе с владельцем и его отсечкой
// отзыва-всех. Объявлен один раз на обе полосы: отсечка, присоединённая только
// к одной из них, разъехалась бы с другой молча.
const userBasicRowSource = `
  FROM user_oauth_clients c
  JOIN users u ON u.id = c.user_id
  LEFT JOIN user_token_revocations r ON r.user_id = u.id`

// Источник строки удостоверения СЛУЖЕБНОЙ УЧЁТКИ.
const saBasicRowSource = `
  FROM service_account_oauth_clients c
  JOIN service_accounts s ON s.id = c.sva_id`

// Резолв строки удостоверения ЛИЧНОСТИ. Состояние владельца — часть ЭТОГО ЖЕ
// оператора: вторым запросом оно дало бы окно, в котором человек уже заблокирован,
// а его секрет ещё проходит. Две последние колонки — момент выдачи строки и
// отсечка владельца (NULL — отсечки нет).
// Слово `secret_hash` здесь — ИМЯ КОЛОНКИ, в которой лежит хеш. Сам секрет в
// этом файле не появляется ни в каком виде и хранению не подлежит by construction.
const resolveUserCredentialSQL = `
SELECT c.id, c.secret_hash, c.expires_at, u.id, u.display_name, c.created_at, r.revoke_before` +
	userBasicRowSource + `
 WHERE c.id = $1` + liveUserCredentialPredicate

// Резолв строки удостоверения СЛУЖЕБНОЙ УЧЁТКИ. На месте отсечки — NULL:
// отсечка человека о ключе машины не говорит ничего.
// То же: имя колонки в тексте запроса, не значение.
const resolveSACredentialSQL = `
SELECT c.id, c.secret_hash, c.expires_at, s.id, s.name, c.created_at, NULL::timestamptz` +
	saBasicRowSource + `
 WHERE c.id = $1` + liveSACredentialPredicate

// ЖИВОСТЬ, СПРОШЕННАЯ ПО ИДЕНТИФИКАТОРУ. Хеш не читается вовсе: спрашивающий
// секрета не предъявляет и предъявить не может, а лишняя колонка в проекции —
// это значение, которое кто-нибудь однажды вернёт наружу. Читается ровно то,
// что нужно решению об отсечке: момент выдачи и сама отсечка.
const liveUserCredentialSQL = `
SELECT c.created_at, r.revoke_before` +
	userBasicRowSource + `
 WHERE c.id = $1` + liveUserCredentialPredicate

const liveSACredentialSQL = `
SELECT c.created_at, NULL::timestamptz` +
	saBasicRowSource + `
 WHERE c.id = $1` + liveSACredentialPredicate

// ownerCutoffForbids — запрещает ли отсечка отзыва-всех владельца
// удостоверение, выданное в момент issuedAt. Одно решение на обе полосы и оба
// носителя.
//
// Сравнение — общее правило полос удостоверений человека, а не своё:
// [revocationpolicy.Forbids], граница включительна. Отсутствие отсечки
// (NULL) — не запрет: её нет, пока человека никто не выводил отовсюду.
func ownerCutoffForbids(cutoff sql.NullTime, issuedAt time.Time) bool {
	return cutoff.Valid && revocationpolicy.Forbids(cutoff.Time, issuedAt)
}

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
		return domain.BasicCredential{}, domain.RefuseBasicCredential(domain.BasicRefusalMalformed)
	}

	lane, known := laneOfCredentialID(p.CredentialID)
	if !known {
		return domain.BasicCredential{}, domain.RefuseBasicCredential(domain.BasicRefusalMalformed)
	}
	query, principalType := lane.resolveSQL, lane.principalType

	var (
		credID      string
		storedHash  []byte
		expiresAt   sql.NullTime
		principalID string
		displayName string
		issuedAt    time.Time
		ownerCutoff sql.NullTime
	)
	qctx, cancel := context.WithTimeout(ctx, r.callTimeout)
	defer cancel()
	err = r.pool.QueryRow(qctx, query, p.CredentialID).
		Scan(&credID, &storedHash, &expiresAt, &principalID, &displayName, &issuedAt, &ownerCutoff)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		// Строки нет: отозвано, истекло, владелец неактивен либо её не было
		// никогда. Наружу — ОДИН отказ; различать эти случаи значило бы
		// завести оракул.
		return domain.BasicCredential{}, domain.RefuseBasicCredential(domain.BasicRefusalNotFound)
	case err != nil:
		// Недоступность авторитета — ОТДЕЛЬНЫЙ исход, и он не подменяется
		// отказом в удостоверении: вызывающему нечего исправлять сменой
		// удостоверения.
		return domain.BasicCredential{}, err
	}

	if !credsecret.Verify(p.CredentialID, p.SecretPart, storedHash) {
		return domain.BasicCredential{}, domain.RefuseBasicCredential(domain.BasicRefusalSecretMismatch)
	}

	// Отсечка владельца судится ПОСЛЕ сверки хеша: не знающему секрета она не
	// сообщает о себе ничего, даже временем ответа. Исход — тот же единый отказ,
	// что у отозванного и истёкшего; своя у него только причина внутри.
	if ownerCutoffForbids(ownerCutoff, issuedAt) {
		return domain.BasicCredential{}, domain.RefuseBasicCredential(domain.BasicRefusalOwnerRevoked)
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
// неактивный владелец, отсечка владельца не раньше выдачи — один исход, иначе
// по различию узнают, существует ли удостоверение; причина едет внутрь
// значением отказа и наружу не выходит. Любая иная ошибка, в том числе
// истёкший предел обращения, — авторитет не смог ответить; это НЕ «не живо», и
// подменять одно другим значило бы закрывать соединения на собственной
// неисправности.
func (r *BasicCredentialRepo) CheckBasicLive(ctx context.Context, credentialID string) error {
	// Уровень 1 отсева: полоса. Пустое, мусор и чужой префикс не оплачиваются
	// обращением к базе.
	lane, known := laneOfCredentialID(credentialID)
	if !known {
		return domain.RefuseBasicCredential(domain.BasicRefusalMalformed)
	}

	var (
		issuedAt    time.Time
		ownerCutoff sql.NullTime
	)
	qctx, cancel := context.WithTimeout(ctx, r.callTimeout)
	defer cancel()
	err := r.pool.QueryRow(qctx, lane.liveSQL, credentialID).Scan(&issuedAt, &ownerCutoff)
	switch {
	case errors.Is(err, pgx.ErrNoRows):
		return domain.RefuseBasicCredential(domain.BasicRefusalNotFound)
	case err != nil:
		// Недоступность авторитета — ОТДЕЛЬНЫЙ исход. Слить её с отказом значило
		// бы закрывать открытые соединения каждый раз, когда база моргнула.
		return err
	}
	if ownerCutoffForbids(ownerCutoff, issuedAt) {
		return domain.RefuseBasicCredential(domain.BasicRefusalOwnerRevoked)
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
	ectx, cancel := context.WithTimeout(ctx, r.callTimeout)
	defer cancel()
	_, err := r.pool.Exec(ectx,
		`UPDATE `+table+` SET last_used_at = now()
		  WHERE id = $1
		    AND (last_used_at IS NULL OR last_used_at < now() - $2::interval)`,
		credentialID, throttle.String())
	return err
}

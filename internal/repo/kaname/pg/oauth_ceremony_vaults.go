// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

// oauth_ceremony_vaults.go — ХРАНИЛИЩА церемонии фундамента
// (`corelib/oauthceremony`: ClientDirectory, AuthorizationCodeVault,
// AccessTokenVault, RefreshTokenVault, UnitOfWork) над записью собственной
// церемонии слоя доступа (`oauth_ceremony_repo.go`, миграции
// `20260920175117`, `20260923231545`, `20260925121413`). Задача
// PRO-Robotech/kaname#423.
//
// # ГРАНТ СОБИРАЕТСЯ ИЗ ЗАПИСИ, А НЕ ХРАНИТСЯ СЛЕПКОМ
//
// Порт отдаёт грант (`oauthceremony.GrantRecord`), а у службы грант — это
// СЕМЕЙСТВО: клиент, человек, сессия, область и снимок уровня лежат на его
// строке, код и токены обновления — его дети. Поля гранта, которых у записи
// нет, выводятся по правилу, названному здесь один раз:
//
//   - субъект — `user_id`, сессия — `session_id`, уровень — `token_families.acr`
//     (снимок на выдаче: у сессии уровень подвижен);
//   - момент аутентификации — `human_sessions.authenticated_at`: он НЕПОДВИЖЕН
//     всю жизнь сессии (Ф11 Р6), и копии у него не заводится;
//   - получатели — `interactive_clients.audiences` ТЕКУЩЕЙ записи клиента:
//     получателя штампуем мы по регистрации клиента (приёмка LINE-A-1 Р6,
//     «output-only»), а не вызывающий; сужение регистрации действует на
//     следующий же выпуск семейства;
//   - граница семейства — меньшее из срока сессии и потолка семейства
//     фундамента (`tokenpolicy.MaxRefreshTokenFamilyTTL`) от рождения семейства:
//     семейство кончается вместе со своим входом (AuthorizationGrant.SessionID).
//
// # ЕДИНИЦА РАБОТЫ И ОБОРОТ В ДВА ШАГА
//
// Движок оборачивает транзакцией выдачу пары: «погасить (обернуть) → положить
// токен доступа → положить токен обновления». Оборот он называет ДВУМЯ
// вызовами: RotateRefreshToken (какой токен обёрнут) и StoreRefreshToken (кто
// преемник). Схема 357 держит пару «обёрнут ↔ назван преемник» ограничением
// строки (`refresh_tokens_successor_pair_ck`), и записать обёртку без преемника
// нельзя. Поэтому оборот — одна транзакция единицы работы:
//
//  1. RotateRefreshToken берёт замок семейства (порядок «родитель → ребёнок»,
//     `lockFamilyOfRefreshSQL`) и строку предъявленного токена `FOR UPDATE` с
//     условием живости В ТОМ ЖЕ операторе. На READ COMMITTED проигравший,
//     стоявший на строке победителя, перепроверяет условие по НОВОЙ версии и
//     получает ноль строк — это и есть одновременный повтор (сценарий 28);
//  2. StoreRefreshToken той же транзакцией исполняет оператор ротации 357
//     (`rotateRefreshSQL`, преемник назван) и заводит преемника
//     (`insertRefreshSQL`). Замок строки держится от шага 1 до фиксации:
//     решение и запись неразделимы, и пары «прочитал — потом записал» без
//     замка здесь нет (ban #10).
//
// Оборот вне единицы работы — нарушение контракта сборки, а не законный путь.
//
// # ОБМЕН КОДА — ОДНА ТРАНЗАКЦИЯ ЗАПРОСА, ОТКРЫТАЯ ПОГАШЕНИЕМ
//
// Движок гасит код при ПРЕДЪЯВЛЕНИИ, а выпуск и пару кладёт позже, отдельными
// вызовами. Погашение, закреплённое сразу, открывало окно: отставший
// одновременный обмен видел ноль строк, отзывал семейство — и отзыв ложился
// РАНЬШЕ записи выпуска опередившего. Запись выпуска в отозванное семейство
// схема отвергает (К1, `access_tokens_family_live_fk`), и опередивший получал
// отказ операции: исход «ровно один обмен проходит» (приёмка LINE-A-1-17)
// зависел от того, кто быстрее. Замер 2026-09-25: из 8 одновременных обменов
// одним кодом — 7 повторов и опередивший с отказом порта.
//
// Поэтому у запроса обмена своя единица (OpenRequest), и погашение открывает её
// транзакцию: условный оператор обмена берёт строку кода под замок и держит его
// до конца запроса. Выборка, справочник клиентов, запись выпуска
// (`RecordAccessToken`) и единица работы движка той же операции идут В НЕЙ ЖЕ.
// Отставший стоит на строке кода, пока опередивший не закрепит всё, и лишь
// потом видит ноль строк; отзыв семейства ложится ПОСЛЕ выдачи и снимает её
// (ровно то, что требует фундамент: семейство умирает вместе с парой
// опередившего).
//
// Погашение переживает откат выдачи: сразу за ним стоит точка сохранения, и
// откат единицы работы откатывается к ней, а урегулирование запроса
// (settle) закрепляет погашение — код, предъявленный однажды, второго
// предъявления не получает и при отказе выдачи (контракт
// `oauthceremony.UnitOfWork`). Сбой процесса до закрепления откатывает всю
// транзакцию: код жив, но и выданное не уехало — выдача остаётся единственной.
//
// # ЗАПИСЬ ВЫПУСКА ТОКЕНА ДОСТУПА — ОДНА, И КЛАДЁТ ЕЁ ПОРТ ВЫПУСКА
//
// Запись «jti → семейство» ложится в порту выпуска (`ceremonyport.AccessTokens`,
// К1): до того, как токен уедет. StoreAccessToken второй записи не заводит —
// первичный ключ её не допустил бы — и ПОДТВЕРЖДАЕТ, что запись лежит в
// семействе гранта, условным оператором правки. Читатель решения о семействе
// выпуска один (`familyRevokedOfIssuanceSQL`, гейт
// `TestFamilyVerdictHasOneReaderAndEverySurfaceAsksTheRule`), поэтому выборки
// гранта по jti здесь нет, а FetchAccessToken и DropAccessToken отказывают
// операцией: интроспекция и отзыв церемонии в службе не собраны, предъявление
// судит правило отзыва (`tokenrevocation`) по записи выпуска.

import (
	"context"
	stderrors "errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"github.com/PRO-Robotech/corelib/oauthceremony"
	"github.com/PRO-Robotech/corelib/tokenpolicy"

	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
)

// CeremonyVaults — хранилища церемонии фундамента над записью церемонии.
type CeremonyVaults struct {
	repo *OAuthCeremonyRepo
	pool *pgxpool.Pool
	// scopes — области, которые клиенту дозволено запрашивать; закрытый
	// перечень домена (`domain.CeremonyScopes`).
	scopes []string
}

var (
	_ oauthceremony.ClientDirectory        = (*CeremonyVaults)(nil)
	_ oauthceremony.AuthorizationCodeVault = (*CeremonyVaults)(nil)
	_ oauthceremony.AccessTokenVault       = (*CeremonyVaults)(nil)
	_ oauthceremony.RefreshTokenVault      = (*CeremonyVaults)(nil)
	_ oauthceremony.UnitOfWork             = (*CeremonyVaults)(nil)
)

// NewCeremonyVaults — хранилища над пулом службы.
func NewCeremonyVaults(pool *pgxpool.Pool) *CeremonyVaults {
	return &CeremonyVaults{repo: NewOAuthCeremonyRepo(pool), pool: pool, scopes: domain.CeremonyScopes()}
}

// familyBoundSeconds — потолок семейства фундамента в секундах, параметром
// операторов границы.
func familyBoundSeconds() float64 { return tokenpolicy.MaxRefreshTokenFamilyTTL.Seconds() }

// ── Единица работы ──────────────────────────────────────────────────────────

// ceremonyUnitKey — ключ единицы работы в контексте.
type ceremonyUnitKey struct{}

// ceremonyUnit — открытая транзакция единицы работы и оборот, названный в ней
// первым шагом и ждущий преемника.
type ceremonyUnit struct {
	tx pgx.Tx
	// request — единица запроса, чью транзакцию единица работы продолжает;
	// nil — своя транзакция (оборот токена обновления).
	request *ceremonyRequest

	mu      sync.Mutex
	pending *pendingRotation
}

// ── Единица запроса обмена ──────────────────────────────────────────────────

// ceremonyRequestKey — ключ единицы запроса в контексте.
type ceremonyRequestKey struct{}

// issuanceSavepoint — точка сохранения за погашением кода: откат выдачи не
// снимает погашения.
const issuanceSavepoint = "ceremony_issuance"

// ceremonyRequest — транзакция запроса обмена: её открывает погашение кода, и
// всё, что операция пишет и читает после него, идёт в ней (см. шапку).
type ceremonyRequest struct {
	mu sync.Mutex
	tx pgx.Tx
	// done — транзакция закреплена единицей работы либо урегулирована.
	done bool
}

// open — транзакция запроса, если она открыта и не закреплена.
func (rq *ceremonyRequest) open() (pgx.Tx, bool) {
	rq.mu.Lock()
	defer rq.mu.Unlock()
	return rq.tx, rq.tx != nil && !rq.done
}

func requestFrom(ctx context.Context) (*ceremonyRequest, bool) {
	rq, ok := ctx.Value(ceremonyRequestKey{}).(*ceremonyRequest)
	return rq, ok && rq != nil
}

// requestTx — открытая транзакция запроса операции, которой принадлежит ctx.
func requestTx(ctx context.Context) (pgx.Tx, bool) {
	rq, ok := requestFrom(ctx)
	if !ok {
		return nil, false
	}
	return rq.open()
}

// OpenRequest открывает единицу запроса обмена. Транзакции у неё ещё нет — её
// открывает погашение кода; до него (доказательство клиента, выборка кода)
// соединение не держится. settle урегулирует запрос: открытую и не
// закреплённую транзакцию (выдача не состоялась либо откатилась) она
// откатывает к точке сохранения и закрепляет погашение. Зовётся ровно один раз,
// после операции и ДО ответа клиенту.
func (v *CeremonyVaults) OpenRequest(ctx context.Context) (context.Context, func(context.Context) error) {
	rq := &ceremonyRequest{}
	return context.WithValue(ctx, ceremonyRequestKey{}, rq), func(ctx context.Context) error {
		rq.mu.Lock()
		defer rq.mu.Unlock()
		if rq.tx == nil || rq.done {
			rq.done = true
			return nil
		}
		rq.done = true
		if _, err := rq.tx.Exec(ctx, "ROLLBACK TO SAVEPOINT "+issuanceSavepoint); err != nil {
			_ = rq.tx.Rollback(ctx)
			return fmt.Errorf("ceremony request: the consumption could not be kept past the refused issuance: %w",
				wrapPgErr(err, "AuthorizationCode", ""))
		}
		if err := rq.tx.Commit(ctx); err != nil {
			return fmt.Errorf("ceremony request: the consumption was not committed: %w",
				wrapPgErr(err, "AuthorizationCode", ""))
		}
		return nil
	}
}

// pendingRotation — предъявленный токен, строка которого взята под замок, и
// семейство, в котором его обернут.
type pendingRotation struct {
	familyID string
	digest   string
}

func unitFrom(ctx context.Context) (*ceremonyUnit, bool) {
	u, ok := ctx.Value(ceremonyUnitKey{}).(*ceremonyUnit)
	return u, ok && u != nil
}

// Begin открывает единицу работы на названном уровне писателей церемонии
// (`ceremonyWriterTx`): исход проигравшего оборота решает перепроверка условия
// строки, а не отказ сериализации.
func (v *CeremonyVaults) Begin(ctx context.Context) (context.Context, error) {
	if _, nested := unitFrom(ctx); nested {
		return ctx, fmt.Errorf("ceremony unit of work: already open in this operation")
	}
	// Погашение кода уже открыло транзакцию запроса — выдача продолжает её.
	if rq, ok := requestFrom(ctx); ok {
		if tx, open := rq.open(); open {
			return context.WithValue(ctx, ceremonyUnitKey{}, &ceremonyUnit{tx: tx, request: rq}), nil
		}
	}
	tx, err := v.repo.beginWriter(ctx)
	if err != nil {
		return ctx, wrapPgErr(err, "TokenFamily", "")
	}
	return context.WithValue(ctx, ceremonyUnitKey{}, &ceremonyUnit{tx: tx}), nil
}

// Commit закрепляет единицу работы. Оборот, названный первым шагом и не
// получивший преемника, закрепить нельзя: строка обёртки без преемника
// схеме невыразима, и молча отпустить замок значило бы потерять решение.
func (v *CeremonyVaults) Commit(ctx context.Context) error {
	u, ok := unitFrom(ctx)
	if !ok {
		return fmt.Errorf("ceremony unit of work: commit without an open unit")
	}
	u.mu.Lock()
	pending := u.pending
	u.mu.Unlock()
	if pending != nil {
		_ = u.tx.Rollback(ctx)
		return fmt.Errorf("ceremony unit of work: refresh token of family %s was rotated without a successor", pending.familyID)
	}
	if u.request != nil {
		// Транзакция запроса: погашение, запись выпуска и пара закрепляются
		// ОДНИМ закреплением.
		u.request.mu.Lock()
		defer u.request.mu.Unlock()
		u.request.done = true
	}
	if err := u.tx.Commit(ctx); err != nil {
		return wrapPgErr(err, "TokenFamily", "")
	}
	return nil
}

// Rollback отменяет единицу работы.
func (v *CeremonyVaults) Rollback(ctx context.Context) error {
	u, ok := unitFrom(ctx)
	if !ok {
		return fmt.Errorf("ceremony unit of work: rollback without an open unit")
	}
	if u.request != nil {
		// Откат выдачи — к точке за погашением: погашение закрепит
		// урегулирование запроса.
		if _, err := u.tx.Exec(ctx, "ROLLBACK TO SAVEPOINT "+issuanceSavepoint); err != nil {
			return wrapPgErr(err, "TokenFamily", "")
		}
		return nil
	}
	if err := u.tx.Rollback(ctx); err != nil && !stderrors.Is(err, pgx.ErrTxClosed) {
		return wrapPgErr(err, "TokenFamily", "")
	}
	return nil
}

// ── Справочник клиентов ─────────────────────────────────────────────────────

// lookupCeremonyClientSQL — клиент церемонии по публичному идентификатору.
// Снимаемый (`DELETING`) клиент — «клиента нет»: снятие действует немедленно.
const lookupCeremonyClientSQL = `
SELECT client_id, redirect_uris, grant_types, audiences, token_endpoint_auth_method
  FROM kaname.interactive_clients
 WHERE client_id = $1 AND status = 'ACTIVE'`

// LookupClient отдаёт запись клиента. Клиента нет (либо он снимается) —
// ErrGrantNotFound, единственный случай пакета в контракте вызова.
func (v *CeremonyVaults) LookupClient(ctx context.Context, clientID string) (oauthceremony.ClientRegistration, error) {
	if clientID == "" {
		return oauthceremony.ClientRegistration{}, oauthceremony.ErrGrantNotFound
	}
	var (
		reg                    oauthceremony.ClientRegistration
		uris, grantTypes, auds []string
		stored, method         string
	)
	err := v.querier(ctx).QueryRow(ctx, lookupCeremonyClientSQL, clientID).Scan(&stored, &uris, &grantTypes, &auds, &method)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return oauthceremony.ClientRegistration{}, oauthceremony.ErrGrantNotFound
	}
	if err != nil {
		return oauthceremony.ClientRegistration{}, wrapPgErr(err, "InteractiveClient", clientID)
	}
	reg.ClientID = stored
	reg.RedirectURIs = append([]string(nil), uris...)
	reg.Audiences = append([]string(nil), auds...)
	reg.Scopes = append([]string(nil), v.scopes...)
	reg.Public = method == string(oauthceremony.ClientAuthNone)
	reg.ResponseDeliveries = []oauthceremony.ResponseDelivery{oauthceremony.DeliveryQuery}
	for _, g := range grantTypes {
		kind := oauthceremony.GrantKind(g)
		if !kind.Declared() {
			// Вид вне словаря церемонии (запись провайдера, иное поколение
			// регистрации) движку не передаётся: права по нему церемония не
			// обслуживает, а слово без обработчика обещало бы поведение.
			continue
		}
		reg.GrantKinds = append(reg.GrantKinds, kind)
		if kind == oauthceremony.GrantAuthorizationCode {
			reg.ResponseKinds = []string{string(oauthceremony.ResponseKindCode)}
		}
	}
	return reg, nil
}

// ── Коды авторизации ────────────────────────────────────────────────────────

// StoreAuthorizationCode заводит семейство и его код ОДНОЙ транзакцией
// (`IssueAuthorizationCode`). Срок кода назначила церемония (граница — не позже
// срока сессии); в базу он уезжает длительностью и отсчитывается от времени
// БАЗЫ, которым его и сравнивает погашение.
func (v *CeremonyVaults) StoreAuthorizationCode(ctx context.Context, signature string, code oauthceremony.AuthorizationCodeRecord) (oauthceremony.StoreOutcome, error) {
	g := code.Grant
	expiry, named := g.Session.ExpiresAt[oauthceremony.TokenKindAuthorizationCode]
	if !named || expiry.IsZero() {
		return oauthceremony.StoreOutcome{}, fmt.Errorf("authorization code: the ceremony named no expiry")
	}
	ttl := time.Until(expiry)
	if ttl <= 0 {
		return oauthceremony.StoreOutcome{}, fmt.Errorf("authorization code: the expiry named by the ceremony has passed")
	}
	redirect := firstValue(g.Form, "redirect_uri")
	if redirect == "" {
		return oauthceremony.StoreOutcome{}, fmt.Errorf("authorization code: the grant carries no redirect_uri")
	}
	err := v.repo.IssueAuthorizationCode(ctx, NewAuthorizationCode{
		Context: domain.CeremonyContext{
			FamilyID: g.GrantID, ClientID: g.ClientID, UserID: g.Session.Subject,
			SessionID: g.Session.SessionID, Scope: append([]string(nil), g.GrantedScopes...),
		},
		CodeDigest:          signature,
		RedirectURI:         redirect,
		CodeChallenge:       code.ProofKey.Challenge,
		CodeChallengeMethod: string(code.ProofKey.Method),
		ACR:                 g.Session.ACR,
		TTL:                 ttl,
	})
	if stderrors.Is(err, iamerr.ErrAlreadyExists) {
		return oauthceremony.StoreOutcome{}, oauthceremony.ErrStorageConflict
	}
	if err != nil {
		return oauthceremony.StoreOutcome{}, err
	}
	return oauthceremony.RowsTouched(1), nil
}

// fetchCodeSQL — запись кода с тем, из чего собирается грант. Живость, срок и
// погашенность судит БАЗА, её временем; разбор исхода ниже только читает ответ.
const fetchCodeSQL = `
SELECT c.family_id, c.client_id, c.user_id, c.session_id, c.scope, c.redirect_uri,
       c.code_challenge, c.code_challenge_method, c.expires_at,
       c.deactivated_at IS NOT NULL, (c.active AND c.expires_at > now()),
       f.acr, f.created_at, s.authenticated_at,
       LEAST(s.expires_at, f.created_at + make_interval(secs => $2)),
       ic.audiences
  FROM kaname.authorization_codes c
  JOIN kaname.token_families f ON f.id = c.family_id
  JOIN kaname.human_sessions s ON s.id = c.session_id
  JOIN kaname.interactive_clients ic ON ic.client_id = c.client_id
 WHERE c.code_digest = $1`

// FetchAuthorizationCode — три исхода контракта:
//
//   - погашен → запись ВМЕСТЕ с ErrAuthorizationCodeConsumed: по ней отзывается
//     семейство повтора, и повтор узнаётся по записи, а не по сроку;
//   - не погашен, но не жив (истёк по времени базы, семейство отозвано) либо
//     строки нет → ErrGrantNotFound: истечение — не признак похищения;
//   - жив → запись.
func (v *CeremonyVaults) FetchAuthorizationCode(ctx context.Context, signature string) (oauthceremony.AuthorizationCodeRecord, error) {
	var (
		row            ceremonyGrantRow
		redirect       string
		challenge      string
		method         string
		codeExpiry     time.Time
		consumed, live bool
	)
	err := v.querier(ctx).QueryRow(ctx, fetchCodeSQL, signature, familyBoundSeconds()).Scan(
		&row.familyID, &row.clientID, &row.userID, &row.sessionID, &row.scope, &redirect,
		&challenge, &method, &codeExpiry, &consumed, &live,
		&row.acr, &row.createdAt, &row.authTime, &row.bound, &row.audiences)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return oauthceremony.AuthorizationCodeRecord{}, oauthceremony.ErrGrantNotFound
	}
	if err != nil {
		return oauthceremony.AuthorizationCodeRecord{}, wrapPgErr(err, "AuthorizationCode", "")
	}
	grant := row.grant(map[oauthceremony.TokenKind]time.Time{oauthceremony.TokenKindAuthorizationCode: codeExpiry})
	grant.Form["response_type"] = []string{string(oauthceremony.ResponseKindCode)}
	grant.Form["redirect_uri"] = []string{redirect}
	rec := oauthceremony.AuthorizationCodeRecord{
		Grant:    grant,
		ProofKey: oauthceremony.ProofKeyBinding{Challenge: challenge, Method: oauthceremony.ProofKeyMethod(method)},
	}
	switch {
	case consumed:
		return rec, oauthceremony.ErrAuthorizationCodeConsumed
	case !live:
		return oauthceremony.AuthorizationCodeRecord{}, oauthceremony.ErrGrantNotFound
	}
	return rec, nil
}

// ConsumeAuthorizationCode гасит код оператором обмена 357 (`exchangeCodeSQL`:
// условие на прежнее состояние в том же операторе) после замка семейства.
//
// В единице запроса (OpenRequest) погашение открывает её транзакцию и НЕ
// закрепляется: замок строки держится до конца запроса (см. шапку). Вне её —
// своя транзакция слоя доступа (`OAuthCeremonyRepo.ConsumeAuthorizationCode`).
func (v *CeremonyVaults) ConsumeAuthorizationCode(ctx context.Context, signature string) (oauthceremony.StoreOutcome, error) {
	rq, ok := requestFrom(ctx)
	if !ok {
		n, err := v.repo.ConsumeAuthorizationCode(ctx, signature)
		if err != nil {
			return oauthceremony.StoreOutcome{}, err
		}
		return oauthceremony.RowsTouched(n), nil
	}
	if err := domain.ValidateCeremonyDigest("authorization_code.code_digest", signature); err != nil {
		return oauthceremony.StoreOutcome{}, err
	}
	rq.mu.Lock()
	defer rq.mu.Unlock()
	if rq.tx != nil || rq.done {
		return oauthceremony.StoreOutcome{}, fmt.Errorf("ceremony request: a second authorization code consumption in one exchange")
	}
	// Начало транзакции — взятие связи из пула и BEGIN — идёт под сроком ЭТОГО
	// вызова: порт обязан уложиться в срок, который ему назначил мост
	// (контракт `oauthceremony`), а пул, не отдающий связи, иначе держал бы обмен
	// без предела под замком единицы запроса. Жить транзакции до конца запроса
	// это не мешает: драйвер контекст начала не удерживает (pgx: контекст
	// судит только команду BEGIN, отката по его концу нет), и срок каждого
	// следующего оператора назначает вызов, который его исполняет.
	tx, err := v.repo.beginWriter(ctx)
	if err != nil {
		return oauthceremony.StoreOutcome{}, wrapPgErr(err, "AuthorizationCode", "")
	}
	consumed, err := consumeCodeTx(ctx, tx, signature)
	if err == nil && consumed == 1 {
		_, err = tx.Exec(ctx, "SAVEPOINT "+issuanceSavepoint)
	}
	if err != nil || consumed != 1 {
		// Ноль строк либо отказ: писать нечего, и замок держать незачем.
		_ = tx.Rollback(ctx)
		if err != nil {
			return oauthceremony.StoreOutcome{}, err
		}
		return oauthceremony.RowsTouched(consumed), nil
	}
	rq.tx = tx
	return oauthceremony.RowsTouched(consumed), nil
}

// querier — транзакция запроса, если погашение её открыло, иначе пул.
func (v *CeremonyVaults) querier(ctx context.Context) rowQuerier {
	if tx, ok := requestTx(ctx); ok {
		return tx
	}
	return v.pool
}

// ── Токены доступа ──────────────────────────────────────────────────────────

// confirmIssuanceSQL — ПОДТВЕРЖДЕНИЕ записи выпуска, а не вторая запись:
// правка без смены значения затрагивает строку ровно тогда, когда выпуск
// записан в семействе гранта. Выборкой это не сделано намеренно — читатель
// решения о семействе выпуска один (см. шапку).
const confirmIssuanceSQL = `
UPDATE kaname.access_tokens SET expires_at = expires_at
 WHERE jti = $1 AND family_id = $2`

// StoreAccessToken подтверждает, что выпуск под jti записан в семействе гранта
// (запись положил порт выпуска). Ноль строк — выпуск не записан: церемония
// отвергает исход как нарушение контракта, и токен клиенту не уезжает.
func (v *CeremonyVaults) StoreAccessToken(ctx context.Context, signature string, grant oauthceremony.GrantRecord) (oauthceremony.StoreOutcome, error) {
	if signature == "" || grant.GrantID == "" {
		return oauthceremony.StoreOutcome{}, fmt.Errorf("access token: neither the issuance nor its family may be unnamed")
	}
	var (
		tagRows int64
		err     error
	)
	if u, ok := unitFrom(ctx); ok {
		tag, execErr := u.tx.Exec(ctx, confirmIssuanceSQL, signature, grant.GrantID)
		tagRows, err = tag.RowsAffected(), execErr
	} else {
		tag, execErr := v.repo.execWriter(ctx, confirmIssuanceSQL, signature, grant.GrantID)
		tagRows, err = tag.RowsAffected(), execErr
	}
	if err != nil {
		return oauthceremony.StoreOutcome{}, wrapPgErr(err, "AccessToken", grant.GrantID)
	}
	return oauthceremony.RowsTouched(tagRows), nil
}

// errGrantByIssuanceNotServed — чтение и снятие гранта по jti в службе не
// обслуживаются: решение о выпуске принадлежит одному читателю, а поверхностей
// интроспекции и отзыва церемонии нет (см. шапку). Отказ операцией, а не
// «записи нет»: ответ «нет» сделал бы годный токен негодным для интроспекции и
// отзыв — успехом без действия.
var errGrantByIssuanceNotServed = stderrors.New("access token: the grant is not read or dropped by issuance here; " +
	"presentation is judged by the revocation rule over the single issuance reader")

// FetchAccessToken — см. errGrantByIssuanceNotServed.
func (v *CeremonyVaults) FetchAccessToken(context.Context, string) (oauthceremony.GrantRecord, error) {
	return oauthceremony.GrantRecord{}, errGrantByIssuanceNotServed
}

// DropAccessToken — см. errGrantByIssuanceNotServed. Снятие одного выпуска в
// схеме невыразимо: выпуск снимает отзыв его семейства (GrantRevoker).
func (v *CeremonyVaults) DropAccessToken(context.Context, string) (oauthceremony.StoreOutcome, error) {
	return oauthceremony.StoreOutcome{}, errGrantByIssuanceNotServed
}

// ── Токены обновления ───────────────────────────────────────────────────────

// fetchRefreshSQL — токен обновления с тем, из чего собирается грант.
const fetchRefreshSQL = `
SELECT t.family_id, t.client_id, t.user_id, t.session_id, t.scope, t.expires_at,
       t.family_live, t.deactivated_at IS NOT NULL, t.expires_at > now(),
       f.acr, f.created_at, s.authenticated_at,
       LEAST(s.expires_at, f.created_at + make_interval(secs => $2)),
       ic.audiences
  FROM kaname.refresh_tokens t
  JOIN kaname.token_families f ON f.id = t.family_id
  JOIN kaname.human_sessions s ON s.id = t.session_id
  JOIN kaname.interactive_clients ic ON ic.client_id = t.client_id
 WHERE t.token_digest = $1`

// FetchRefreshToken — три исхода контракта:
//
//   - семейство отозвано либо строки нет → ErrGrantNotFound;
//   - обёрнут → грант ВМЕСТЕ с ErrRefreshTokenRotated (повтор: по нему
//     отзывается семейство);
//   - жив → грант. Живой, но истёкший по времени базы — ErrGrantNotFound.
func (v *CeremonyVaults) FetchRefreshToken(ctx context.Context, signature string) (oauthceremony.GrantRecord, error) {
	var (
		row                      ceremonyGrantRow
		expiry                   time.Time
		familyLive, rotated, due bool
	)
	err := v.pool.QueryRow(ctx, fetchRefreshSQL, signature, familyBoundSeconds()).Scan(
		&row.familyID, &row.clientID, &row.userID, &row.sessionID, &row.scope, &expiry,
		&familyLive, &rotated, &due,
		&row.acr, &row.createdAt, &row.authTime, &row.bound, &row.audiences)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return oauthceremony.GrantRecord{}, oauthceremony.ErrGrantNotFound
	}
	if err != nil {
		return oauthceremony.GrantRecord{}, wrapPgErr(err, "RefreshToken", "")
	}
	grant := row.grant(map[oauthceremony.TokenKind]time.Time{oauthceremony.TokenKindRefresh: expiry})
	switch {
	case !familyLive:
		return oauthceremony.GrantRecord{}, oauthceremony.ErrGrantNotFound
	case rotated:
		return grant, oauthceremony.ErrRefreshTokenRotated
	case !due:
		return oauthceremony.GrantRecord{}, oauthceremony.ErrGrantNotFound
	}
	return grant, nil
}

// lockRefreshForRotationSQL — строка предъявленного токена под замком С
// условием живости в том же операторе. Ноль строк — токен уже обернули
// (одновременный повтор) либо он не жив.
const lockRefreshForRotationSQL = `
SELECT 1 FROM kaname.refresh_tokens
 WHERE token_digest = $1 AND family_id = $2 AND active AND expires_at > now()
   FOR UPDATE`

// RotateRefreshToken — первый шаг оборота (см. шапку): только в единице работы.
func (v *CeremonyVaults) RotateRefreshToken(ctx context.Context, grantID, signature string) (oauthceremony.StoreOutcome, error) {
	u, ok := unitFrom(ctx)
	if !ok {
		return oauthceremony.StoreOutcome{}, fmt.Errorf("refresh token rotation outside a unit of work: " +
			"the wrapped row and its successor are one statement of one transaction here")
	}
	if grantID == "" || signature == "" {
		return oauthceremony.StoreOutcome{}, fmt.Errorf("refresh token rotation: the family and the token must be named")
	}
	// ЗАМОК СЕМЕЙСТВА — ПЕРВЫМ, как у ротации 357: порядок «родитель → ребёнок»
	// встречен порядку отзыва.
	if _, err := u.tx.Exec(ctx, lockFamilyOfRefreshSQL, signature); err != nil {
		return oauthceremony.StoreOutcome{}, wrapPgErr(err, "TokenFamily", grantID)
	}
	tag, err := u.tx.Exec(ctx, lockRefreshForRotationSQL, signature, grantID)
	if err != nil {
		return oauthceremony.StoreOutcome{}, wrapPgErr(err, "RefreshToken", grantID)
	}
	if tag.RowsAffected() == 1 {
		u.mu.Lock()
		u.pending = &pendingRotation{familyID: grantID, digest: signature}
		u.mu.Unlock()
	}
	return oauthceremony.RowsTouched(tag.RowsAffected()), nil
}

// StoreRefreshToken заводит токен обновления: в обороте — преемника той же
// транзакцией, что обёртка предшественника; вне оборота — первое поколение
// семейства (обмен кода). Связь с токеном доступа несёт семейство.
func (v *CeremonyVaults) StoreRefreshToken(ctx context.Context, signature, _ string, grant oauthceremony.GrantRecord) (oauthceremony.StoreOutcome, error) {
	u, ok := unitFrom(ctx)
	if !ok {
		return oauthceremony.StoreOutcome{}, fmt.Errorf("refresh token outside a unit of work")
	}
	expiry, named := grant.Session.ExpiresAt[oauthceremony.TokenKindRefresh]
	if !named || expiry.IsZero() {
		return oauthceremony.StoreOutcome{}, fmt.Errorf("refresh token: the ceremony named no expiry")
	}
	ttl := time.Until(expiry)
	if ttl <= 0 {
		return oauthceremony.StoreOutcome{}, fmt.Errorf("refresh token: the expiry named by the ceremony has passed")
	}

	u.mu.Lock()
	pending := u.pending
	u.pending = nil
	u.mu.Unlock()

	if pending == nil {
		c := domain.CeremonyContext{
			FamilyID: grant.GrantID, ClientID: grant.ClientID, UserID: grant.Session.Subject,
			SessionID: grant.Session.SessionID, Scope: append([]string(nil), grant.GrantedScopes...),
		}
		if err := c.Validate(); err != nil {
			return oauthceremony.StoreOutcome{}, err
		}
		if err := insertRefreshTokenTx(ctx, u.tx, signature, c, 0, ttl); err != nil {
			return oauthceremony.StoreOutcome{}, err
		}
		return oauthceremony.RowsTouched(1), nil
	}
	if pending.familyID != grant.GrantID {
		return oauthceremony.StoreOutcome{}, fmt.Errorf("refresh token: the successor names family %s, the rotation family %s",
			grant.GrantID, pending.familyID)
	}
	var rotated domain.RotatedRefreshToken
	err := u.tx.QueryRow(ctx, rotateRefreshSQL, pending.digest, signature).Scan(
		&rotated.Context.FamilyID, &rotated.Context.ClientID, &rotated.Context.UserID,
		&rotated.Context.SessionID, &rotated.Context.Scope, &rotated.Generation)
	if stderrors.Is(err, pgx.ErrNoRows) {
		// Строка под нашим замком с шага 1 — ноль строк здесь означает, что
		// условие ротации и условие замка разошлись.
		return oauthceremony.StoreOutcome{}, fmt.Errorf("refresh token of family %s: the row locked for rotation "+
			"no longer matches the rotation condition", pending.familyID)
	}
	if err != nil {
		return oauthceremony.StoreOutcome{}, wrapPgErr(err, "RefreshToken", pending.familyID)
	}
	if err := insertRefreshTokenTx(ctx, u.tx, signature, rotated.Context, rotated.Generation+1, ttl); err != nil {
		return oauthceremony.StoreOutcome{}, err
	}
	return oauthceremony.RowsTouched(1), nil
}

// dropRefreshSQL — живость предъявленного токена для снятия.
const dropRefreshSQL = `SELECT active FROM kaname.refresh_tokens WHERE token_digest = $1`

// DropRefreshToken снимает токен обновления. Движок зовёт его на пути повтора —
// для обёрнутого токена, который из оборота уже выведен: снимать нечего (ноль
// строк — законный исход). Снятие ЖИВОГО одиночного токена в схеме невыразимо:
// токен снимает отзыв его семейства, и такой вызов — отказ, а не молчаливый ноль.
func (v *CeremonyVaults) DropRefreshToken(ctx context.Context, signature string) (oauthceremony.StoreOutcome, error) {
	var q rowQuerier = v.pool
	if u, ok := unitFrom(ctx); ok {
		q = u.tx
	}
	var active bool
	err := q.QueryRow(ctx, dropRefreshSQL, signature).Scan(&active)
	if stderrors.Is(err, pgx.ErrNoRows) {
		return oauthceremony.RowsTouched(0), nil
	}
	if err != nil {
		return oauthceremony.StoreOutcome{}, wrapPgErr(err, "RefreshToken", "")
	}
	if active {
		return oauthceremony.StoreOutcome{}, fmt.Errorf("refresh token: a live token is removed by revoking its family, not singly")
	}
	return oauthceremony.RowsTouched(0), nil
}

// ── Сборка гранта ───────────────────────────────────────────────────────────

// ceremonyGrantRow — то, из чего собирается грант, прочитанное одним оператором.
type ceremonyGrantRow struct {
	familyID, clientID, userID, sessionID string
	scope, audiences                      []string
	acr                                   string
	createdAt, authTime, bound            time.Time
}

// grant собирает запись гранта по правилу шапки.
func (r ceremonyGrantRow) grant(expires map[oauthceremony.TokenKind]time.Time) oauthceremony.GrantRecord {
	notAfter := map[oauthceremony.TokenKind]time.Time{
		oauthceremony.TokenKindAuthorizationCode: r.bound,
		oauthceremony.TokenKindAccess:            r.bound,
		oauthceremony.TokenKindRefresh:           r.bound,
	}
	return oauthceremony.GrantRecord{
		GrantID:            r.familyID,
		ClientID:           r.clientID,
		IssuedAt:           r.createdAt,
		RequestedScopes:    append([]string(nil), r.scope...),
		GrantedScopes:      append([]string(nil), r.scope...),
		RequestedAudiences: append([]string(nil), r.audiences...),
		GrantedAudiences:   append([]string(nil), r.audiences...),
		Form: map[string][]string{
			"client_id": {r.clientID},
			"scope":     {strings.Join(r.scope, " ")},
		},
		Session: oauthceremony.SessionRecord{
			Subject:   r.userID,
			SessionID: r.sessionID,
			ACR:       r.acr,
			AuthTime:  r.authTime,
			ExpiresAt: expires,
			NotAfter:  notAfter,
			Claims:    map[string]any{},
		},
	}
}

func firstValue(form map[string][]string, key string) string {
	if v := form[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

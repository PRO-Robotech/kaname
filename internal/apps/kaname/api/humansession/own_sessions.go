// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package humansession

// own_sessions.go — СВОИ СЕССИИ: перечень живых записей человека, выход из
// выбранной и выход из всех, кроме текущей (задача PRO-Robotech/kaname#634;
// приёмка `docs/engineering/acceptance/own-sessions-are-listed-and-ended-by-their-owner.md`,
// отпечаток 63333cc2…, Р1…Р10).
//
// # Субъект — только из носителя (§6 инв. 1)
//
// Ни один из трёх глаголов не принимает субъекта из запроса: носитель
// резолвится в запись, запись называет субъекта, и глагол действует ТОЛЬКО над
// записями этого субъекта. «Текущая» сессия — понятие носителя: это запись, на
// которую указывает носитель запроса (Р2).
//
// # Владение, живость и срок решает ОПЕРАТОР снятия (ban #10, §6 инв. 3)
//
// Последовательности «прочитать запись → сравнить субъекта → снять» здесь нет:
// оператор снятия несёт условие на субъекта, на живость и на срок, и ноль
// снятых строк есть отказ SESSION_NOT_FOUND — один на чужую, неизвестную,
// снятую и истёкшую (Р5). Живость ДЕЙСТВУЮЩЕЙ записи (носителя запроса)
// судится под замком писателя нескольких сессий этого человека — тем же, под
// которым идёт снятие (Р7): из двух встречных «всех, кроме текущей» жива
// остаётся ровно одна действующая.
//
// # Исход — одна транзакция; отсечки нет (Р6)
//
// Отметки снятия, отзыв выданного в снятых записях (дверь снятия, kaname#313) и
// событие `iam.session.ended_by_person` — одной транзакцией писателя; отказ
// любой записи не оставляет ни одной. Отсечку эти глаголы НЕ пишут: она —
// величина на субъекта и накрыла бы запись носителя. Снятая запись перестаёт
// действовать на следующем же предъявлении — край спрашивает службу о сессии
// на каждом запросе. Носитель текущей записи не перевыпускается.

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strconv"
	"time"

	"github.com/PRO-Robotech/corelib/pagetoken"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/domain"
	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// AuditSessionEndedByPerson — событие снятия своих записей из другой своей
// сессии (Р6): `user_id`, `session_id` (запись носителя — ОТКУДА сняли),
// `ended_session_ids` (снятые; набор). Ни адреса, ни имени, ни описания клиента.
const AuditSessionEndedByPerson = "iam.session.ended_by_person"

// Отказы своих сессий (Р5) — контракт полосы, тексты фиксированы и
// идентификатора не повторяют.
const (
	TextSessionNotFound    = "session not found"
	ReasonSessionNotFound  = "SESSION_NOT_FOUND"
	TextSessionIsCurrent   = "the current session ends by logout"
	ReasonSessionIsCurrent = "SESSION_IS_CURRENT"
)

var (
	// ErrSessionNotFound — названная запись не живая запись субъекта носителя:
	// чужая, неизвестная, снятая либо истёкшая — один отказ (Р5).
	ErrSessionNotFound = errors.New(TextSessionNotFound)
	// ErrSessionIsCurrent — названа запись носителя: текущая сессия выходится
	// только выходом (Ф3-15), который гасит печенье (Р5).
	ErrSessionIsCurrent = errors.New(TextSessionIsCurrent)
)

// Параметры страницы перечня (Р4): имена — как их шлёт клиент; набор закрыт.
const (
	OwnSessionsPageSizeParam  = "pageSize"
	OwnSessionsPageTokenParam = "pageToken"
)

// OwnSessionsPage — страница перечня: величина в [0..MaxListPageSize] (0 —
// умолчание) и непрозрачный курсор того же кодека, что у списков службы.
type OwnSessionsPage struct {
	Size  int32
	Token string
}

// ParseOwnSessionsPage — параметры страницы из СЫРЫХ значений запроса, до
// любого чтения хранилища (Р4). sizeGiven=false — параметра нет (умолчание).
// Отказы — FieldError с правилом: тексты OS-05 несут правило и пустые details.
func ParseOwnSessionsPage(rawSize string, sizeGiven bool, token string) (OwnSessionsPage, error) {
	var page OwnSessionsPage
	if sizeGiven {
		n, err := strconv.ParseInt(rawSize, 10, 64)
		switch {
		case errors.Is(err, strconv.ErrRange):
			return OwnSessionsPage{}, pageSizeOutOfRange()
		case err != nil:
			return OwnSessionsPage{}, &FieldError{Field: OwnSessionsPageSizeParam, Rule: "must be an integer"}
		case n < 0 || n > int64(shared.MaxListPageSize):
			return OwnSessionsPage{}, pageSizeOutOfRange()
		}
		page.Size = int32(n)
	}
	if !pagetoken.WellFormed(token) {
		return OwnSessionsPage{}, &FieldError{Field: OwnSessionsPageTokenParam, Rule: "malformed"}
	}
	page.Token = token
	return page, nil
}

func pageSizeOutOfRange() error {
	return &FieldError{Field: OwnSessionsPageSizeParam,
		Rule: fmt.Sprintf("must be in [0..%d] (0 means default)", shared.MaxListPageSize)}
}

// validate — та же проверка уже разобранной страницы: вызывающий мимо
// транспорта не обходит её.
func (p OwnSessionsPage) validate() error {
	if p.Size < 0 || p.Size > shared.MaxListPageSize {
		return pageSizeOutOfRange()
	}
	if !pagetoken.WellFormed(p.Token) {
		return &FieldError{Field: OwnSessionsPageTokenParam, Rule: "malformed"}
	}
	return nil
}

// OwnSessionsDeps — зависимости трёх глаголов; все обязательны, кроме
// наблюдателя, часов и журнала.
type OwnSessionsDeps struct {
	Store Store
	// Freshness — окно свежести правки своих данных (Ф1 §4.1): снятие требует
	// свежей сессии, граница включена (Р8). Перечень свежести не требует.
	Freshness time.Duration
	Observer  Observer
	Now       func() time.Time
	Logger    *slog.Logger
}

func (d *OwnSessionsDeps) init(verb string) error {
	switch {
	case d.Store == nil:
		return fmt.Errorf("%s: session store required", verb)
	case d.Freshness <= 0:
		return fmt.Errorf("%s: freshness window must be positive", verb)
	}
	if d.Observer == nil {
		d.Observer = NopObserver{}
	}
	if d.Now == nil {
		d.Now = time.Now
	}
	if d.Logger == nil {
		d.Logger = slog.Default()
	}
	return nil
}

// actingSession — запись носителя запроса на now: носителя нет, хранилище его
// не знает, запись снята, срок вышел, личность заблокирована — один отказ (Р9).
func (d OwnSessionsDeps) actingSession(ctx context.Context, bearer domain.SessionBearer, now time.Time) (Resolved, error) {
	if bearer.IsZero() {
		return Resolved{}, ErrAuthenticationFailed
	}
	resolved, reason, err := d.Store.Resolve(ctx, bearer.Digest(), now)
	if err != nil {
		d.Logger.ErrorContext(ctx, "own sessions: session store did not resolve the bearer", "err", err.Error())
		return Resolved{}, ErrStoreUnavailable
	}
	if reason != SessionFound {
		d.Observer.NoSessionObserved(reason)
		return Resolved{}, ErrAuthenticationFailed
	}
	return resolved, nil
}

// freshEnough — свежесть записи носителя (Р8): момент последнего предъявления
// не старше окна; ровно окно — свежая.
func (d OwnSessionsDeps) freshEnough(s domain.HumanSession, now time.Time) error {
	if now.Sub(s.LastPresentedAt) > d.Freshness {
		return ErrSessionNotFresh
	}
	return nil
}

// --- перечень ---

// ListOwnSessionsInput — носитель и страница.
type ListOwnSessionsInput struct {
	Bearer domain.SessionBearer
	Page   OwnSessionsPage
}

// OwnSession — элемент перечня: запись и пометка «текущая».
type OwnSession struct {
	Session domain.HumanSession
	Current bool
}

// ListOwnSessionsOutput — страница в порядке выдачи (created_at, id); пустой
// NextPageToken ⇔ страница последняя.
type ListOwnSessionsOutput struct {
	Sessions      []OwnSession
	NextPageToken string
}

// ListOwnSessionsUseCase — перечень живых записей субъекта носителя (Р4).
type ListOwnSessionsUseCase struct{ deps OwnSessionsDeps }

// NewListOwnSessionsUseCase — построение с проверкой зависимостей.
func NewListOwnSessionsUseCase(d OwnSessionsDeps) (*ListOwnSessionsUseCase, error) {
	if err := d.init("own sessions list"); err != nil {
		return nil, err
	}
	return &ListOwnSessionsUseCase{deps: d}, nil
}

// Execute — порядок: страница → носитель → чтение. Страница судится до
// хранилища.
func (uc *ListOwnSessionsUseCase) Execute(ctx context.Context, in ListOwnSessionsInput) (ListOwnSessionsOutput, error) {
	if err := in.Page.validate(); err != nil {
		return ListOwnSessionsOutput{}, err
	}
	now := uc.deps.Now().UTC()
	acting, err := uc.deps.actingSession(ctx, in.Bearer, now)
	if err != nil {
		return ListOwnSessionsOutput{}, err
	}
	rows, next, err := uc.deps.Store.SessionsOf(ctx, acting.User.ID, now, in.Page.Size, in.Page.Token)
	if err != nil {
		// Курсор уже судим выше тем же кодеком; отказ аргументом хранилища —
		// его авторитетный повтор на служимом пути, и он остаётся отказом формы.
		if errors.Is(err, iamerr.ErrInvalidArg) {
			return ListOwnSessionsOutput{}, &FieldError{Field: OwnSessionsPageTokenParam, Rule: "malformed"}
		}
		uc.deps.Logger.ErrorContext(ctx, "own sessions list: session store did not answer", "err", err.Error())
		return ListOwnSessionsOutput{}, ErrStoreUnavailable
	}
	out := ListOwnSessionsOutput{Sessions: make([]OwnSession, 0, len(rows)), NextPageToken: next}
	for _, s := range rows {
		out.Sessions = append(out.Sessions, OwnSession{Session: s, Current: s.ID == acting.Session.ID})
	}
	return out, nil
}

// --- выход из выбранной ---

// EndOwnSessionInput — носитель и названная запись (форма уже судима).
type EndOwnSessionInput struct {
	Bearer    domain.SessionBearer
	SessionID domain.HumanSessionID
}

// EndOwnSessionOutput — исход: запись снята (иначе — отказ).
type EndOwnSessionOutput struct{}

// EndOwnSessionUseCase — выход из выбранной своей записи (Р5, Р6).
type EndOwnSessionUseCase struct{ deps OwnSessionsDeps }

// NewEndOwnSessionUseCase — построение с проверкой зависимостей.
func NewEndOwnSessionUseCase(d OwnSessionsDeps) (*EndOwnSessionUseCase, error) {
	if err := d.init("own session end"); err != nil {
		return nil, err
	}
	return &EndOwnSessionUseCase{deps: d}, nil
}

// Execute — порядок: форма → носитель → свежесть → «это текущая» → замок
// личности → живость действующей → снятие с условием субъекта, живости и срока
// → событие → фиксация.
func (uc *EndOwnSessionUseCase) Execute(ctx context.Context, in EndOwnSessionInput) (EndOwnSessionOutput, error) {
	if _, ok := domain.ParseHumanSessionID(string(in.SessionID)); !ok {
		if in.SessionID == "" {
			return EndOwnSessionOutput{}, FieldRequired("sessionId")
		}
		return EndOwnSessionOutput{}, &FieldError{Field: "sessionId", Rule: domain.TextHumanSessionIDRule}
	}
	now := uc.deps.Now().UTC()
	acting, err := uc.deps.actingSession(ctx, in.Bearer, now)
	if err != nil {
		return EndOwnSessionOutput{}, err
	}
	if err := uc.deps.freshEnough(acting.Session, now); err != nil {
		return EndOwnSessionOutput{}, err
	}
	if in.SessionID == acting.Session.ID {
		return EndOwnSessionOutput{}, ErrSessionIsCurrent
	}
	ended, err := endOwnSessionsTx(ctx, uc.deps, acting, now, func(w Writer) ([]domain.HumanSessionID, error) {
		ok, err := w.EndOwnSession(ctx, acting.User.ID, in.SessionID, now, domain.RevokeReasonEndedFromAnotherSession)
		if err != nil || !ok {
			return nil, err
		}
		return []domain.HumanSessionID{in.SessionID}, nil
	})
	if err != nil {
		return EndOwnSessionOutput{}, err
	}
	if len(ended) == 0 {
		return EndOwnSessionOutput{}, ErrSessionNotFound
	}
	return EndOwnSessionOutput{}, nil
}

// --- выход из всех, кроме текущей ---

// EndOtherOwnSessionsInput — носитель.
type EndOtherOwnSessionsInput struct {
	Bearer domain.SessionBearer
}

// EndOtherOwnSessionsOutput — число снятых записей.
type EndOtherOwnSessionsOutput struct {
	Ended int
}

// EndOtherOwnSessionsUseCase — выход из всех своих записей, кроме текущей (Р7).
type EndOtherOwnSessionsUseCase struct{ deps OwnSessionsDeps }

// NewEndOtherOwnSessionsUseCase — построение с проверкой зависимостей.
func NewEndOtherOwnSessionsUseCase(d OwnSessionsDeps) (*EndOtherOwnSessionsUseCase, error) {
	if err := d.init("own sessions end others"); err != nil {
		return nil, err
	}
	return &EndOtherOwnSessionsUseCase{deps: d}, nil
}

// Execute — порядок: носитель → свежесть → замок личности → живость
// действующей → снятие прочих живых → событие (если снято хоть что-то) →
// фиксация.
func (uc *EndOtherOwnSessionsUseCase) Execute(ctx context.Context, in EndOtherOwnSessionsInput) (EndOtherOwnSessionsOutput, error) {
	now := uc.deps.Now().UTC()
	acting, err := uc.deps.actingSession(ctx, in.Bearer, now)
	if err != nil {
		return EndOtherOwnSessionsOutput{}, err
	}
	if err := uc.deps.freshEnough(acting.Session, now); err != nil {
		return EndOtherOwnSessionsOutput{}, err
	}
	ended, err := endOwnSessionsTx(ctx, uc.deps, acting, now, func(w Writer) ([]domain.HumanSessionID, error) {
		return w.EndOtherLiveSessions(ctx, acting.User.ID, acting.Session.ID, now, domain.RevokeReasonEndedFromAnotherSession)
	})
	if err != nil {
		return EndOtherOwnSessionsOutput{}, err
	}
	return EndOtherOwnSessionsOutput{Ended: len(ended)}, nil
}

// endOwnSessionsTx — общий исход обоих снимающих глаголов (Р6, Р7): транзакция,
// ПЕРВЫМ оператором которой взята строка личности замком писателя нескольких
// сессий; под ним — живость действующей записи, снятие (end) и событие. Снято
// ноль — событие не пишется, транзакция откатывается. Отказ любой записи —
// откат целиком.
func endOwnSessionsTx(ctx context.Context, d OwnSessionsDeps, acting Resolved, now time.Time,
	end func(w Writer) ([]domain.HumanSessionID, error),
) ([]domain.HumanSessionID, error) {
	w, err := d.Store.SessionSetWriter(ctx, acting.User.ID)
	if err != nil {
		d.Logger.ErrorContext(ctx, "own sessions end: writer not opened", "err", err.Error())
		return nil, ErrStoreUnavailable
	}
	defer func() { _ = w.Rollback(ctx) }()

	// Живость действующей — под тем же замком, что снятие (Р7): запись,
	// снятая встречным снятием, зафиксированным за ожидание замка, видна этому
	// оператору снятой.
	live, err := w.SessionLive(ctx, acting.User.ID, acting.Session.ID, now)
	if err != nil {
		d.Logger.ErrorContext(ctx, "own sessions end: acting session not read", "err", err.Error())
		return nil, ErrStoreUnavailable
	}
	if !live {
		d.Observer.NoSessionObserved(NoSessionEnded)
		return nil, ErrAuthenticationFailed
	}
	ended, err := end(w)
	if err != nil {
		d.Logger.ErrorContext(ctx, "own sessions end: end statement refused", "err", err.Error())
		return nil, ErrStoreUnavailable
	}
	if len(ended) == 0 {
		return nil, nil
	}
	ids := make([]string, 0, len(ended))
	for _, id := range ended {
		ids = append(ids, string(id))
	}
	if err := w.EmitAudit(ctx, outboxtypes.AuditEvent{
		EventType:       AuditSessionEndedByPerson,
		TenantAccountID: string(acting.User.AccountID),
		Payload: map[string]any{
			"user_id":           string(acting.User.ID),
			"session_id":        string(acting.Session.ID),
			"ended_session_ids": ids,
		},
	}); err != nil {
		d.Logger.ErrorContext(ctx, "own sessions end: audit event not written", "err", err.Error())
		return nil, ErrStoreUnavailable
	}
	if err := w.Commit(ctx); err != nil {
		d.Logger.ErrorContext(ctx, "own sessions end: commit refused", "err", err.Error())
		return nil, ErrStoreUnavailable
	}
	return ended, nil
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package humansession — полоса входа паролем, наша сессия человека, её
// носитель, выход, смена пароля и ответ краю о сессии (фаза Ф3, задача
// PRO-Robotech/kacho#1269; приёмка
// `docs/engineering/acceptance/login-lane-issues-our-session-and-logout-ends-it-server-side.md`).
//
// # Раскладка
//
// Порты — в этом файле; варианты использования — по глаголу: `issue.go`
// (операция выдачи, зовомая ИЗНУТРИ транзакции выдающего глагола — Д10),
// `login.go`, `logout.go`, `change_password.go`, `form_token.go`, `resolve.go`.
// Транспорт (HTTP-обработчик полосы формы и gRPC-обработчик `Resolve`) живёт в
// `internal/handler/loginlanehttp` и в `handler.go`; сюда транспорт не течёт.
//
// # Чего здесь нет — и это сказано
//
// Отсечка на предъявлении здесь НЕ применяется: её читает край (Р7, §8 инв. 8).
// `Resolve` отвечает «сессия» либо «сессии нет» и отсечки не видит.
package humansession

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// NoSessionReason — ПОЧЕМУ сессии нет. Наружу (краю, предъявителю) причина не
// выходит — она различима только клеткой счётчика и журналом (Ф1-11, Ф1-17,
// Ф3-27). Нулевое значение — сессия ЕСТЬ.
type NoSessionReason string

const (
	// SessionFound — записи есть, срок не вышел, личность не заблокирована.
	SessionFound NoSessionReason = ""
	// NoSessionUnknown — значения хранилище не знает.
	NoSessionUnknown NoSessionReason = "unknown"
	// NoSessionEnded — запись снята выходом либо сменой пароля из другой сессии.
	NoSessionEnded NoSessionReason = "ended"
	// NoSessionExpired — срок вышел.
	NoSessionExpired NoSessionReason = "expired"
	// NoSessionBlocked — запись жива, личность заблокирована администратором.
	NoSessionBlocked NoSessionReason = "blocked"
)

// NoSessionReasons — закрытый перечень причин: клетки счётчика заводятся по
// нему нулём до первого события (форма Ф-е).
func NoSessionReasons() []NoSessionReason {
	return []NoSessionReason{NoSessionUnknown, NoSessionEnded, NoSessionExpired, NoSessionBlocked}
}

// Resolved — сессия вместе с тем, что о её субъекте читает край.
type Resolved struct {
	Session       domain.HumanSession
	User          domain.User
	EmailVerified bool
}

// FailureScope — ось счёта неверных предъявлений (Р10): по адресу и по
// источнику.
type FailureScope string

const (
	FailureByAddress FailureScope = "address"
	FailureBySource  FailureScope = "source"
)

// Store — хранилище сессии человека, памяти первой аутентификации и счёта
// неверных предъявлений. Отказы — семейство `internal/errors`.
type Store interface {
	// Resolve — запись по дайджесту носителя на момент now. Причина ненулевая
	// ⇔ сессии нет; тогда Resolved пуст.
	Resolve(ctx context.Context, digest domain.BearerDigest, now time.Time) (Resolved, NoSessionReason, error)
	// CountFailures — неверных предъявлений по оси и ключу с момента since.
	CountFailures(ctx context.Context, scope FailureScope, key string, since time.Time) (int, error)
	// OldestFailureSince — момент самого раннего неверного предъявления в окне
	// (по нему считается `Retry-After`: окно кончается, когда он состарится).
	OldestFailureSince(ctx context.Context, scope FailureScope, key string, since time.Time) (time.Time, bool, error)
	// FirstAuthentication — момент первой аутентификации личности нашей
	// посадкой (Р5). found=false — посадка эту личность ещё не аутентифицировала.
	FirstAuthentication(ctx context.Context, userID domain.UserID) (time.Time, bool, error)
	// Writer открывает транзакцию записи. Вызывающий обязан Commit либо Rollback.
	Writer(ctx context.Context) (Writer, error)
}

// Writer — одна транзакция записи. Всё, что глагол делает «одним исходом»
// (Р4, Р6, Ф3-47), делает через ОДИН Writer.
type Writer interface {
	// InsertSession кладёт запись; дайджест носителя уникален (23505 →
	// ALREADY_EXISTS; при 256 битах случайности это наша ошибка, а не гонка).
	InsertSession(ctx context.Context, s domain.HumanSession, digest domain.BearerDigest) error
	// RememberFirstAuthentication — запись на личность, МЕНЬШИЙ из двух моментов
	// (Р5): при стоящей записи не поднимает никогда.
	RememberFirstAuthentication(ctx context.Context, userID domain.UserID, at time.Time) error
	// FirstAuthentication — то же чтение внутри транзакции.
	FirstAuthentication(ctx context.Context, userID domain.UserID) (time.Time, bool, error)
	// EndSession снимает запись выходом: ended=false — записи нет либо она уже
	// снята (второй выход ничего не пишет — Ф1-18).
	EndSession(ctx context.Context, id domain.HumanSessionID, at time.Time, reason string) (ended bool, err error)
	// EndOtherSessions снимает ВСЕ прочие живые записи личности, кроме keep
	// (Ф1-15, Ф1-65); отвечает числом снятых.
	EndOtherSessions(ctx context.Context, userID domain.UserID, keep domain.HumanSessionID, at time.Time, reason string) (int, error)
	// RotateBearer перевыпускает носитель записи (Ф11 Р5): прежний дайджест
	// перестаёт находить запись, момент аутентификации и срок прежние, момент
	// последнего предъявления сдвигается на presentedAt.
	RotateBearer(ctx context.Context, id domain.HumanSessionID, digest domain.BearerDigest, presentedAt time.Time) error
	// ClearPasswordChangeRequired снимает требование сменить пароль с записи
	// (Ф5-24): исход смены пароля из сессии восстановления.
	ClearPasswordChangeRequired(ctx context.Context, id domain.HumanSessionID) error
	// UpsertCutoff — операция записи отсечки (§4.1 п.17): момент монотонен;
	// причина и актор идут за ПРИНЯТЫМ моментом, на равных стоит последняя.
	UpsertCutoff(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error
	// ReplaceLoginVerifier замещает материал способа входа одним оператором
	// (ID-PW-1 PWV-10): replaced=false — строки способа нет.
	ReplaceLoginVerifier(ctx context.Context, m domain.LoginMethod) (replaced bool, err error)
	// RecordFailure — одно неверное предъявление по оси и ключу.
	RecordFailure(ctx context.Context, scope FailureScope, key string, at time.Time) error
	// ResetFailures снимает счёт по оси и ключу (успешный вход обнуляет счёт по
	// адресу — Р10).
	ResetFailures(ctx context.Context, scope FailureScope, key string) error
	// EmitAudit — событие аудита в очередь той же транзакцией (форма Ф-м).
	EmitAudit(ctx context.Context, ev outboxtypes.AuditEvent) error

	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// FailureSweeper / SessionSweeper — порты уборки (форма Ф-ж): записи, которые
// `Resolve` уже не обслужит ни при каком носителе, и следы неверных
// предъявлений старше самого длинного окна.
type SessionSweeper interface {
	SweepUnservableSessions(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

type FailureSweeper interface {
	SweepAgedFailures(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

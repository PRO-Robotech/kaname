// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package humansession — полоса входа паролем, наша сессия человека, её
// носитель, выход, смена пароля, ответ краю о сессии (фаза Ф3, задача
// PRO-Robotech/kacho#1269; приёмка
// `docs/engineering/acceptance/login-lane-issues-our-session-and-logout-ends-it-server-side.md`)
// и восстановление доступа кодом по почте (фаза Ф5, задача
// PRO-Robotech/kacho#1271; приёмка `docs/engineering/acceptance/recovery-of-access.md`).
//
// # Раскладка
//
// Порты — в этом файле; варианты использования — по глаголу: `issue.go`
// (операция выдачи, зовомая ИЗНУТРИ транзакции выдающего глагола — Д10),
// `login.go`, `logout.go`, `change_password.go`, `form_token.go`, `resolve.go`,
// `recovery_request.go` (запрос кода), `recovery_complete.go` (предъявление
// кода с новым паролем), `dispatch.go` (работа вне пути ответа — Ф5 Р2).
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

// RecoveryTarget — человек, которому адресован запрос восстановления, вместе с
// подтверждённостью его адреса (Ф1-25: код — для подтверждённого адреса).
type RecoveryTarget struct {
	User          domain.User
	EmailVerified bool
}

// RecoveryMailIntent — намерение отправить письмо восстановления: пишется той же
// транзакцией, что строка кода (Ф5-09). Код уходит в письмо своей формой для
// человека — единственным своим выходом к нему.
type RecoveryMailIntent struct {
	UserID    domain.UserID
	AccountID domain.AccountID
	To        string
	Code      domain.RecoveryCodeValue
	// ValidFor — срок кода, как его назовёт письмо.
	ValidFor time.Duration
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
	// RecoveryTarget — человек по адресу вместе с подтверждённостью адреса
	// ОДНИМ чтением: обе полосы запроса восстановления (адрес есть · адреса
	// нет) стоят одинаково (Ф5 Р2, Р7). found=false — адреса нет ни у кого.
	RecoveryTarget(ctx context.Context, email domain.Email) (RecoveryTarget, bool, error)
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
	// PresentInSession — предъявление способа ВНУТРИ сессии (Ф11 Р5, Ф12):
	// множество предъявленного, уровень (по правилу, вычислен вызывающим),
	// новый дайджест носителя и момент последнего предъявления — одной записью
	// на живой строке; момент аутентификации и срок не трогаются.
	PresentInSession(ctx context.Context, id domain.HumanSessionID, methods []string, level string, digest domain.BearerDigest, presentedAt time.Time) error
	// UpsertCutoff — операция записи отсечки (§4.1 п.17): момент монотонен;
	// причина и актор идут за ПРИНЯТЫМ моментом, на равных стоит последняя.
	UpsertCutoff(ctx context.Context, u domain.UserTokenRevocation, revokedBy domain.UserID) error
	// ReplaceLoginVerifier замещает материал способа входа одним оператором
	// (ID-PW-1 PWV-10): replaced=false — строки способа нет.
	ReplaceLoginVerifier(ctx context.Context, m domain.LoginMethod) (replaced bool, err error)
	// LoginMethod — строка способа входа человека данного вида, прочитанная
	// ЭТОЙ транзакцией: то же чтение, что `loginmethod.Store.Get` (NOT_FOUND —
	// строки нет), но соединением открытой транзакции, а не вторым из пула —
	// вложенного захвата соединения у него нет (шапка `completed_login.go`).
	LoginMethod(ctx context.Context, userID domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error)
	// RecordFailure — одно неверное предъявление по оси и ключу.
	RecordFailure(ctx context.Context, scope FailureScope, key string, at time.Time) error
	// ResetFailures снимает счёт по оси и ключу (успешный вход обнуляет счёт по
	// адресу — Р10).
	ResetFailures(ctx context.Context, scope FailureScope, key string) error
	// EmitAudit — событие аудита в очередь той же транзакцией (форма Ф-м).
	EmitAudit(ctx context.Context, ev outboxtypes.AuditEvent) error

	// --- восстановление доступа (Ф5) ---

	// InsertRecoveryCode кладёт строку кода (свёртку, не значение — Р1).
	InsertRecoveryCode(ctx context.Context, c domain.RecoveryCode) error
	// SupersedeRecoveryCodes снимает неприменённые коды личности: живой код у
	// личности один, и новый запрос вытесняет прежний. Отвечает числом снятых.
	SupersedeRecoveryCodes(ctx context.Context, userID domain.UserID) (int, error)
	// ConsumeRecoveryCode — ОДИН оператор применения (Р1, Ф5-05): строка
	// личности с этой свёрткой, ещё не применённая и не истёкшая на now,
	// получает отметку применения. found=false — такого кода нет, он применён
	// либо истёк; различать это вызывающему незачем — отказ один (Ф5-04, Ф5-07).
	ConsumeRecoveryCode(ctx context.Context, userID domain.UserID, digest domain.CodeDigest, now time.Time) (domain.RecoveryCode, bool, error)
	// EmitRecoveryMail — намерение отправить письмо восстановления той же
	// транзакцией, что строка кода (Ф5-09, Р3).
	EmitRecoveryMail(ctx context.Context, in RecoveryMailIntent) error
	// InsertRecoveryCompletion — журнал завершений по ключу потока (Р4, форма
	// Ф-а): inserted=false — ключ уже стоит, побочных записей делать нельзя.
	InsertRecoveryCompletion(ctx context.Context, rc domain.RecoveryCompletion) (inserted bool, err error)

	// --- второй фактор (Ф12, kacho#1281) — операторы над таблицей способов
	// входа; каждый живёт в адаптере таблицы секрета, писатель сессии их
	// делегирует. Инварианты держит база (ban #10): ключ «человек, вид»,
	// условные операторы, замок строки набора.

	// UpsertPendingTOTP — ОДИН оператор заведения под ключом «человек, вид»
	// (Ф12-05, F4d-14 в части исхода): строки нет — вставка `pending`; строка
	// `pending` — замена секрета и момента заведения; строка `active` —
	// accepted=false, ничего не записано. Проверки перед вставкой нет.
	UpsertPendingTOTP(ctx context.Context, m domain.LoginMethod) (accepted bool, err error)
	// ActivateTOTP — CAS подтверждения (Ф12-07): строка `pending` с ЭТИМ моментом
	// заведения (pendingSince — версия строки) становится `active` с принятым
	// шагом и моментом подтверждения; activated=false — строки `pending` того
	// заведения нет (уже `active`, заменена, снята).
	ActivateTOTP(ctx context.Context, userID domain.UserID, pendingSince time.Time, step int64, at time.Time) (activated bool, err error)
	// ReplaceLookupSet — набор запасных кодов целиком: вставка либо замена
	// строки `lookup_secret` (Ф12 Р6: перечеканка заменяет набор целиком).
	ReplaceLookupSet(ctx context.Context, m domain.LoginMethod) error
	// LockLookupSet — строка набора ПОД ЗАМКОМ до конца транзакции
	// (сериализация чтения-изменения-записи набора, Ф12-24): сравнение и
	// потребление идут под ним. found=false — набора нет.
	LockLookupSet(ctx context.Context, userID domain.UserID) (domain.LoginMethod, bool, error)
	// ConsumeLookupElement — снятие ОДНОГО элемента набора по его значению
	// (Ф12-23): consumed=false — такого элемента в наборе нет.
	ConsumeLookupElement(ctx context.Context, userID domain.UserID, element string) (consumed bool, err error)
	// RecordAcceptedStep — условная запись принятого шага (Ф12 Р5, Ф12-22):
	// проходит, когда строка `active` и шаг старше последнего принятого;
	// recorded=false — повтор либо младший шаг либо строка не `active`.
	RecordAcceptedStep(ctx context.Context, userID domain.UserID, step int64) (recorded bool, err error)
	// RemoveSecondFactor — строки `totp` (`active`) и `lookup_secret` сняты
	// одним оператором (Ф12-28, Ф12-30); removed=false — заведённого фактора
	// нет, и строка `pending` при этом НЕ тронута (матрица Р4).
	RemoveSecondFactor(ctx context.Context, userID domain.UserID) (removed bool, err error)

	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// EnrollmentSweeper — порт уборки неподтверждённых заведений второго фактора
// (Ф12-44): строки `pending`, чей срок (окно Р8 от момента заведения) истёк,
// — `confirm` их уже не примет ни при каком коде.
type EnrollmentSweeper interface {
	SweepExpiredEnrollments(ctx context.Context, window time.Duration, batch int) (int64, bool, error)
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

// RecoveryCodeSweeper — порт уборки кодов восстановления: применённые и
// истёкшие строки, которые оператор применения уже не обслужит.
type RecoveryCodeSweeper interface {
	SweepUnservableRecoveryCodes(ctx context.Context, grace time.Duration, batch int) (int64, bool, error)
}

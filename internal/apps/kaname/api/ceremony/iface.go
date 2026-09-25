// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package ceremony — церемония OAuth 2.1 `authorization_code` нашими силами
// (под-фаза LINE-A-1, задача PRO-Robotech/kacho#2721; контракт для
// арендатора — `docs/content/api/authorization-code.mdx`).
//
// Три глагола: выдача кода эндпоинтом авторизации, обмен кода на наш
// подписанный предъявитель и ротация обновляющего удостоверения. Транспорта
// здесь нет: обработчики разбирают запрос в входы этого пакета и печатают его
// решения.
//
// # Кто решает, аутентифицирован ли человек, — ШОВ, а не церемония
//
// Церемония спрашивает порт [LoginAuthority] и знает ЧТО предъявлено (субъект,
// сессия, момент, уровень), но не ЧЕМ получено (Р2). «Не аутентифицирован» —
// отдельное представление (второе возвращаемое `false`), а не субъект-заглушка
// и не пустая строка: на этом исходе код не выдаётся и записи кода не
// создаётся.
//
// # Связку назначает выдача, и ВСЯКАЯ её проверка — в операторе базы
//
// Запись кода заводится условной вставкой, судящей клиента, цель и сессию в
// том же операторе; потребление — одним оператором с условием «не потреблён,
// не истёк, тот же клиент, та же цель, тот же вызов PKCE, сессия жива» (Р5,
// ban #10). Субъект, уровень и момент обмен читает у записи сессии, на которую
// ссылается код, — присланные вызывающим значения этих полей не читаются вовсе.
package ceremony

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	"github.com/PRO-Robotech/kaname/internal/service"
	"github.com/PRO-Robotech/kaname/internal/tokensigner"
)

// Authentication — ответ шва о человеке: кто, какой сессией, когда и каким
// уровнем аутентифицирован. Уровень — строка закрытой оси записи сессии:
// производитель у него один (`assurance.LevelOf`), здесь он только читается.
type Authentication struct {
	Subject         domain.UserID
	Session         domain.HumanSessionID
	AuthenticatedAt time.Time
	Level           string
}

// LoginAuthority — шов «авторитет входа» (Р2). Второе возвращаемое `false` —
// «не аутентифицирован»; ошибка — «спросить не смогли», третий исход, не
// сливающийся ни с одним из двух.
type LoginAuthority interface {
	Resolve(ctx context.Context, presented domain.SessionBearer) (Authentication, bool, error)
}

// ClientRegistry — чтение интерактивного клиента по НАШЕМУ идентификатору.
// Второе возвращаемое `false` — строки нет; снятый клиент возвращается
// строкой со своим статусом (судит вызывающий).
type ClientRegistry interface {
	InteractiveClient(ctx context.Context, id domain.InteractiveClientID) (domain.InteractiveClient, bool, error)
	// ClientSecret — проверочное значение секрета клиента. Нулевое значение —
	// секрета нет (законное состояние строки).
	ClientSecret(ctx context.Context, id domain.InteractiveClientID) (ClientSecret, bool, error)
}

// ClientSecret — то, чем клиент аутентифицируется на обмене.
type ClientSecret struct {
	Active   bool
	Verifier domain.LoginVerifier
}

// SecretVerifier — проверяющий предъявленного секрета против проверочного
// значения. Реализуется `passwordverify.Verifier`: разбор значения, потолок
// стоимости и ёмкость — его, а не этого пакета.
type SecretVerifier interface {
	Verify(stored domain.LoginVerifier, presented string) passwordverify.Result
}

// CodeIssue — запись выдаваемого кода.
type CodeIssue struct {
	Digest        domain.CeremonySecretDigest
	Client        domain.InteractiveClientID
	Session       domain.HumanSessionID
	Subject       domain.UserID
	RedirectURI   string
	Scope         string
	CodeChallenge string
	TTL           time.Duration
}

// CodeRedemption — предъявление кода на обмене. Challenge — вызов,
// ВЫЧИСЛЕННЫЙ из присланного `code_verifier`; сравнение с сохранённым — в
// операторе потребления.
type CodeRedemption struct {
	Digest      domain.CeremonySecretDigest
	Client      domain.InteractiveClientID
	RedirectURI string
	Challenge   string
	Grant       domain.AuthorizationGrantID
}

// Grant — авторизация (семейство токенов) вместе с фактами сессии, которые
// переносятся в предъявитель.
type Grant struct {
	ID               domain.AuthorizationGrantID
	Client           domain.InteractiveClientID
	Subject          domain.UserID
	Session          domain.HumanSessionID
	Scope            string
	AuthenticatedAt  time.Time
	Level            string
	SessionExpiresAt time.Time
}

// FamilyRevocation — отзыв семейства, записываемый той же транзакцией, что
// обнаружение повтора.
type FamilyRevocation struct {
	Grant  domain.AuthorizationGrantID
	Reason RevocationReason
	// Before — отсечка предъявителей семейства: всё, выпущенное раньше неё,
	// недействительно на предъявлении.
	Before time.Time
}

// RevocationReason — причина отзыва семейства; словарь закрыт и совпадает с
// CHECK хранилища.
type RevocationReason string

const (
	// RevokedCodeReplay — потреблённый код предъявлен повторно (Р8, 13).
	RevokedCodeReplay RevocationReason = "code-replay"
	// RevokedRefreshReplay — ротированное удостоверение предъявлено повторно
	// (Р8, 21, 28).
	RevokedRefreshReplay RevocationReason = "refresh-replay"
)

// CodeRefusal — почему предъявленный код не потреблён. Наружу — один ответ на
// все значения (Р10); различимость живёт в журнале и счётчике.
type CodeRefusal string

const (
	CodeUnknown          CodeRefusal = "unknown"
	CodeConsumed         CodeRefusal = "consumed"
	CodeExpired          CodeRefusal = "expired"
	CodeClientMismatch   CodeRefusal = "client-mismatch"
	CodeRedirectMismatch CodeRefusal = "redirect-mismatch"
	CodeVerifierMismatch CodeRefusal = "verifier-mismatch"
	CodeSessionEnded     CodeRefusal = "session-ended"
)

// RefreshState — состояние предъявленного обновляющего удостоверения, как его
// видит транзакция, держащая замок семейства.
type RefreshState struct {
	Found       bool
	Grant       Grant
	Rotated     bool
	Revoked     bool
	SessionLive bool
	// CutOff — отсечка субъекта покрывает момент аутентификации сессии.
	CutOff bool
}

// Store — хранилище церемонии.
type Store interface {
	// IssueCode — условная вставка записи кода: запись ложится, только если
	// клиент `ACTIVE`, цель в его списке и сессия жива — тем же оператором.
	// `false` — условие не выполнено.
	IssueCode(ctx context.Context, in CodeIssue) (bool, error)
	// ClassifyCode — почему код не потреблён. Только для журнала: решение об
	// отказе уже принято оператором потребления.
	ClassifyCode(ctx context.Context, in CodeRedemption) (CodeRefusal, error)
	Writer(ctx context.Context) (Writer, error)
}

// Writer — транзакция церемонии.
type Writer interface {
	// RedeemCode — атомарное потребление кода с заведением авторизации.
	// `false` — ноль строк: код неизвестен, потреблён, истёк либо связка не та.
	RedeemCode(ctx context.Context, in CodeRedemption) (Grant, bool, error)
	// RevokeFamilyOfCode — отзыв авторизации, выданной по УЖЕ потреблённому
	// коду. `false` — отзывать нечего (код не потреблялся либо уже отозван).
	RevokeFamilyOfCode(ctx context.Context, digest domain.CeremonySecretDigest, before time.Time) (Grant, bool, error)
	// LockRefresh — замок семейства предъявленного удостоверения и его
	// состояние, прочитанное ПОСЛЕ замка.
	LockRefresh(ctx context.Context, digest domain.CeremonySecretDigest) (RefreshState, error)
	// RotateRefresh — CAS ротации: предшественник помечается той же
	// транзакцией, что заводится преемник. `false` — предшественник уже
	// ротирован (повтор).
	RotateRefresh(ctx context.Context, prev, next domain.CeremonySecretDigest, grant domain.AuthorizationGrantID) (bool, error)
	// InsertRefresh — первое удостоверение семейства.
	InsertRefresh(ctx context.Context, digest domain.CeremonySecretDigest, grant domain.AuthorizationGrantID) error
	// RevokeFamily — отзыв семейства с отсечкой его предъявителей.
	RevokeFamily(ctx context.Context, in FamilyRevocation) (bool, error)
	EmitAudit(ctx context.Context, ev outboxtypes.AuditEvent) error
	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// Signer — порт подписанта.
type Signer interface {
	Sign(ctx context.Context, req tokensigner.Request) (tokensigner.Token, error)
	Issuer() string
}

// Users — чтение человека, за которого говорит предъявитель.
type Users interface {
	GetByID(ctx context.Context, id domain.UserID) (domain.User, error)
}

// ClaimSource — ОДНО объявление состава утверждений человека: тот же
// производитель, что у прочих полос выдачи.
type ClaimSource interface {
	UserClaims(u domain.User, subject string, hookCtx service.TokenHookContext) map[string]any
}

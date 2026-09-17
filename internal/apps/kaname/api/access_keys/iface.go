// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package access_keys — глаголы ключа доступа человека: сервер церемонии
// регистрации, перечень, снятие, испытание и проверка утверждения (iam Ф7,
// PRO-Robotech/kacho#1273; приёмка
// `docs/engineering/acceptance/access-keys-are-ours.md`, Р1…Р11).
//
// # Раскладка
//
// Порты — здесь; зависимости и величины контракта — `deps.go`; отказы —
// `refusals.go`; глаголы — по файлу на каждый: `begin_registration.go`,
// `finish_registration.go`, `list.go`, `revoke.go`, `begin_assertion.go`,
// `finish_assertion.go`; события аудита — `audit.go`; транспорт — `handler.go`.
// Сверка байтов — `internal/webauthnverify`, один проверяющий на дерево
// (Ф13 Р13); сюда транспорт не течёт, а pgx и заглушки контракта — тем более.
//
// # Кто вызывающий — и что здесь значит «сессия»
//
// Глаголы — публичные RPC (Р11). Вызывающего называет слушатель: личность,
// переданная краем из сессии человека, либо предъявленное им удостоверение.
// Записи сессии на этой полосе нет by construction — край не передаёт её
// номера. Поэтому «сессия» приёмки здесь — ВЫЗЫВАЮЩИЙ: испытание выдаётся ему
// и находится только у него (Ф7-55), утверждение принимается только его
// ключа (Ф7-51), а свежесть — момент последнего предъявления человека — читает
// порт `Freshness` из хранилища сессий. Граница названа в порте.
package access_keys

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/outboxtypes"
)

// Store — хранилище ключей и испытаний. Отказы — семейство `internal/errors`.
type Store interface {
	// KeyByCredentialID — строка ключа по идентификатору удостоверения (Ф7-08,
	// Ф7-09); found=false — строки нет.
	KeyByCredentialID(ctx context.Context, credentialID []byte) (domain.AccessKey, bool, error)
	// KeysOf — перечень ключей человека постранично, в порядке заведения.
	KeysOf(ctx context.Context, userID domain.UserID, pageToken string, pageSize int32) ([]domain.AccessKey, string, error)
	// CredentialIDsOf — идентификаторы удостоверений человека для
	// `allowCredentials` испытания предъявления.
	CredentialIDsOf(ctx context.Context, userID domain.UserID) ([][]byte, error)
	// Challenge — выданное испытание по его байтам, ПРИВЯЗАННОЕ к вызывающему и
	// процедуре (Р11): чужое и невыданное неразличимы — found=false у обоих.
	Challenge(ctx context.Context, challenge []byte, userID domain.UserID, purpose domain.AccessKeyChallengePurpose) (domain.AccessKeyChallenge, bool, error)
	// UserOf — человек ОДНИМ чтением: аккаунт (для метаданных операции),
	// состояние (только ACTIVE заводит ключ — как у удостоверений-соседей),
	// адрес и имя (их показывает аутентификатор во время церемонии; в строку
	// ключа они не попадают). Нет человека — ErrNotFound.
	UserOf(ctx context.Context, id domain.UserID) (domain.User, error)
	// Writer открывает транзакцию записи. Вызывающий обязан Commit либо Rollback.
	Writer(ctx context.Context) (Writer, error)
}

// Writer — одна транзакция записи. Строка ключа, потребление испытания и
// событие аудита ложатся одним исходом (§4.1 п. 11).
type Writer interface {
	// InsertChallenge кладёт выданное испытание.
	InsertChallenge(ctx context.Context, c domain.AccessKeyChallenge) error
	// ConsumeChallenge — ОДИН оператор однократности (Ф7-03, Ф7-53): строка
	// вызывающего этой процедуры, не потреблённая и не истёкшая на now,
	// получает отметку; consumed=false — её нет, она потреблена либо истекла.
	ConsumeChallenge(ctx context.Context, challenge []byte, userID domain.UserID, purpose domain.AccessKeyChallengePurpose, now time.Time) (consumed bool, err error)
	// InsertKey кладёт строку ключа. Уникальность идентификатора удостоверения
	// (23505 → ALREADY_EXISTS) и слот потолка (KQ001/KQ002) держит база.
	InsertKey(ctx context.Context, k domain.AccessKey) (domain.AccessKey, error)
	// LockKeysOf — строки ключей человека ПОД ЗАМКОМ до конца транзакции:
	// сериализует «сосчитать способы — снять» (Ф7-26, ban #10).
	LockKeysOf(ctx context.Context, userID domain.UserID) ([]domain.AccessKey, error)
	// DeleteOwnedByID снимает строку ОДНИМ оператором, суженным владельцем;
	// found=false — строки нет ЛИБО она чужая, и это неразличимо by
	// construction (Ф7-27).
	DeleteOwnedByID(ctx context.Context, userID domain.UserID, id domain.AccessKeyID) (domain.AccessKey, bool, error)
	// AdvanceSignCount — атомарный сдвиг счётчика и момента предъявления с
	// условием на прежнее значение (Р6): advanced=false — проигравший
	// конкуренции. При reported == expected == 0 сдвигается только момент.
	AdvanceSignCount(ctx context.Context, id domain.AccessKeyID, expected, reported uint32, usedAt time.Time) (advanced bool, err error)
	// EmitAudit — событие аудита той же транзакцией (§4.1 п. 11).
	EmitAudit(ctx context.Context, ev outboxtypes.AuditEvent) error

	Commit(ctx context.Context) error
	Rollback(ctx context.Context) error
}

// Freshness — момент последнего предъявления человека (Р5, Ф7-04, Ф7-36).
//
// ГРАНИЦА НАЗВАНА. Полоса RPC записи сессии не видит: край передаёт личность и
// уровень, а не номер записи. Поэтому порт спрашивает о ЧЕЛОВЕКЕ, и адаптер
// отвечает самым свежим предъявлением среди его ЖИВЫХ сессий. У человека с
// двумя сессиями окно открывает любая из них — это шире, чем окно одной
// сессии у полосы формы (Ф12), и это сказано здесь, а не выведено читателем.
// found=false — живых сессий нет: предъявления не было.
type Freshness interface {
	LastPresentedAt(ctx context.Context, userID domain.UserID) (time.Time, bool, error)
}

// LoginMethods — есть ли у человека способ входа паролем: «последний способ
// входа не снимается» (Ф7-26) судит по строке пароля И числу ключей.
type LoginMethods interface {
	HasPassword(ctx context.Context, userID domain.UserID) (bool, error)
}

// Observer — наблюдаемость (Ф7-18: громкое состояние на убывании счётчика;
// клетки заводятся нулём по закрытым перечням).
type Observer interface {
	AccessKeyRefusalObserved(lane Lane, reason Refusal)
	AccessKeyEventObserved(event Event)
	// SignCountRegressionObserved — единственный сигнал клонирования (Р6).
	SignCountRegressionObserved()
}

// NopObserver — наблюдатель, который ничего не считает.
type NopObserver struct{}

func (NopObserver) AccessKeyRefusalObserved(Lane, Refusal) {}
func (NopObserver) AccessKeyEventObserved(Event)           {}
func (NopObserver) SignCountRegressionObserved()           {}

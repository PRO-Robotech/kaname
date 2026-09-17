// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package registration

// iface.go — порты глагола регистрации.
//
// # Одна транзакция — один Writer (Р1)
//
// Три следствия пишет ОДИН writer: зеркало (`Mirror` — композиция
// `user.RegisterMirrorTx` над писателем зеркала той же транзакции), строка способа входа
// (`InsertLoginMethod`), строка сессии и её память (`humansession.Writer`).
// Адаптер (`internal/repo/kaname/pg`) собирает всё это над одной транзакцией
// базы; сшивка приложением тремя writer'ами здесь невыразима: у порта нет
// способа открыть второй.

import (
	"context"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/humansession"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/user"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// MirrorInput / MirrorResult — вход и исход заведения зеркала (Р6, `user`).
type (
	MirrorInput  = user.MirrorInput
	MirrorResult = user.MirrorResult
)

// Store — хранилище регистрации: открывает ОДНУ транзакцию трёх следствий.
type Store interface {
	// Writer открывает транзакцию записи. Вызывающий обязан Commit либо Rollback.
	Writer(ctx context.Context) (Writer, error)
}

// Writer — одна транзакция трёх следствий.
type Writer interface {
	// Сессия, память первой аутентификации, событие аудита (Ф3 Р1) — тем же
	// writer'ом: `humansession.IssueSession` зовётся изнутри этой транзакции.
	humansession.Writer

	// Mirror — зеркало пользователя (Р6): приглашение по адресу активируется
	// той же полосой, иначе заводится новая строка; личный аккаунт, проект,
	// самопривязки, намерения материализации — одним исходом с прочими
	// записями ЭТОЙ транзакции. Композиция — `user.RegisterMirrorTx` над
	// писателем зеркала той же транзакции; исполняет её адаптер порта в
	// композиционном корне (адаптер базы порт не импортирует — круг импортов
	// в пробах пакета зеркала). Занятость адреса судит ключ базы:
	// ErrAlreadyExists.
	Mirror(ctx context.Context, in MirrorInput) (MirrorResult, error)

	// InsertLoginMethod — строка способа входа человека (Ф2 П1) в этой же
	// транзакции. ALREADY_EXISTS — способ этого вида у человека уже есть.
	InsertLoginMethod(ctx context.Context, m domain.LoginMethod) error
}

// PasswordJudge — правило пароля Ф3 (одно на три полосы, Ф1-32…38):
// регистрация зовёт его и своего не заводит.
type PasswordJudge interface {
	Judge(ctx context.Context, email, password string) error
}

// OwnerBindingReconciler — пост-коммитная материализация собственнической
// выдачи (та же, что у провизион-хука). nil-safe: без неё материализует
// периодическая уборка по намерениям, лежащим в очереди той же транзакцией.
type OwnerBindingReconciler = user.OwnerBindingReconciler

// Outcome — исход регистрации по причине. Перечень закрыт: вызывающий видит
// ОДИН отказ (Р3), причина различима только клеткой счётчика и журналом.
type Outcome string

const (
	OutcomeIssued        Outcome = "issued"
	OutcomeIssuedInvited Outcome = "issued-invited" // приглашение активировано (Ф4-23)
	// OutcomeRefusedOccupied — адрес принадлежит личности, либо приглашение
	// уже активировал конкурент, либо тот же человек повторил обращение (Ф4-24).
	OutcomeRefusedOccupied Outcome = "refused-occupied"
	// OutcomeRefusedInviteExpired — приглашение по адресу пережило срок и
	// держит ключ почты (паритет с полосой поставщика).
	OutcomeRefusedInviteExpired Outcome = "refused-invite-expired"
	// OutcomeRefusedRate — потолок темпа заведения исчерпан (Р5).
	OutcomeRefusedRate Outcome = "refused-rate"
	// OutcomeRefusedPassword — правило пароля отвергло (Ф1-32).
	OutcomeRefusedPassword Outcome = "refused-password"
	OutcomeStoreFailed     Outcome = "store-failed"
)

// Outcomes — закрытый перечень исходов: клетки заводятся нулём до первого
// события.
func Outcomes() []Outcome {
	return []Outcome{
		OutcomeIssued, OutcomeIssuedInvited, OutcomeRefusedOccupied, OutcomeRefusedInviteExpired,
		OutcomeRefusedRate, OutcomeRefusedPassword, OutcomeStoreFailed,
	}
}

// Observer — приёмник событий регистрации. Дёшев и ничего не возвращает:
// наблюдение не меняет исхода.
type Observer interface {
	RegistrationObserved(lane string, outcome Outcome)
}

// NopObserver — приёмник, ничего не считающий; для проб, не о наблюдаемости.
type NopObserver struct{}

func (NopObserver) RegistrationObserved(string, Outcome) {}

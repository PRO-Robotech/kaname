// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package loginmethod — порт хранилища способа входа человека и
// подтверждённости его адреса (фаза Ф2, часть П1, задача
// PRO-Robotech/kacho#1268).
//
// # Кто его зовёт
//
// Вызывающих в прод-коде у порта в этой части НЕТ, и это сказано прямо, а не
// оставлено читателю выводить из тишины. Их двое, и оба приходят своими
// частями той же линии: перенос личностей (часть П3 фазы Ф2) присоединяет
// способ к существующему человеку, полоса входа (Ф3) читает способ и отметку
// подтверждённости. До них порт держат интеграционные пробы адаптера
// (`internal/repo/kaname/pg/login_method_repo_integration_test.go`), и они же
// утверждают, что адаптер его исполняет.
//
// # Чего порт НЕ делает
//
// Не проверяет пароль и не судит формат материала — это проверяющий (часть П2),
// и его ещё нет. Не выдаёт материал наружу: `domain.LoginVerifier` не
// печатается и не сериализуется, а его выход держит гейт дерева
// `internal/check` `TestLoginVerifierStaysInside`.
package loginmethod

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Store — хранилище способа входа и подтверждённости адреса.
//
// Отказы — семейство `internal/errors`; коды сказаны у каждого метода.
type Store interface {
	// Create заводит способ.
	//
	//   - INVALID_ARGUMENT — строка негодна (`domain.LoginMethod.Validate`); до
	//     базы вход не доходит;
	//   - ALREADY_EXISTS — у человека уже есть способ этого вида. Производит
	//     ключ базы, поэтому под конкуренцией проходит ровно одна вставка;
	//   - FAILED_PRECONDITION — человека нет.
	Create(ctx context.Context, m domain.LoginMethod) (domain.LoginMethod, error)

	// Get читает способ человека данного вида. NOT_FOUND — такого способа нет.
	Get(ctx context.Context, userID domain.UserID, kind domain.LoginMethodKind) (domain.LoginMethod, error)

	// MarkEmailVerified записывает момент подтверждения адреса address человеку
	// userID — ТОЛЬКО если текущий адрес человека побайтово равен address.
	// Подтверждённость есть свойство значения: подтверждение значения, которое
	// успело смениться, не ложится.
	//
	//   - INVALID_ARGUMENT — момент нулевой;
	//   - NOT_FOUND — человека нет;
	//   - FAILED_PRECONDITION — текущий адрес не тот, что подтверждали.
	MarkEmailVerified(ctx context.Context, userID domain.UserID, address domain.Email, at time.Time) error

	// EmailVerification — момент подтверждения ТЕКУЩЕГО адреса. Исходов три,
	// и различаются они типом: (момент, true) — подтверждён; (нуль, false) — не
	// подтверждён; ошибка — спросить не удалось (NOT_FOUND — человека нет).
	EmailVerification(ctx context.Context, userID domain.UserID) (at time.Time, verified bool, err error)
}

// CostClassCount — строка переписи классов стоимости: префикс класса (значение
// без соли и тела — формат и числа параметров, как его читает
// `passwordverify.ParseCostClassPrefix`) и число строк этого класса. Пустой
// префикс — признак формата вне перечня: сегмент чужого признака из хранилища
// не выносится.
type CostClassCount struct {
	Prefix string
	Rows   int64
}

// CostClassCensus — перепись классов стоимости хранимых значений способа
// «пароль» (решение kaname#188): вызывающий — композиционный корень при старте,
// калибрующий огибающую по потолку на ФАКТИЧЕСКОЙ популяции. Материал перепись
// не выносит; порт отделён от `Store`, потому что читатель у него один и другой.
type CostClassCensus interface {
	// PasswordCostClasses — по строке на класс, с числом строк; один проход по
	// таблице способов без индекса по материалу (индекс копировал бы колонку в
	// свои страницы, и заводить его нельзя — шапка миграции таблицы).
	PasswordCostClasses(ctx context.Context) ([]CostClassCount, error)
}

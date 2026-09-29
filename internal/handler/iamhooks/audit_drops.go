// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package iamhooks

// audit_drops.go — запись журнала выдачи, которую полоса НЕ записала,
// становится величиной (задача kaname#389, возврат рецензента).
//
// # Предмет
//
// Полосы хука пишут журнал выдачи и отказа отдельной короткой транзакцией, и на
// отказе записи обслуживают дальше: ответ поставщику не ждёт журнала. До этой
// величины у потерянной записи было одно наблюдение — предупреждающая строка, —
// а под пределом на вызов (issuance_deadline.go) запись, не успевшая за предел,
// откатывается, и хук отвечает 200: токен выдан, строки в журнале нет.
//
// # Почему величина, а не отказ в выдаче
//
// Журнал пишется в ту же базу, что читают полосы, отдельной записью. Отказ
// выдачи на отказе записи сделал бы исправность журнала условием входа КАЖДОГО
// человека: история этого адаптера уже знает запись, отвергнутую базой на
// каждом вызове (идентификатор не проходил проверку таблицы), — при отказе в
// выдаче это был бы отказ всем. Потеря записи терпима, пока она ВИДНА числом:
// проход без счётчика — мягкий проход, который видит только читающий журнал
// построчно.
//
// # Почему набор видов закрыт и объявлен здесь
//
// Виды записей пишут обработчики этого пакета, и только они. Второй перечень у
// приёмника величин разошёлся бы с этим молча — в сторону вида без клетки.

import (
	"context"
	"errors"
)

// Виды записей журнала, которые пишут полосы хука выдачи. Набор ЗАКРЫТ.
const (
	// AuditTokenIssued — хук выпуска отдал утверждения токена.
	// #nosec G101 -- это имя вида записи журнала, а не секрет: значение читают
	// приёмник величин и журнал аудита. Правило срабатывает на подстроку "token"
	// в имени константы.
	AuditTokenIssued = "authn.token.issued"
	// AuditTokenDenied — хук выпуска отказал в токене.
	// #nosec G101 -- это имя вида записи журнала, а не секрет; причина та же,
	// что у AuditTokenIssued.
	AuditTokenDenied = "authn.token.denied"
	// AuditRefreshIssued — хук обновления отдал утверждения токена.
	AuditRefreshIssued = "authn.refresh.issued"
	// AuditRefreshDenied — хук обновления отказал в токене.
	AuditRefreshDenied = "authn.refresh.denied"
)

// AuditEventTypes — закрытый набор видов записей в порядке объявления.
//
// ВЫВОДИТСЯ отсюда всяким, кому нужен перечень: заведение клеток величины,
// перепись пробы.
func AuditEventTypes() []string {
	return []string{AuditTokenIssued, AuditTokenDenied, AuditRefreshIssued, AuditRefreshDenied}
}

// AuditDropObserver — приёмник записей журнала, которые полоса не записала.
// Порт, а не готовый счётчик: слой транспорта не знает реестра величин.
type AuditDropObserver interface {
	// AuditDropped принимает ОДНУ незаписанную запись вида eventType из
	// [AuditEventTypes].
	AuditDropped(eventType string)
}

// ErrAuditDropObserverMissing — сборка полос без приёмника потерь журнала.
var ErrAuditDropObserverMissing = errors.New("iamhooks: issuance lanes: audit drop observer is not wired")

// ObserveAuditDrops надевает на запись журнала счёт незаписанных записей.
//
// Считается ОТКАЗ записи, каким бы он ни был — предел на вызов, отказ базы,
// ушедший вызывающий: во всех случаях короткая транзакция записи откатилась, и
// строки журнала нет. Корзины «прочее» у величины нет, потому что причины она
// не различает: причину называет строка журнала обработчика, величина — число.
//
// Порядок с пределом на вызов ([WithCallDeadline]) счёта не меняет: обёртка
// предела передаёт порту контекст со своим сроком и возвращает его отказ как есть,
// поэтому запись, срезанная пределом, видна счёту и поверх предела, и под ним
// (опыт J3 рецензента, kaname#436). Держит
// `TestObserveAuditDrops_CountsTheCutWriteOnEitherSideOfTheCallDeadline`. Сборка
// полос надевает счёт поверх предела — это место провязки, а не условие счёта.
//
// Нулевой приёмник — отказ сборки: полоса, теряющая журнал без величины, и есть
// тот мягкий проход, ради которого приёмник заведён. Неподанная запись журнала
// остаётся неподанной — у обработчиков для неё своя ветвь.
func ObserveAuditDrops(inner AuditEmitter, obs AuditDropObserver) (AuditEmitter, error) {
	if obs == nil {
		return nil, ErrAuditDropObserverMissing
	}
	if inner == nil {
		return nil, nil
	}
	return droppedAuditCounter{inner: inner, obs: obs}, nil
}

// droppedAuditCounter — запись журнала со счётом незаписанного.
type droppedAuditCounter struct {
	inner AuditEmitter
	obs   AuditDropObserver
}

func (d droppedAuditCounter) Emit(ctx context.Context, evt AuditEvent) error {
	err := d.inner.Emit(ctx, evt)
	if err != nil {
		d.obs.AuditDropped(evt.EventType)
	}
	return err
}

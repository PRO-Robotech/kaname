// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

// authz_lanes.go — полосы, которыми у владельца прав спрашивают доступ, и
// наблюдение каждой из них.
//
// # Полос ТРИ, и они принадлежат разным вызывающим
//
//   - [LaneCheck] — КРАЙ: один вопрос на входящий запрос арендатора
//     (`AuthorizeService/Check`);
//   - [LaneBatchCheck] — сужатель списочной выдачи модулей: вопрос на КАЖДЫЙ
//     объект страницы (`AuthorizeService/BatchCheck`; страница контрактно бывает
//     до тысячи);
//   - [LaneCheckRelation] — пообъектное звено решения модулей: вопрос на RPC
//     (`InternalIAMService/Check` → `CheckRelation`).
//
// # Почему это заведено отдельным файлом со словарём
//
// Счётчик видел ОДНУ полосу из трёх, при том что тип наблюдения объявлял две:
// значение метки было названо в комментарии и не производилось ни одним
// прод-местом. Такая полоса присутствует нулём и выглядит исправным
// наблюдением — то есть скрывает собственное отсутствие лучше, чем отсутствие
// счётчика вовсе.
//
// Следствие для того, кто читает числа: всякое «проверок в секунду», снятое с
// владельца прав, было занижено — на пути чтения по идентификатору ровно вдвое,
// потому что проверок там две (край и сервис), а видна была вторая.
//
// Словарь ЗАКРЫТ и сверяется с производителями пробой
// `TestEveryDeclaredLaneHasAProducer`: полоса без производителя и производитель
// без объявления — обе находки.

import (
	"context"
	"time"

	"github.com/PRO-Robotech/kaname/internal/service"
)

// Значения метки `rpc` — ЗАКРЫТЫЙ словарь. Именованные константы, а не литералы
// по месту: одно расхождение в написании завело бы четвёртую полосу, которую
// никто не заметит, потому что она всегда ноль.
const (
	// LaneCheck — полоса КРАЯ.
	LaneCheck = "Check"
	// LaneBatchCheck — полоса сужателя списочной выдачи.
	LaneBatchCheck = "BatchCheck"
	// LaneCheckRelation — полоса пообъектного звена модулей.
	LaneCheckRelation = "CheckRelation"
)

// DeclaredAuthzLanes — полосы, которые обязаны иметь производителя.
//
// Отдаётся копия: перечень — контракт с панелями и правилами тревог, и
// вызывающий, получивший срез пакета, мог бы подвинуть его у всех сразу.
func DeclaredAuthzLanes() []string {
	return []string{LaneCheck, LaneBatchCheck, LaneCheckRelation}
}

// subjectAuthorizer — порт решателя, которым пользуется ТРАНСПОРТ публичной
// службы авторизации.
//
// Объявлен здесь, а не в use-case: инструментирование живёт на границе адаптера
// (чистая архитектура), и use-case не обязан знать про сбор величин. Конкретный
// `*service.AuthorizeService` порт удовлетворяет.
type subjectAuthorizer interface {
	Check(ctx context.Context, req service.CheckRequest) (*service.CheckResult, error)
	BatchCheck(ctx context.Context, reqs []service.CheckRequest) ([]*service.CheckResult, error)
	ListSubjects(ctx context.Context, req service.ListSubjectsRequest) (*service.ListSubjectsResult, error)
	ExpandRelations(ctx context.Context, req service.ExpandRequest) (*service.ExpandResult, error)
}

// InstrumentedSubjectAuthorizer — сквозной декоратор публичного решателя.
//
// Наблюдает ДВЕ полосы (край и сужатель) и не трогает ничего больше: результат
// и ошибка возвращаются дословно, поэтому решение остаётся решением use-case.
// Остальные методы порта проходят насквозь без наблюдения — у них своя цена и
// свой предмет, и приписывать их к «проверкам» значило бы завысить число ровно
// так же, как раньше оно было занижено.
type InstrumentedSubjectAuthorizer struct {
	inner subjectAuthorizer
	reg   *Registry
}

// NewInstrumentedSubjectAuthorizer оборачивает решатель публичной службы.
// Провязывается в композиционном корне — единственном месте, которое знает и
// решатель, и реестр величин.
func NewInstrumentedSubjectAuthorizer(inner subjectAuthorizer, reg *Registry) *InstrumentedSubjectAuthorizer {
	return &InstrumentedSubjectAuthorizer{inner: inner, reg: reg}
}

// Check — полоса КРАЯ: один вопрос, одно наблюдение.
func (d *InstrumentedSubjectAuthorizer) Check(ctx context.Context, req service.CheckRequest) (*service.CheckResult, error) {
	start := time.Now()
	res, err := d.inner.Check(ctx, req)
	d.reg.ObserveAuthz(AuthzObservation{
		RPC:      LaneCheck,
		Allowed:  err == nil && res != nil && res.Allowed,
		Err:      err != nil,
		Duration: time.Since(start).Seconds(),
	})
	return res, err
}

// BatchCheck — полоса сужателя: одно наблюдение ДЛИТЕЛЬНОСТИ на вызов и по
// решению на КАЖДЫЙ вопрос пачки.
//
// Разделение не бухгалтерское. Длительность принадлежит вызову: делить её на
// вопросы значило бы утверждать про каждый то, чего никто не измерял. Решения
// принадлежат вопросам: страница контрактно бывает до тысячи объектов, и счёт
// по вызовам занизил бы нагрузку от списочной выдачи в тысячу раз — то есть
// сделал бы её невидимой ровно там, где она наибольшая.
//
// На ошибке пачки вопросы не считаются поштучно: их исход неизвестен, и
// приписать им «отказ» значило бы выдумать решения, которых не принимали.
// Считается ОДИН сбой — столько же, сколько было вызовов.
func (d *InstrumentedSubjectAuthorizer) BatchCheck(ctx context.Context, reqs []service.CheckRequest) ([]*service.CheckResult, error) {
	start := time.Now()
	res, err := d.inner.BatchCheck(ctx, reqs)
	elapsed := time.Since(start).Seconds()

	if err != nil {
		d.reg.ObserveAuthz(AuthzObservation{RPC: LaneBatchCheck, Err: true, Duration: elapsed})
		return res, err
	}
	// Длительность — одним наблюдением на вызов. На полосе пачки метка `allowed`
	// отвечает «вызов состоялся», а НЕ «вопрос разрешён»: ответов в пачке много,
	// и один ярлык на всех был бы ложью о каждом. На «чем кончился вопрос»
	// отвечает счётчик решений ниже, по вопросу на каждый.
	d.reg.ObserveAuthzDuration(LaneBatchCheck, true, elapsed)
	for _, r := range res {
		d.reg.ObserveAuthzDecision(LaneBatchCheck, r != nil && r.Allowed, false)
	}
	return res, nil
}

// ListSubjects / ExpandRelations — сквозной проход БЕЗ
// наблюдения: у них своя цена и свой предмет.
func (d *InstrumentedSubjectAuthorizer) ListSubjects(ctx context.Context, req service.ListSubjectsRequest) (*service.ListSubjectsResult, error) {
	return d.inner.ListSubjects(ctx, req)
}

func (d *InstrumentedSubjectAuthorizer) ExpandRelations(ctx context.Context, req service.ExpandRequest) (*service.ExpandResult, error) {
	return d.inner.ExpandRelations(ctx, req)
}

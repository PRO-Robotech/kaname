// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package moduleroles

// refusal.go — ПОЛОСА отказа применителя, названная машинно (задача #1880).
//
// # Сентинела мало, и это измерено, а не предположено
//
// Применитель объявляет три сентинела, но до вызывающего доезжает только тот,
// что рождается ДО писательской транзакции. Отказ писателя проходит через
// единственное в дереве объявление паттерна (`shared.DoWithWriteTx`), а тот
// приводит отказ действия к gRPC-статусу через `shared.MapRepoErr`. Статус
// собирается ЗАНОВО — `status.Error(code, StripSentinel(err))`, — и `%w`-цепочка
// не сохраняется:
//
//	errors.Is(mapped, ErrWriteFailed) → false
//	status.Code(mapped)               → FailedPrecondition
//
// Следствие: две полосы — «манифест назвал негодное правило» и «база отвергла
// запись» — вызывающий машинно НЕ различал, у него оставался разбор прозы. Тон
// сообщения стабилен и есть часть контракта, но парсибельным он от этого не
// становится — ровно то, против чего заведён `reason`-токен
// (`api-conventions.md` §«by-lane code-split»).
//
// Асимметрия при этом невидима в обзоре: обе полосы выглядят одинаково
// защитимо, расходится только то, что доезжает.
//
// # Форма взята у соседей, а не изобретена
//
// Признак полосы живёт в `google.rpc.ErrorInfo` — ровно как у отказа учёта
// (`shared/quota.go`) и у отказа «членство несёт права»
// (`shared/membership_refusal.go`): `Reason` — токен полосы, `Domain` — сервис,
// `Metadata` — величины. Совпадение намеренное: клиенту не должно требоваться
// знать, какой отказ ему достался, прежде чем понять, ГДЕ искать признак.
//
// # Почему признак ставит применитель, а не общая классификация
//
// Соседние полосы разбираются ВНУТРИ `MapRepoErr`, потому что их сентинелы живут
// в `internal/errors` — пакете, который `shared` уже импортирует. Сентинелы
// применителя живут ЗДЕСЬ, в use-case, и обратный импорт замкнул бы граф:
// `moduleroles` импортирует `shared` (repotx.go). Второе объявление тех же
// сентинелов в `internal/errors` разошлось бы с первым молча. Поэтому признак
// ставится на выходе применителя — в том единственном месте, где полоса ещё
// известна ДОСТОВЕРНО, а не восстанавливается разбором.
//
// # Оракула существования здесь нет, и вопрос задан, а не пропущен
//
// Различимый отказ становится оракулом, когда по нему узнают о ЧУЖОМ ресурсе.
// Обе полосы говорят ровно о двух вещах: о манифесте, который прислал сам
// вызывающий, и о ПЛАТФОРМЕННОМ каталоге ресурсов — общем для всех и
// admin-curated (та же поверхность, что у каталога размещения, объявленного
// публичным по решению). Арендаторских строк не касается ни одна из них, а сам
// применитель живёт на КЛАСТЕРНОМ ярусе, куда арендатор не ходит by
// construction. Поэтому подробность здесь — то, что восстанавливает следующий
// шаг («поправь вот эту строку манифеста»), а не то, что раскрывает чужое.

import (
	"errors"
	"fmt"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/shared"
)

const (
	// LaneRejectedByDomain — роль отвергнута ДОМЕНОМ, до всякой записи. Чинится
	// правкой манифеста, а не состоянием базы, и повтор без правки бессмыслен.
	LaneRejectedByDomain = "MODULE_ROLE_REJECTED_BY_DOMAIN"
	// LanePolicyNotCompilable — правило не сворачивается в разрешения. Полоса
	// отдельная от предыдущей: домен судит ФОРМУ роли, а сворачивание —
	// выразимость её правил в каталоге разрешений, и правит их вызывающий
	// по-разному.
	LanePolicyNotCompilable = "MODULE_ROLE_POLICY_NOT_COMPILABLE"
	// LaneWriteFailed — отказала ЗАПИСЬ. Инвариант держит база, поэтому предмет
	// отказа приезжает её текстом, а класс — её кодом; применитель ни того, ни
	// другого не перетолковывает.
	LaneWriteFailed = "MODULE_ROLE_WRITE_FAILED"
	// LaneNamedRightIncomplete — ПОИМЁННЫЙ перечень права роли не полон по
	// своему классу (#1998). Полоса отдельная от двух первых: чинится перечень,
	// а не форма правила и не состояние базы, и текст отказа несёт недостающие
	// имена.
	LaneNamedRightIncomplete = "MODULE_ROLE_NAMED_RIGHT_INCOMPLETE"
	// LaneRightsExportNotWired — производитель правил роли НЕ ПРОВЯЗАН. Виновата
	// провязка, а не вход: правку манифеста этот отказ не примет ни при какой
	// строке, и объединять его с предыдущей полосой значило бы послать
	// вызывающего чинить не то.
	LaneRightsExportNotWired = "MODULE_ROLE_RIGHTS_EXPORT_NOT_WIRED"
	// LaneRetirementActorUnnamed — АВТОР снятия не назван вызывающим. Полоса
	// своя, потому что чинится ПРОВЯЗКОЙ: ни вход манифеста, ни состояние базы
	// тут ни при чём. Подставить «system» вместо отказа значило бы сделать вопрос
	// «кто у меня отобрал» безответным ровно тогда, когда его задают (#1913).
	LaneRetirementActorUnnamed = "MODULE_ROLE_RETIREMENT_ACTOR_UNNAMED"
)

// refusalDomain — источник отказа в `ErrorInfo.domain`, как его видит клиент.
// Совпадает с доменом соседних полос: сервис один.
const refusalDomain = "iam.kacho.cloud"

const (
	// metaModule / metaRole — величины полосы. Обе взяты из манифеста, который
	// прислал сам вызывающий, поэтому называть их безопасно, а не называть —
	// значит заставить его искать строку перебором.
	metaModule = "module"
	metaRole   = "role"
)

// RefusalLane — полоса отказа применителя ОДНИМ токеном; пустая строка означает
// «полоса не наша».
//
// # Источников два, и оба нужны
//
// Отказ, прошедший приведение к статусу, цепочку не несёт — признак читается из
// `ErrorInfo`. Отказ, до приведения не дошедший (вызывающий в процессе, до
// границы транспорта), несёт цепочку — и она отвечает. Один вопрос, два
// источника: клиенту не надо знать, на каком берегу он стоит.
//
// Порядок именно такой: признак сильнее цепочки, потому что он переживает
// приведение, а цепочка — нет.
func RefusalLane(err error) string {
	if err == nil {
		return ""
	}
	if st, ok := status.FromError(err); ok {
		for _, d := range st.Details() {
			ei, isInfo := d.(*errdetails.ErrorInfo)
			if !isInfo || ei.GetDomain() != refusalDomain {
				continue
			}
			switch ei.GetReason() {
			case LaneRejectedByDomain, LanePolicyNotCompilable, LaneWriteFailed,
				LaneNamedRightIncomplete, LaneRightsExportNotWired,
				LaneRetirementActorUnnamed:
				return ei.GetReason()
			}
		}
	}
	switch {
	case errors.Is(err, ErrRoleRejectedByDomain):
		return LaneRejectedByDomain
	case errors.Is(err, ErrRolePolicyNotCompilable):
		return LanePolicyNotCompilable
	case errors.Is(err, ErrWriteFailed):
		return LaneWriteFailed
	case errors.Is(err, ErrNamedRightIncomplete):
		return LaneNamedRightIncomplete
	case errors.Is(err, ErrRightsExportNotWired):
		return LaneRightsExportNotWired
	case errors.Is(err, ErrRetirementActorUnnamed):
		return LaneRetirementActorUnnamed
	}
	return ""
}

// laneRefusal — отказ с ДВУМЯ лицами: статус с признаком полосы для клиента за
// проводом и цепочка сентинела для вызывающего в процессе.
//
// Лица два, а объект ОДИН — разойтись им негде. Второй объект («статус рядом с
// ошибкой») был бы двумя местами об одном предмете, и первая же правка увела бы
// одно от другого молча.
//
// `Error()` отдаёт текст статуса, а НЕ текст цепочки: цепочка на полосе писателя
// несёт внутри себя уже собранный статус, и её `Error()` дал бы «rpc error: code
// = … desc = …» внутри сообщения — служебную обёртку в тексте, который читает
// человек.
type laneRefusal struct {
	st      *status.Status
	wrapped error
}

func (e *laneRefusal) Error() string              { return e.st.Message() }
func (e *laneRefusal) GRPCStatus() *status.Status { return e.st }
func (e *laneRefusal) Unwrap() error              { return e.wrapped }

// refuse собирает отказ полосы: код и текст — те, что уже решены, признак —
// токен полосы, цепочка — как была.
func refuse(code codes.Code, msg, reason, module, role string, wrapped error) error {
	st := status.New(code, msg)

	meta := map[string]string{}
	if module != "" {
		meta[metaModule] = module
	}
	if role != "" {
		meta[metaRole] = role
	}
	withDetails, derr := st.WithDetails(&errdetails.ErrorInfo{
		Reason:   reason,
		Domain:   refusalDomain,
		Metadata: meta,
	})
	if derr != nil {
		// Деталь не прикрепилась — код, текст и цепочка важнее признака, и они
		// остаются. Полоса при этом отвечает по цепочке: `RefusalLane` спрашивает
		// оба источника именно ради этого случая.
		return &laneRefusal{st: st, wrapped: wrapped}
	}
	return &laneRefusal{st: withDetails, wrapped: wrapped}
}

// writeRefusal — отказ полосы писателя.
//
// Код и текст УЖЕ решены исполнителем транзакций: инвариант держит база, и её
// классификация здесь не перетолковывается. Добавляется ровно две вещи — признак
// полосы и цепочка сентинела, которую исполнитель потерял.
//
// Приведение зовётся повторно и это НЕ второй классификатор: `MapRepoErr`
// идемпотентен by construction — статус с названным классом он возвращает как
// есть первой же своей ветвью. Ветвь нужна для исполнителя, который отказ не
// привёл вовсе: он получает тот же опаковый INTERNAL, что и в проде, а не
// `Unknown` с сырым текстом драйвера в сообщении.
func writeRefusal(module, role string, err error) error {
	mapped := shared.MapRepoErr(err)
	st, _ := status.FromError(mapped)
	return refuse(st.Code(), st.Message(), LaneWriteFailed, module, role,
		fmt.Errorf("%w: %w", ErrWriteFailed, err))
}

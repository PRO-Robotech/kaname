// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package shared

import (
	stderrors "errors"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/quota/quotadetail"
	iamerr "github.com/PRO-Robotech/kacho/services/iam/internal/errors"
)

// Отказ учёта числа ресурсов на пути наружу.
//
// ПОЧЕМУ ЭТИ ДВА ИСХОДА РАЗБИРАЮТСЯ ОТДЕЛЬНО ОТ ОСТАЛЬНЫХ SENTINEL'ОВ. Общая
// классификация (`MapRepoErr`) отвечает только за КОД. Учёту этого мало: клиент
// обязан различать полосы МАШИННО — по `reason`-токену в
// `google.rpc.ErrorInfo`, а не разбором прозы (`api-conventions.md` §By-lane
// code-split). Токен приклеивается здесь, в одном месте на все api-слайсы
// домена, чтобы «отказ на внешнем слушателе» и «тот же отказ на внутреннем» не
// разошлись признаком.
//
// Форма — та же, что у пяти прочих владельцев учёта (vpc / compute / storage /
// nlb / registry). Совпадение намеренное: отказ производит один шаблон на всех,
// и разный признак у одного отказа означал бы, что клиенту надо знать, чей
// домен ему ответил, прежде чем понять, что ему делать.
const (
	// reasonQuotaExceeded — место кончилось: потолок назван и выбран.
	// Администратору требуется ПОДНЯТЬ предел.
	reasonQuotaExceeded = "QUOTA_EXCEEDED"

	// reasonQuotaNotProvisioned — потолок не назван ни на одной области.
	// Администратору требуется ЗАВЕСТИ предел.
	//
	// Отдельный признак, а не оттенок предыдущего: сведи их в один, и читающий
	// «место кончилось» пойдёт искать, что понизить, там, где ничего не
	// назначено.
	reasonQuotaNotProvisioned = "QUOTA_NOT_PROVISIONED"

	// reasonQuotaRateExceeded — темп исчерпан: за текущее окно принято столько,
	// сколько названо величиной. Арендатору требуется ПОДОЖДАТЬ.
	//
	// Отдельный признак, а не оттенок `QUOTA_EXCEEDED`, и различие несущее ровно
	// так же, как между двумя предыдущими: там разница в действии АДМИНИСТРАТОРА,
	// здесь — в действии САМОГО ВЫЗЫВАЮЩЕГО. Повтор запроса по объёму не пройдёт
	// никогда, повтор по темпу пройдёт в следующем окне; клиент, не различающий
	// эти полосы, либо бросает работу там, где надо повторить, либо повторяет
	// вечно там, где повтор бесполезен.
	reasonQuotaRateExceeded = "QUOTA_RATE_EXCEEDED"
)

// quotaReasonDomain — источник отказа в `ErrorInfo.domain`, как его видит клиент.
const quotaReasonDomain = "iam.kacho.cloud"

// quotaRefusal собирает статус отказа учёта, если err им является; ok=false
// означает «это не отказ учёта» и передаёт разбор общей классификации.
//
// Текст производителя (`kacho_quota_refuse`, миграция 484001) выносится наружу
// ДОСЛОВНО: он и есть контракт — называет носителя, предел и вид.
func quotaRefusal(err error) (error, bool) {
	var (
		code   codes.Code
		reason string
	)
	switch {
	case stderrors.Is(err, iamerr.ErrQuotaExceeded):
		code, reason = codes.ResourceExhausted, reasonQuotaExceeded
	case stderrors.Is(err, iamerr.ErrQuotaRateExceeded):
		// Тот же код, что у объёма: место исчерпано, и край отдаёт 429 в обоих
		// случаях. Различает полосы ПРИЗНАК — по коду они и не должны различаться,
		// потому что «повтори позже» на транспортном уровне верно для обеих.
		code, reason = codes.ResourceExhausted, reasonQuotaRateExceeded
	case stderrors.Is(err, iamerr.ErrQuotaNotProvisioned):
		// FAILED_PRECONDITION, а не INVALID_ARGUMENT: ввод арендатора корректен,
		// не выполнено предусловие ПЛАТФОРМЫ. INVALID_ARGUMENT обвинил бы
		// вызывающего в том, чего он не присылал.
		code, reason = codes.FailedPrecondition, reasonQuotaNotProvisioned
	default:
		return nil, false
	}

	st := status.New(code, iamerr.StripSentinel(err))
	// Величины производителя — в штатное поле `metadata`, а не в прозу. Контракт
	// от этого не меняется: `ErrorInfo.metadata` существует ровно под такие
	// величины, и клиент, читавший только признак, продолжает работать
	// (задача продукта #1605). Величин нет — поле остаётся пустым; выдумывать их
	// нечем, а ноль есть законная величина занятого и молчанием быть не может.
	withDetails, derr := st.WithDetails(&errdetails.ErrorInfo{
		Reason:   reason,
		Domain:   quotaReasonDomain,
		Metadata: quotadetail.MetadataFromError(err),
	})
	if derr != nil {
		// Деталь не прикрепилась — код и текст важнее признака.
		return st.Err(), true
	}
	return withDetails.Err(), true
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

// object_refusal.go — машинный признак полосы у отказа регистрации, называющего
// объект регистрации (kaname#982, приёмка
// `kaname-derives-the-parent-of-a-registered-object.md`, Р8).
//
// ЗАЧЕМ ОТДЕЛЬНО ОТ ОБЩЕГО switch'а — та же причина, что у `referenceRefusal`:
// ветвь `ErrFailedPrecondition` в `MapRepoErr` пересобирает статус голым
// `status.Error(code, text)`, и деталь потерялась бы.
//
// ЧТО ПРИЗНАК ДАЁТ ПОТРЕБИТЕЛЮ. Отказ вывода родителя и отказ по ссылке делят
// код FAILED_PRECONDITION, а лечатся разным: здесь — исправить сведения о
// родителе либо сперва зарегистрировать контейнер, и повторить. Различать их
// разбором прозы вызывающему запрещено конвенцией, поэтому различие живёт в
// признаке.

import (
	stderrors "errors"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kaname/internal/errors"
	"github.com/PRO-Robotech/kaname/internal/refusaldomain"
)

// reasonParentScopeMismatch — сведения модуля о родителе регистрируемого объекта
// расходятся с иерархией kaname либо опоры нет.
const reasonParentScopeMismatch = "PARENT_SCOPE_MISMATCH"

// reasonObjectBoundToOtherProject — регистрация называет проект, отличный от
// проекта, к которому id объекта привязан (kaname#983).
const reasonObjectBoundToOtherProject = "OBJECT_BOUND_TO_OTHER_PROJECT"

// objectRefusal — статус с признаком полосы, если ошибка — отказ по объекту
// регистрации; на всём прочем false, и общий switch отрабатывает как прежде.
//
// `metadata` — ровно модельный тип и id объекта: отказ не называет ни проекта,
// ни аккаунта, ни контейнера, и деталь эту границу держит своим составом.
func objectRefusal(err error) (error, bool) {
	var reason string
	switch {
	case stderrors.Is(err, iamerr.ErrParentScopeMismatch):
		reason = reasonParentScopeMismatch
	case stderrors.Is(err, iamerr.ErrObjectBoundToOtherProject):
		reason = reasonObjectBoundToOtherProject
	default:
		return nil, false
	}
	st := status.New(codes.FailedPrecondition, iamerr.StripSentinel(err))
	info := &errdetails.ErrorInfo{
		Reason: reason,
		Domain: refusaldomain.For(refusaldomain.ServiceIAM),
	}
	if obj, ok := iamerr.RefusedObjectOf(err); ok {
		info.Metadata = map[string]string{
			metaResourceType: obj.ResourceType,
			metaResourceID:   obj.ResourceID,
		}
	}
	withDetails, derr := st.WithDetails(info)
	if derr != nil {
		// Деталь не прикрепилась — код и текст важнее признака.
		return st.Err(), true
	}
	return withDetails.Err(), true
}

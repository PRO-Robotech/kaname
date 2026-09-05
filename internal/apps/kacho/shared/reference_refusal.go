// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

// reference_refusal.go — машинный признак полосы у отказа по ссылке между
// ресурсами.
//
// ЗАЧЕМ ОТДЕЛЬНО ОТ ОБЩЕГО switch'а. Ветвь `ErrFailedPrecondition` в
// `MapRepoErr` пересобирает статус голым `status.Error(code, text)` и деталь
// потеряла бы. Тот же порядок и по той же причине уже применён к отказу учёта
// величин (`quotaRefusal`) — здесь он повторяется, а не изобретается.
//
// ЧТО ЭТОТ ПРИЗНАК ДАЁТ КЛИЕНТУ. Два состояния одного нарушения ссылочной
// целостности противоположны по действию: «ссылаемого нет» лечится СОЗДАНИЕМ,
// «ещё используется» — ОСВОБОЖДЕНИЕМ. Различать их разбором прозы вызывающему
// запрещено конвенцией (тон стабилен, но не парсибелен), а код у них один и тот
// же — FAILED_PRECONDITION, потому что оба и есть «состояние ресурсов не
// позволяет». Значит единственное место, где различие может жить машинно, —
// признак.

import (
	stderrors "errors"

	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

const (
	// reasonReferenceMissing — ресурс, на который ссылается запрос, не
	// существует. Следующий шаг вызывающего — создать его либо исправить ссылку.
	reasonReferenceMissing = "REFERENCE_MISSING"

	// reasonReferenceInUse — на ресурс ещё ссылаются, поэтому снять его нельзя.
	// Следующий шаг вызывающего — освободить ссылки.
	reasonReferenceInUse = "REFERENCE_IN_USE"
)

// referenceRefusal — статус с признаком полосы, если ошибка несёт одну из двух
// сторон ссылки. Второе значение — «это был отказ по ссылке»; на всём прочем
// возвращается false, и общий switch отрабатывает как прежде.
//
// Порядок проверок несущий: обе полосы ВЛОЖЕНЫ в `ErrFailedPrecondition`,
// поэтому спрашивать надо о них, а не о нём, — иначе признак не поставится
// никогда.
func referenceRefusal(err error) (error, bool) {
	var reason string
	switch {
	case stderrors.Is(err, iamerr.ErrReferenceMissing):
		reason = reasonReferenceMissing
	case stderrors.Is(err, iamerr.ErrReferenceInUse):
		reason = reasonReferenceInUse
	default:
		return nil, false
	}

	st := status.New(codes.FailedPrecondition, iamerr.StripSentinel(err))
	withDetails, derr := st.WithDetails(&errdetails.ErrorInfo{
		Reason: reason,
		Domain: quotaReasonDomain,
	})
	if derr != nil {
		// Деталь не прикрепилась — код и текст важнее признака.
		return st.Err(), true
	}
	return withDetails.Err(), true
}

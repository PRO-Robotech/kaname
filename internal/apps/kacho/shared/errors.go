// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package shared — errors.go: единый sentinel → gRPC status mapping для всех
// api-слайсов (account / project / user / service_account / group / role /
// access_binding).
//
// Заменяет 7+ копий per-resource `mapRepoErr` (account/helpers.go,
// project/helpers.go, …). Все вызывающие должны
// маппить sentinel-ошибки именно через эти функции — единственный
// authoritative point of translation между internal-sentinels и gRPC-кодами,
// чтобы (а) не дрейфил mapping per-package, (б) добавление нового sentinel'а
// требовало правки одного места.
package shared

import (
	stderrors "errors"
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// MapRepoErr — sentinel → gRPC status. Возвращает nil на nil-input.
//
// Полное покрытие 8 sentinel'ов (включая ErrPermissionDenied /
// ErrUnauthenticated, которых не было в per-resource копиях — leak'ало
// `codes.Internal` клиенту до этой консолидации).
//
// Fallback'и:
//   - если err уже несет gRPC status (не codes.Unknown) — пропускаем через;
//   - если err-текст начинается с "Illegal argument" — YC-style InvalidArgument
//     (parity с verbatim-формой error-сообщений);
//   - иначе — Internal с переданным err-текстом (StripSentinel снимает
//     sentinel-prefix чтобы клиент не увидел "not found: ...").
//
// Порядок веток — сначала pass-through, потом sentinel-switch (форма kacho-nlb).
// Он несущий, а не косметический: pkg/validate кладёт имя поля ТОЛЬКО в
// google.rpc.BadRequest-details, сообщение остаётся общим «invalid argument».
// Пересборка статуса в sentinel-ветке (`status.Error(code, StripSentinel(err))`)
// детали теряет, поэтому ошибка, обёрнутая через `%w` на iamerr.Err*, обязана
// пройти pass-through ПЕРВОЙ. status с codes.Unknown под pass-through НЕ попадает
// (guard `!= Unknown`) — он падает в sentinel-switch и дальше в фиксированный
// INTERNAL, без leak'а.
func MapRepoErr(err error) error {
	if err == nil {
		return nil
	}
	if st, ok := status.FromError(err); ok && st.Code() != codes.Unknown {
		return err
	}
	// Отказ учёта — ДО общего switch'а: он несёт не только код, но и признак
	// полосы в `google.rpc.ErrorInfo`, а sentinel-ветка ниже пересобирает статус
	// голым `status.Error(code, text)` и признак потеряла бы.
	if refusal, ok := quotaRefusal(err); ok {
		return refusal
	}
	// Отказ по ссылке — по той же причине и тем же порядком: две его полосы
	// («ссылаемого нет» / «ещё используется») различает ТОЛЬКО признак, а
	// sentinel-ветка ниже пересобрала бы статус голым `status.Error` и признак
	// потеряла бы. Спрашивается ДО общего switch'а ещё и потому, что обе полосы
	// вложены в `ErrFailedPrecondition` и его ветвь перехватила бы их первой.
	if refusal, ok := referenceRefusal(err); ok {
		return refusal
	}
	// Отказ «членство несёт права» — по той же причине и ДО общего switch'а: он
	// несёт признак полосы, по которому исключение человека узнаёт, что перечень
	// мешающих выдач можно дочитать. Sentinel-ветка ниже пересобирает статус
	// голым `status.Error(code, text)` и признак потеряла бы (задача #1686).
	if refusal, ok := membershipRefusal(err); ok {
		return refusal
	}
	switch {
	case stderrors.Is(err, iamerr.ErrNotFound):
		return status.Error(codes.NotFound, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrAlreadyExists):
		return status.Error(codes.AlreadyExists, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrPermissionDenied):
		return status.Error(codes.PermissionDenied, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrUnauthenticated):
		return status.Error(codes.Unauthenticated, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrFailedPrecondition):
		return status.Error(codes.FailedPrecondition, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrInvalidArg):
		return status.Error(codes.InvalidArgument, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrAborted):
		return status.Error(codes.Aborted, iamerr.StripSentinel(err))
	case stderrors.Is(err, iamerr.ErrUnavailable):
		// Фиксированный текст, как у INTERNAL, и по той же причине: цепочка ведёт
		// к драйверу и может нести адрес узла, имя базы и учётную запись. Прежде
		// здесь стоял `StripSentinel`, то есть текст обёртки вызывающего доезжал
		// до провода дословно; утечки не случалось лишь потому, что все
		// производители этого признака в сервисе опаковы сами — «by construction»
		// на деле означало «пока никто не обернул». Деталь остаётся в цепочке и
		// уходит в журнал (shared.LogRepoErr).
		//
		// Текст НЕ называет подсистему: признак недоступности ставит и база, и
		// сосед, и гейт прав, поэтому «database unavailable» на проводе был бы
		// собственной маленькой ложью в двух случаях из трёх.
		return status.Error(codes.Unavailable, "service unavailable")
	case stderrors.Is(err, iamerr.ErrInternal):
		// hardening-invariant #1: INTERNAL carries a FIXED opaque text, never the
		// wrapped detail (a wrapped ErrInternal may embed subject/principal ids,
		// row-counts or pgx/SQL text). Detail stays in the error chain for logs.
		return status.Error(codes.Internal, "internal error")
	}
	if strings.HasPrefix(err.Error(), "Illegal argument") {
		return status.Error(codes.InvalidArgument, err.Error())
	}
	// Defense-in-depth: an unexpected non-sentinel error must never surface its
	// raw text (could carry pgx/SQL detail) as the gRPC INTERNAL message
	// (api-conventions.md: INTERNAL = fixed text, no leak). The detail stays in
	// the error chain for server-side logging.
	return status.Error(codes.Internal, "internal error")
}

// MapValidationErr — обертка для результатов `domain.<Type>.Validate()`
// (cumulative multierr). Все sync-handler'ы вызывают ее на validation-stage
// перед эмитом Operation, чтобы InvalidArgument имел единую форму.
func MapValidationErr(err error) error {
	if err == nil {
		return nil
	}
	return status.Error(codes.InvalidArgument, err.Error())
}

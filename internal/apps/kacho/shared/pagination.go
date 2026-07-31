// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package shared

// pagination.go — page-token format validation at the app boundary.
//
// The keyset page token is base64(Std) of `<RFC3339Nano>|<id>` (mirrors the repo
// codec in repo/kacho/pg). Validating the FORMAT in the handler — as the first
// statement, BEFORE any listauthz empty-grant short-circuit — makes a garbage token
// deterministically INVALID_ARGUMENT regardless of the caller's grant state
// (api-conventions.md: "валидация pagination — ДО listauthz empty-grant
// short-circuit"). The repo's decodePageToken stays the authoritative backstop.

import (
	"encoding/base64"
	"strings"
	"time"
)

// ValidatePageToken returns InvalidArgument when a non-empty token is not a
// well-formed keyset cursor (base64 of `<RFC3339Nano>|<id>`). Empty → OK (first
// page). The message is the stable contract form "Illegal argument <field>".
func ValidatePageToken(field, token string) error {
	if token == "" {
		return nil
	}
	raw, err := base64.StdEncoding.DecodeString(token)
	if err != nil {
		return InvalidArg(field, "Illegal argument "+field)
	}
	parts := strings.SplitN(string(raw), "|", 2)
	if len(parts) != 2 {
		return InvalidArg(field, "Illegal argument "+field)
	}
	if _, err := time.Parse(time.RFC3339Nano, parts[0]); err != nil {
		return InvalidArg(field, "Illegal argument "+field)
	}
	return nil
}

// MaxListPageSize — верхняя граница page_size, общая с репозиторием
// (pg.effectivePageSize) и с платформенной validate.PageSize. Значение вне
// диапазона ОТВЕРГАЕТСЯ, а не зажимается: молчаливое зажатие отдаёт не ту
// страницу, о которой просили, и вызывающий об этом не узнаёт.
const MaxListPageSize int32 = 1000

// ValidatePagination — sync-проверка формата пагинации целиком (page_size +
// page_token) для списочного use-case'а.
//
// Зачем в use-case'е, а не только в хендлере. Списочный use-case решает, кто
// спрашивает, раньше, чем читает страницу: анонимный или неуправомоченный
// вызывающий получает пустую страницу и до репозитория не доходит. Пока формат
// проверял только репозиторий, один и тот же мусорный курсор получал разный
// ответ в зависимости от того, что вызывающему выдано, — то есть проверка ввода
// зависела от прав. Здесь она от них не зависит.
//
// Репозиторий остаётся авторитетным: он повторяет обе проверки на служимом
// пути.
func ValidatePagination(pageToken string, pageSize int32) error {
	if pageSize < 0 || pageSize > MaxListPageSize {
		return InvalidArg("page_size", "Illegal argument page_size")
	}
	return ValidatePageToken("page_token", pageToken)
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package shared

// pagination.go — page-token format validation at the app boundary.
//
// The keyset page token is base64(Std) of `<RFC3339Nano>|<id>` (mirrors the repo
// codec in repo/kaname/pg). Validating the FORMAT in the handler — as the first
// statement, BEFORE any listauthz empty-grant short-circuit — makes a garbage token
// deterministically INVALID_ARGUMENT regardless of the caller's grant state
// (api-conventions.md: "валидация pagination — ДО listauthz empty-grant
// short-circuit"). The repo's decodePageToken stays the authoritative backstop.

import (
	"github.com/PRO-Robotech/kacho/pkg/pagetoken"
	corevalidate "github.com/PRO-Robotech/kacho/pkg/validate"
)

// ValidatePageToken returns InvalidArgument when a non-empty token is not a
// well-formed keyset cursor (base64 of `<RFC3339Nano>|<id>`). Empty → OK (first
// page). The message is the stable contract form "Illegal argument <field>".
func ValidatePageToken(field, token string) error {
	// Разбор — ТОТ ЖЕ, что исполняется на пути чтения (#652). Здесь стояло
	// рукописное зеркало формы, и оно было СЛАБЕЕ авторитетного кодека: пустой
	// идентификатор оно принимало, а репозиторий отвергал. То есть проверка,
	// стоящая ПЕРВОЙ, пропускала токен, на котором чтение падало ниже, — и
	// расходились они ровно там, где расхождение не видно: на валидном входе оба
	// отвечали «валидно».
	if !pagetoken.WellFormed(token) {
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
//
// ВАЖНО про место вызова: сюда приходит уже суженное до int32 значение. Если
// вызывающий сузил его насыщающим преобразованием, отрицательный ввод превратился
// в 0 ещё ДО этой строки, а 0 в контракте значит «применить умолчание» — проверка
// стоит, верна и не может сработать. Формат СЫРОГО запроса судит
// ValidateRawPagination; эта функция остаётся проверкой уже разобранного фильтра.
func ValidatePagination(pageToken string, pageSize int32) error {
	if pageSize < 0 || pageSize > MaxListPageSize {
		return InvalidArg("page_size", "Illegal argument page_size")
	}
	return ValidatePageToken("page_token", pageToken)
}

// ValidateRawPagination — формат пагинации по СЫРЫМ значениям запроса, до любого
// преобразования типа и до любого решения о доступе.
//
// Зачем отдельная функция и почему она принимает int64. `page_size` приезжает по
// проводу как int64, а внутренние фильтры iam — int32, поэтому транспорт сужал
// значение насыщающим преобразованием (safeconv.ClampNonNegInt32). Насыщение —
// не проверка: −1 становится нулём, ноль означает «умолчание», и вызывающий
// получает страницу, о которой не просил, ничего об этом не узнав. Судить надо то,
// что прислали, а сужать — уже проверенное (после этой строки значение лежит в
// [0..1000] и в int32 помещается by construction).
//
// Порядок тоже её предмет. Вопрос «правильно ли составлен запрос» имеет ОДИН ответ
// для всех вызывающих, поэтому отвечать на него надо раньше, чем на вопрос «что
// этому вызывающему видно» (api-conventions.md: формат → authz → repo). Иначе один
// и тот же мусорный курсор даёт InvalidArgument тому, у кого грант есть, и отказ
// либо пустую страницу тому, у кого его нет.
//
// Текст отказа — платформенный (`validate.PageSize`), тот же, что у vpc/geo/storage
// и что записан в требованиях к продукту: "page_size must be in [0..1000]".
func ValidateRawPagination(pageToken string, pageSize int64) error {
	if _, err := corevalidate.PageSize("page_size", pageSize); err != nil {
		return err
	}
	return ValidatePageToken("page_token", pageToken)
}

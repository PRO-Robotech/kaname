// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package shared — ids.go: resource-id format validator.
//
// Заменяет 11+ копий per-resource `validate<Resource>ID(id)` и
// `validateAccountIDFor<Resource>(id)` функций (account/get.go,
// project/get.go, role/helpers.go, group/helpers.go, ServiceAccount, User,
// AccessBinding — все одинаковые: prefix + length check).
package shared

import (
	"strings"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ValidateResourceID проверяет соответствие id формату `<prefix><17-char-tail>`
// (общая для всех IAM-ресурсов длина — `domain.ShortIDLen`).
//
// СТРОГОСТЬ ЗДЕСЬ — РЕШЕНИЕ, А НЕ УПУЩЕНИЕ, и она отличает эту проверку от
// платформенного маршрутизатора `corevalidate.ResourceID` по ТРЁМ осям, а не по
// одной: пустая строка (здесь отвергается, там проходит), чужой тип с известным
// префиксом (здесь отвергается, там проходит в полосу отсутствия) и длина тела
// (здесь фиксирована, там не проверяется).
//
// Поэтому «привести к конвенции» заменой вызова — ослабление по трём осям
// сразу; ось пустой строки при этом завела бы отказ с вырезанным id
// (`"Account  not found"`) во все места разом. Расхождение с
// `api-conventions.md` §«By-lane code-split», довод, три границы и ВНЕШНИЙ
// предикат пересмотра записаны решением:
// `docs/engineering/architecture/known-divergences.md`, §19.
//
// ЗВАТЬ ТОЛЬКО ДЛЯ СВОЕГО ИДЕНТИФИКАТОРА. Тип чужого решает его владелец;
// строгая сверка префикса на чужой ссылке — нарушение конвенции, и она
// стережётся гейтом `TestStrictIDFormatCheckStaysOwnerScoped` (ids_owner_scope_test.go):
// префикс обязан быть константой собственного пакета `domain`.
//
// На несоответствии возвращает InvalidArgument с сообщением в каноническом
// Kachō-формате: `"invalid <resource-name> id '<id>'"`. resourceName — для
// error-сообщения (например "account", "service account", "access binding";
// **именно** в той форме, в какой Kachō показывает ошибку — с пробелами, не
// camelCase).
func ValidateResourceID(id, prefix, resourceName string) error {
	if !strings.HasPrefix(id, prefix) {
		return status.Errorf(codes.InvalidArgument, "invalid %s id '%s'", resourceName, id)
	}
	// Длина — чеканная форма ЛИБО закрытый перечень посеянного применённой
	// миграцией (`domain.SeededResourceIDs`). Второе — не послабление длины: оно
	// принимает ровно те строки, которые продукт посеял сам и которые неизменяемы
	// by construction (ban #15, ban #5). Объявлять собственный посев негодным —
	// значит отвечать `INVALID_ARGUMENT` на id, выданный этим же сервисом в
	// ответе `List` (задача #1808). Префикс при этом проверен ВЫШЕ, поэтому
	// посеянный id роли не пройдёт там, где ждут аккаунт.
	if len(id) != domain.ShortIDLen && !domain.IsSeededResourceID(id) {
		return status.Errorf(codes.InvalidArgument, "invalid %s id '%s'", resourceName, id)
	}
	return nil
}

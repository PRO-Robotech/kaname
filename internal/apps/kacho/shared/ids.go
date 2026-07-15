// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

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

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ValidateResourceID проверяет соответствие id формату `<prefix><17-char-tail>`
// (общая для всех IAM-ресурсов длина — `domain.ShortIDLen`).
//
// На несоответствии возвращает InvalidArgument с сообщением в каноническом
// Kachō-формате: `"invalid <resource-name> id '<id>'"`. resourceName — для
// error-сообщения (например "account", "service account", "access binding";
// **именно** в той форме, в какой Kachō показывает ошибку — с пробелами, не
// camelCase).
func ValidateResourceID(id, prefix, resourceName string) error {
	if !strings.HasPrefix(id, prefix) || len(id) != domain.ShortIDLen {
		return status.Errorf(codes.InvalidArgument, "invalid %s id '%s'", resourceName, id)
	}
	return nil
}

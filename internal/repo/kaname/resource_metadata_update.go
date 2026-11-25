// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package kaname

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/PRO-Robotech/corelib/operations"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ResourceMetadataUpdateWriter завершает операцию в транзакции записи зеркала.
type ResourceMetadataUpdateWriter interface {
	UpdateResourceMetadata(context.Context, domain.ResourceRef, domain.Labels, domain.Labels, []string, operations.Operation) (*operations.Operation, error)
}

// MirrorMetadataOperationKey ограничивает размер индексного ключа. Точная пара
// хранится в protobuf Metadata и проверяется независимо от этого ключа.
func MirrorMetadataOperationKey(root domain.ResourceRef) (string, bool) {
	module, resource, ok := strings.Cut(root.Type, ".")
	if !ok || module == "" || module == "iam" || resource == "" || strings.Contains(resource, ".") {
		return "", false
	}
	for _, s := range []string{root.Type, root.ID} {
		if s == "" || len(s) > 16384 || !utf8.ValidString(s) || strings.ContainsAny(s, ":#*\x00") || strings.IndexFunc(s, func(r rune) bool { return unicode.IsSpace(r) || unicode.IsControl(r) }) >= 0 {
			return "", false
		}
	}
	sum := sha256.Sum256([]byte(root.Type + "\x00" + root.ID))
	return "resource_metadata:" + hex.EncodeToString(sum[:]), true
}

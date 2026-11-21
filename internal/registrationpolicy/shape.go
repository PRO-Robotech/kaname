// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package registrationpolicy хранит общую безопасную форму registration intent.
// Каталог, account gate и native допуск остаются отдельными проверками.
package registrationpolicy

import (
	"strings"

	"github.com/PRO-Robotech/corelib/authz/proxytuple"
	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
)

// ValidateShape используется HTTP/gRPC границей и закрытым PG runner; перенос
// не расширяет прежний набор отношений и не допускает внутренние grant keys.
func ValidateShape(module, subject, relation, object string) error {
	if InternalGrantReference(subject) || InternalGrantReference(object) {
		return authzguard.PermissionDenied()
	}
	if module == "" || strings.ContainsAny(module, "* \t\n") {
		return authzguard.PermissionDenied()
	}
	if proxytuple.Hierarchical(proxytuple.Relation(relation)) || proxytuple.IsPublicReadGrant(subject, relation) {
		if err := proxytuple.ValidateTuple("", subject, relation, object); err != nil {
			return authzguard.PermissionDenied()
		}
		return nil
	}
	if !relationString(subject) || !relationString(object) || !RelationName(relation) {
		return authzguard.PermissionDenied()
	}
	subjectType, subjectID, _ := strings.Cut(subject, ":")
	if !NamedPointerSubjectType(subjectType) || strings.Contains(subjectID, "*") {
		return authzguard.PermissionDenied()
	}
	objectType, _, _ := strings.Cut(object, ":")
	for _, forbidden := range proxytuple.ForbiddenObjectTypes() {
		if objectType == forbidden {
			return authzguard.PermissionDenied()
		}
	}
	return nil
}
func relationString(value string) bool {
	if strings.ContainsAny(value, " \t\n#") {
		return false
	}
	colon := strings.IndexByte(value, ':')
	return colon > 0 && colon < len(value)-1 && strings.IndexByte(value[colon+1:], ':') < 0
}
func InternalGrantReference(reference string) bool {
	typ, _, _ := strings.Cut(reference, ":")
	return grantcapability.IsInternalObjectType(typ)
}
func RelationName(name string) bool {
	if name == "" || name[0] < 'a' || name[0] > 'z' {
		return false
	}
	for _, c := range name {
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '_' {
			return false
		}
	}
	return true
}
func NamedPointerSubjectType(typ string) bool {
	if InternalGrantReference(typ) {
		return false
	}
	if typ == "project" {
		return true
	}
	for _, forbidden := range proxytuple.ForbiddenObjectTypes() {
		if typ == forbidden {
			return false
		}
	}
	return typ != "" && !strings.Contains(typ, "*")
}

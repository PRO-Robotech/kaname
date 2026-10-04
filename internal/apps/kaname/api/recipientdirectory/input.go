// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package recipientdirectory

// input.go — вход `Resolve` и его проверка (приёмка NTF-3 Р7, «Проверка входа
// `Resolve`»).
//
// Порядок несущий и записан решением: (1) обязательность; (2) `subject` при
// `account_owner`; (3) тип, отношение, число ссылок, смесь типов. Вся проверка
// стоит до любого вопроса к модели о праве получателя: без шага (1) пустой id
// ушёл бы к модели объектом `storage_volume:` и вернулся бы исходом по
// субъекту, неотличимым от законного, а пустой набор ссылок дал бы
// `AUDIENCE_DENIED` без единого вопроса.
//
// Перепись отказов — одиннадцать, по тексту Р7: namespace, audience, subject
// при resource/self, resource_refs пуст, resource_refs[i].id, account_id,
// subject при account_owner, тип, отношение, больше 100, смесь.

import (
	"fmt"
	"slices"
	"strings"

	"github.com/PRO-Robotech/corelib/notify/spec"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzmap"
)

// maxResourceRefs — наибольшее число ссылок одного вызова.
const maxResourceRefs = 100

// AudienceKind — форма аудитории `Resolve`.
type AudienceKind int

const (
	// AudienceUnset — форма не задана.
	AudienceUnset AudienceKind = iota
	// AudienceResource — субъект, которому видны ресурсы.
	AudienceResource
	// AudienceSelf — сам субъект.
	AudienceSelf
	// AudienceAccountOwner — владелец аккаунта.
	AudienceAccountOwner
)

// ResourceRef — ссылка на ресурс письма.
type ResourceRef struct {
	Type string
	ID   string
}

// String — `<тип>:<id>`, объект модели прав.
func (r ResourceRef) String() string { return r.Type + ":" + r.ID }

// ResolveRequest — вход `Resolve`, разобранный транспортом.
type ResolveRequest struct {
	Namespace string
	Subject   string
	Audience  AudienceKind
	// Refs и Relation — только при AudienceResource.
	Refs     []ResourceRef
	Relation string
	// AccountID — только при AudienceAccountOwner.
	AccountID string
}

// subjectNamed — у субъекта есть id после `:`; пусто и `user:` — нет.
func subjectNamed(subject string) bool {
	if subject == "" {
		return false
	}
	_, id, found := strings.Cut(subject, ":")
	return !found || id != ""
}

// validate — проверка входа в порядке Р7. Первый отказ — ответ.
func (r ResolveRequest) validate() error {
	if err := r.required(); err != nil {
		return err
	}
	if r.Audience == AudienceAccountOwner && r.Subject != "" {
		return shared.InvalidArg("subject", "subject: must be empty for audience account_owner")
	}
	if r.Audience == AudienceResource {
		return r.validateResource()
	}
	return nil
}

// required — шаг (1): обязательность.
func (r ResolveRequest) required() error {
	if r.Namespace == "" {
		return shared.InvalidArg("namespace", "namespace: required")
	}
	switch r.Audience {
	case AudienceUnset:
		return shared.InvalidArg("audience", "audience: required")
	case AudienceResource, AudienceSelf:
		if !subjectNamed(r.Subject) {
			return shared.InvalidArg("subject", "subject: required")
		}
	case AudienceAccountOwner:
	}
	switch r.Audience {
	case AudienceResource:
		if len(r.Refs) == 0 {
			return shared.InvalidArg("resource_refs", "resource_refs: required")
		}
		for i, ref := range r.Refs {
			if ref.ID == "" {
				field := fmt.Sprintf("resource_refs[%d].id", i)
				return shared.InvalidArg(field, field+": required")
			}
		}
	case AudienceAccountOwner:
		if r.AccountID == "" {
			return shared.InvalidArg("audience.account_owner.account_id", "audience.account_owner.account_id: required")
		}
	case AudienceUnset, AudienceSelf:
	}
	return nil
}

// validateResource — шаг (3): отношение, число ссылок, тип каждой ссылки,
// смесь типов.
func (r ResolveRequest) validateResource() error {
	relations := spec.DirectoryRelations()
	if !slices.Contains(relations, r.Relation) {
		return shared.InvalidArg("relation", fmt.Sprintf("relation: '%s' is not in {%s}",
			r.Relation, strings.Join(relations, ", ")))
	}
	if len(r.Refs) > maxResourceRefs {
		return shared.InvalidArg("resource_refs", fmt.Sprintf("resource_refs: at most %d references, got %d",
			maxResourceRefs, len(r.Refs)))
	}
	for i, ref := range r.Refs {
		if !typeOfNamespace(ref.Type, r.Namespace) {
			field := fmt.Sprintf("resource_refs[%d].type", i)
			return shared.InvalidArg(field, fmt.Sprintf("%s: '%s' is not a resource type of namespace '%s'",
				field, ref.Type, r.Namespace))
		}
	}
	for _, ref := range r.Refs[1:] {
		if ref.Type != r.Refs[0].Type {
			return shared.InvalidArg("resource_refs", fmt.Sprintf(
				"resource_refs: references of one type only, got %s and %s", r.Refs[0].Type, ref.Type))
		}
	}
	return nil
}

// anchorTypes — типы, принимаемые в любом пространстве: якорь снятия и
// контакт (Р7).
var anchorTypes = []string{"project", "account"}

// typeOfNamespace — тип модели прав typ объявлен модулем пространства
// namespace либо якорный. Членство точное: модуль типа берётся переходником
// имени закрытой таблицы (`authzmap.DottedType`, её порождают манифесты
// модулей) и сравнивается целиком, поэтому тип с общим началом имени без
// разделителя не входит (УК3-07), а неизвестный таблице тип — тоже.
func typeOfNamespace(typ, namespace string) bool {
	if slices.Contains(anchorTypes, typ) {
		return true
	}
	dotted, ok := authzmap.DottedType(typ)
	if !ok {
		return false
	}
	module, _, ok := authzmap.SplitObjectType(dotted)
	return ok && module == namespace
}

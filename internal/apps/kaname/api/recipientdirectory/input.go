// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package recipientdirectory

// input.go — вход `Resolve` и `ListEventAudience` и его проверка (приёмка
// NTF-3 Р7, «Проверка входа `Resolve`»; `ListEventAudience`).
//
// Порядок `Resolve` несущий и записан решением: (1) обязательность; (2)
// `subject` при `account_owner`; (3) форма и тип объекта `event`, форма токена
// и цепей предков. Вся проверка стоит до любого вопроса об аудитории: без шага
// (1) пустой id ушёл бы вопросом и вернулся бы исходом по субъекту,
// неотличимым от законного.
//
// Перепись отказов `Resolve` по тексту Р7 — десять: namespace, audience,
// subject при event/self/account_reader, audience.event.object,
// audience.event.source_version, audience.event.authz_rev,
// account_reader.account_id, account_owner.account_id, subject при
// account_owner, форма и тип объекта. Сверх неё — форма токена и элемента цепи
// предков: строку, которую служба не выдавала, вопрос не принимает и не
// угадывает (отказ с именем поля, а не сбой базы на разборе).

import (
	"fmt"
	"slices"
	"strings"

	"github.com/PRO-Robotech/corelib/authz/proxytuple"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/shared"
	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// AudienceKind — форма аудитории `Resolve`.
type AudienceKind int

const (
	// AudienceUnset — форма не задана.
	AudienceUnset AudienceKind = iota
	// AudienceEvent — субъект входит в аудиторию версии события (Р30).
	AudienceEvent
	// AudienceSelf — сам субъект.
	AudienceSelf
	// AudienceAccountReader — субъект имеет `v_get` на аккаунт.
	AudienceAccountReader
	// AudienceAccountOwner — владелец аккаунта.
	AudienceAccountOwner
)

// EventRef — версия события: объект, поколение, токен, факты.
type EventRef struct {
	// Object — `<тип модели>:<id>`.
	Object     string
	Generation int64
	AuthzRev   string
	Facts      domain.EventFacts
}

// ResolveRequest — вход `Resolve`, разобранный транспортом.
type ResolveRequest struct {
	Namespace string
	Subject   string
	Audience  AudienceKind
	// Event и ViaSubscription — только при AudienceEvent.
	Event           EventRef
	ViaSubscription bool
	// AccountID — при AudienceAccountReader и AudienceAccountOwner.
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
	if r.Audience == AudienceEvent {
		return r.Event.validateForm("audience.event.", func(typ string) bool { return typeOfNamespace(typ, r.Namespace) },
			fmt.Sprintf("is not a resource type of namespace '%s'", r.Namespace))
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
	case AudienceEvent, AudienceSelf, AudienceAccountReader:
		if !subjectNamed(r.Subject) {
			return shared.InvalidArg("subject", "subject: required")
		}
	case AudienceAccountOwner:
	}
	switch r.Audience {
	case AudienceEvent:
		return r.Event.required("audience.event.")
	case AudienceAccountReader:
		if r.AccountID == "" {
			return shared.InvalidArg("audience.account_reader.account_id", "audience.account_reader.account_id: required")
		}
	case AudienceAccountOwner:
		if r.AccountID == "" {
			return shared.InvalidArg("audience.account_owner.account_id", "audience.account_owner.account_id: required")
		}
	case AudienceUnset, AudienceSelf:
	}
	return nil
}

// required — обязательность полей версии события; prefix — путь поля в
// сообщении запроса (`audience.event.` у `Resolve`, пусто у списка).
func (e EventRef) required(prefix string) error {
	switch {
	case e.Object == "":
		return shared.InvalidArg(prefix+"object", prefix+"object: required")
	case e.Generation == 0:
		return shared.InvalidArg(prefix+"source_version", prefix+"source_version: required")
	case e.AuthzRev == "":
		return shared.InvalidArg(prefix+"authz_rev", prefix+"authz_rev: required")
	}
	return nil
}

// validateForm — форма и тип объекта, поколение, форма токена и цепей
// предков. admitted судит тип модели объекта; notAdmitted — хвост текста
// отказа по типу.
func (e EventRef) validateForm(prefix string, admitted func(string) bool, notAdmitted string) error {
	typ, id, ok := strings.Cut(e.Object, ":")
	if !ok || typ == "" || id == "" {
		return shared.InvalidArg(prefix+"object",
			fmt.Sprintf("%sobject: '%s' is not in the form <type>:<id>", prefix, e.Object))
	}
	if !admitted(typ) {
		return shared.InvalidArg(prefix+"object", fmt.Sprintf("%sobject: '%s' %s", prefix, typ, notAdmitted))
	}
	if e.Generation < 0 {
		return shared.InvalidArg(prefix+"source_version",
			fmt.Sprintf("%ssource_version: must be positive, got %d", prefix, e.Generation))
	}
	if !domain.ValidAuthzRevisionForm(e.AuthzRev) {
		return shared.InvalidArg(prefix+"authz_rev",
			prefix+"authz_rev: not an authorization revision issued by this service")
	}
	if field, entry, bad := e.Facts.MalformedChainEntry(); bad {
		path := prefix + "facts." + field
		return shared.InvalidArg(path, fmt.Sprintf("%s: '%s' is not in the form <type>:<id>", path, entry))
	}
	return nil
}

// split — тип модели и id объекта (форма уже проверена).
func (e EventRef) split() (string, string) {
	typ, id, _ := strings.Cut(e.Object, ":")
	return typ, id
}

// typeOfNamespace — тип модели прав typ объявлен модулем пространства
// namespace. Членство точное: модуль типа берётся переходником имени закрытой
// таблицы (`authzmap.DottedType`, её порождают манифесты модулей) и
// сравнивается целиком, поэтому тип с общим началом имени без разделителя не
// входит (УК3-07), а неизвестный таблице тип — тоже.
func typeOfNamespace(typ, namespace string) bool {
	if !eventObjectType(typ) {
		return false
	}
	dotted, known := authzmap.DottedType(typ)
	if !known {
		return false
	}
	module, _, ok := authzmap.SplitObjectType(dotted)
	return ok && module == namespace
}

// eventObjectType — typ — тип модели ресурса модуля: известен закрытой
// таблице каталога и не входит в запретный набор правила приёма
// (`proxytuple.ForbiddenObjectTypes`: кластер, иерархия, субъекты, типы службы
// доступа). Только у таких объектов есть поколение события — голова объекта
// пишется регистрацией модуля-владельца.
func eventObjectType(typ string) bool {
	if _, known := authzmap.DottedType(typ); !known {
		return false
	}
	return !slices.Contains(proxytuple.ForbiddenObjectTypes(), typ)
}

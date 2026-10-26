// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package errors

// object_refusal.go — отказ регистрации, называющий ОБЪЕКТ регистрации и только
// его (kaname#982, приёмка `kaname-derives-the-parent-of-a-registered-object.md`,
// Р8).
//
// # Две половины одного отказа
//
// Полосу ([ErrParentScopeMismatch]) узнаёт переводчик `shared.MapRepoErr` и
// ставит машинную причину в `google.rpc.ErrorInfo`; объект ([RefusedObject])
// уезжает в `metadata` той же детали. Ни текст, ни `metadata` не называют
// выведенного проекта, аккаунта или контейнера и того, какое сведение разошлось:
// иерархию kaname модуль из отказа не узнаёт.
//
// # Полоса — СПЕЦИАЛИЗАЦИЯ предусловия, и узнаётся по тождеству указателя
//
// `errors.Is(err, ErrFailedPrecondition)` на ней истинно: потребители, различающие
// только общий признак, продолжают работать. Полоса — указатель, а не значение
// [specialisedSentinel]: два значения той структуры с одним общим признаком
// равны, и полоса «членство несёт права» отвечала бы «да» на вопрос об этой.

import stderrors "errors"

// objectLane — полоса отказа по объекту регистрации. Текст — текст общего
// признака дословно: по нему [StripSentinel] снимает префикс, и наружу он не
// уезжает.
type objectLane struct{ name string }

func (l *objectLane) Error() string { return ErrFailedPrecondition.Error() }
func (l *objectLane) Unwrap() error { return ErrFailedPrecondition }

// ErrParentScopeMismatch — сведения модуля о родителе регистрируемого объекта
// расходятся с иерархией kaname, либо опоры нет вовсе (Р8). Ответ один на оба
// случая: различие было бы оракулом иерархии.
var ErrParentScopeMismatch error = &objectLane{name: "parent scope mismatch"}

// RefusedObject — объект регистрации, названный отказом: модельный тип и id.
type RefusedObject struct {
	ResourceType string
	ResourceID   string
}

// objectRefusal — отказ полосы lane с текстом для клиента и объектом.
type objectRefusal struct {
	lane   error
	text   string
	object RefusedObject
}

func (r *objectRefusal) Error() string { return r.lane.Error() + ": " + r.text }
func (r *objectRefusal) Unwrap() error { return r.lane }

// ParentScopeMismatch — отказ вывода родителя для объекта object (значение поля
// `object` запроса дословно) модельного типа resourceType с id resourceID.
func ParentScopeMismatch(object, resourceType, resourceID string) error {
	return &objectRefusal{
		lane:   ErrParentScopeMismatch,
		text:   object + " parent scope does not match",
		object: RefusedObject{ResourceType: resourceType, ResourceID: resourceID},
	}
}

// RefusedObjectOf — объект отказа по объекту регистрации; ok=false — отказ
// другой полосы.
func RefusedObjectOf(err error) (RefusedObject, bool) {
	var r *objectRefusal
	if stderrors.As(err, &r) {
		return r.object, true
	}
	return RefusedObject{}, false
}

// ErrObjectBoundToOtherProject — регистрация называет проект (полем либо звеном
// `project` цепи), отличный от проекта, к которому id объекта привязан (kaname#983,
// приёмка object-keeps-its-project-after-unregistration.md, Р4). Привязку держит
// база (триггеры записи зеркала и цепи); адаптер записи узнаёт её отказ по имени
// ограничения и отдаёт этот признак, а use-case — отказ с объектом
// ([ObjectBoundToOtherProject]). Ответ один, действует ли регистрация или снята и
// каким носителем назван другой проект; проект привязки он не называет.
var ErrObjectBoundToOtherProject error = &objectLane{name: "object bound to another project"}

// ObjectBoundToOtherProject — отказ привязки для объекта object (значение поля
// `object` запроса дословно) модельного типа resourceType с id resourceID.
func ObjectBoundToOtherProject(object, resourceType, resourceID string) error {
	return &objectRefusal{
		lane:   ErrObjectBoundToOtherProject,
		text:   object + " is bound to another project",
		object: RefusedObject{ResourceType: resourceType, ResourceID: resourceID},
	}
}

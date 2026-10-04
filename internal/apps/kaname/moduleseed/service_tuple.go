// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleseed

// service_tuple.go — кортеж со СЛУЖЕБНЫМ субъектом `service:<имя>` (приёмка
// NTF-1, Р2 п.5 и Р5; замысел З13, З17; условие УК1).
//
// # Почему у кортежа закрытый тип
//
// Субъект `service:<имя>` производится ОДНОЙ функцией фундамента —
// `authz.ServiceSubject`. Тенантский кодек `domain.FGASubjectRef` слова
// `service` не знает и не узнаёт: неизвестный ему тип он пишет `user:`, то есть
// служебный субъект, собранный через него, стал бы человеком с тем же именем.
// Поэтому кортеж со служебным субъектом собирается только конструктором этого
// файла, а поля у него неэкспортируемые: писатель хранилища получает готовый
// кортеж и собрать свой не может.
//
// Нулевое значение не называет никого: у него пустой субъект, и писатель такой
// кортеж отвергает, а не пишет.

import (
	"errors"
	"fmt"

	"github.com/PRO-Robotech/corelib/authz"
	"github.com/PRO-Robotech/corelib/grpcsrv"
)

// Словарь модели прав для строки `notifications` (модель — `fga_model.fga`,
// типы Р5). Отношение и тип объекта — слова МОДЕЛИ, а не каталога.
const (
	// relationFeedReader — право забрать тело письма из ленты.
	relationFeedReader = "reader"
	// typeNotificationFeed — лента уведомлений пространства.
	typeNotificationFeed = "notification_feed"
	// relationNamespaceSender — право слать письма от имени пространства.
	relationNamespaceSender = "sender"
	// typeNotificationNamespace — пространство уведомлений модуля.
	typeNotificationNamespace = "notification_namespace"
)

// ErrServiceName — имя службы вне формы DNS label: служебного субъекта у него
// нет, и посев строку не применяет (отказ, а не `user:` по умолчанию).
var ErrServiceName = errors.New("moduleseed: service name is not a DNS label")

// ServiceTuple — кортеж со служебным субъектом. Производится только
// конструкторами этого файла.
type ServiceTuple struct {
	user       string
	relation   string
	objectType string
	objectID   string
}

// User — субъект кортежа, `service:<имя>`; у нулевого значения пуст.
func (t ServiceTuple) User() string { return t.user }

// Relation — отношение кортежа.
func (t ServiceTuple) Relation() string { return t.relation }

// ObjectType — тип объекта в словаре модели.
func (t ServiceTuple) ObjectType() string { return t.objectType }

// ObjectID — идентификатор объекта.
func (t ServiceTuple) ObjectID() string { return t.objectID }

// Object — объект кортежа, `<тип>:<идентификатор>`.
func (t ServiceTuple) Object() string { return t.objectType + ":" + t.objectID }

// Valid — кортеж назван целиком: нулевое значение и частично собранный кортеж
// писатель не пишет.
func (t ServiceTuple) Valid() bool {
	return t.user != "" && t.relation != "" && t.objectType != "" && t.objectID != ""
}

func (t ServiceTuple) String() string { return t.user + " " + t.relation + " " + t.Object() }

// feedReaderTuple — `service:<reader> reader notification_feed:<feed>`.
//
// Имя читателя проходит форму имени службы фундамента; вне формы — отказ.
func feedReaderTuple(reader, feed string) (ServiceTuple, error) {
	user := authz.ServiceSubject(grpcsrv.ServiceName(reader))
	if user == "" {
		return ServiceTuple{}, fmt.Errorf("%w: читатель %q", ErrServiceName, reader)
	}
	if feed == "" {
		return ServiceTuple{}, errors.New("moduleseed: лента уведомлений не названа")
	}
	return ServiceTuple{user: user, relation: relationFeedReader, objectType: typeNotificationFeed, objectID: feed}, nil
}

// SenderTuple — `service:<пространство> sender notification_namespace:<пространство>`:
// проекция записи выдачи пространства (приёмка NTF-1 Р5). Пространство — имя
// модуля, и служебный субъект модуля назван тем же именем.
//
// Её пишет посев — только для вставленной записи выдачи — и снимает и
// возвращает `Revoke`/`Restore` пространства той же транзакцией, что переход
// записи. Имя вне формы службы — отказ.
func SenderTuple(namespace string) (ServiceTuple, error) {
	user := authz.ServiceSubject(grpcsrv.ServiceName(namespace))
	if user == "" {
		return ServiceTuple{}, fmt.Errorf("%w: пространство %q", ErrServiceName, namespace)
	}
	return ServiceTuple{user: user, relation: relationNamespaceSender, objectType: typeNotificationNamespace, objectID: namespace}, nil
}

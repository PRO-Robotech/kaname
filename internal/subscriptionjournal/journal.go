// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package subscriptionjournal — ОБЪЯВЛЕНИЕ ВЛАДЕЛЬЦА для общего сервера потока
// изменений (`corelib/subscription`).
//
// Служба доступа — шестой владелец журнала и ПЕРВЫЙ, чьи предметы вместимы не
// проектом, а аккаунтом. Что из этого следует и чем закрыто — APPROVED-приёмка
// `docs/engineering/acceptance/access-resources-reach-a-narrowed-subscriber.md`;
// здесь она не пересказывается, потому что два места об одном предмете
// расходятся молча.
//
// # Что приносит владелец, и почему только значения
//
// Сервер берёт у владельца ТРИ объявления — где журнал лежит, каким каналом
// будит, как строка становится событием — и ничего больше. Курсор, горизонт
// устоявшегося, пределы, порядок отказов принадлежат серверу. Появись здесь
// возможность принести своё вместо любого из них, механизм перестал бы быть
// общим, оставшись общим по имени.
//
// # Состояние предмета этот журнал НЕ производит
//
// И причина называется СЛОВОМ, а не пустой нагрузкой: `NOT_PRODUCED` —
// первоклассное значение закрытого словаря контракта, машинно отличимое от
// сбоя сборки. Подписчик по нему знает, что делать: идти за предметом по
// `resource_id`, а на снятии — убрать его у себя.
//
// Довод — §2.6 приёмки, и он не про объём работы: потребитель по событию
// ПЕРЕЧИТЫВАЕТ предмет, а не применяет нагрузку, а поверхность утечки для
// домена, чей предмет сами права, сужается до оболочки. Конверт состояния
// заводится своей задачей (`PRO-Robotech/kaname#72`).
package subscriptionjournal

import (
	"fmt"

	"google.golang.org/protobuf/types/known/anypb"

	subscriptionv1 "github.com/PRO-Robotech/corelib/api/kacho/cloud/subscription"
	"github.com/PRO-Robotech/corelib/authz"
	"github.com/PRO-Robotech/corelib/subscription"

	"github.com/PRO-Robotech/kaname/internal/authzfilter"
)

// Table — журнал службы. Имя НЕ на `_outbox`: у службы шесть очередей с таким
// окончанием, и ни одна лентой изменений не является.
const Table = "kaname.resource_journal"

// resourceJournalChannel — канал `LISTEN`, на который пишет триггер журнала.
//
// Имя константы оканчивается на `Channel` НАМЕРЕННО: гейт дерева
// (`internal/migrations`, согласие производителя канала с потребителем) связывает
// имя двумя формами узлов разбора — поле `Channel` составного литерала со
// строковым литералом либо объявление с таким окончанием имени. Константа,
// названная иначе и подставленная в поле идентификатором, не связалась бы НИ
// ОДНОЙ ветвью, и гейт объявил бы канал беспотребительским.
//
// Канал назван отдельно от таблицы: имя таблицы схемо-квалифицировано, а
// `pg_notify` квалифицированного имени не принимает.
const resourceJournalChannel = "kaname_resource_journal"

// Виды предмета СЛОВОМ ЖУРНАЛА. Здесь они совпадают с типами объекта модели
// прав — не по совпадению, а по требованию механизма: вид, у которого нет типа
// модели, недоставляем, потому что вопрос о видимости его строки задать нечем.
//
// Единого словаря типов у службы нет — каждый use-case держит своё локальное
// значение, — поэтому перечень объявлен ЗДЕСЬ и СВЯЗАН С ДЕРЕВОМ пробой: каждый
// вид обязан быть живым типом канонической модели, а перечень — совпадать со
// словарём, закрытым ограничением миграции. Объявление без такой связи
// устарело бы молча.
const (
	KindAccount        = "account"
	KindProject        = "project"
	KindUser           = "iam_user"
	KindGroup          = "iam_group"
	KindServiceAccount = "iam_service_account"
	KindRole           = "iam_role"
	KindAccessBinding  = "iam_access_binding"
)

// Действия, ради которых задаётся вопрос о видимости строки. Списочные, а не
// одиночные: строка потока принадлежит выборке подписчика, и предикат членства
// выборки есть тот же, которым сужается страница списка.
const (
	actionAccountList        = "iam.accounts.list"
	actionProjectList        = "iam.projects.list"
	actionUserList           = "iam.users.list"
	actionGroupList          = "iam.groups.list"
	actionServiceAccountList = "iam.service_accounts.list"
	actionRoleList           = "iam.roles.list"
	actionAccessBindingList  = "iam.access_bindings.list"
)

// Слова рода изменения — те же три, что закрыты ограничением миграции.
const (
	changeCreated = "CREATED"
	changeUpdated = "UPDATED"
	changeDeleted = "DELETED"
)

// projectObjectType — тип объекта проекта в модели прав: им сторожится ось
// `project_id`.
const projectObjectType = "project"

// Journal — объявление владельца.
func Journal() subscription.Journal {
	return subscription.Journal{
		Storage: subscription.Storage{
			Table:          Table,
			PositionColumn: "sequence_no",
			KindColumn:     "resource_kind",
			IDColumn:       "resource_id",
			ChangeColumn:   "event_type",
			PayloadColumn:  "payload",
			// Якорь колонкой и НАСТОЯЩИЙ: пусто означает «предмет проекту не
			// принадлежит». Аккаунт сюда не кладётся никогда — контракт
			// объявляет пустое значение законным состоянием предмета уровня
			// аккаунта, и подмена была бы ложью на проводе, притом молчаливой.
			ProjectColumn: "project_id",
			Project:       subscription.ProjectInColumn,
			Retention:     subscription.RetainsFromEarliestRow,
			AgeColumn:     "created_at",
		},
		Channel: resourceJournalChannel,
		Mapping: subscription.Mapping{
			Kinds: map[string]subscription.Kind{
				KindAccount:        {ObjectType: KindAccount, Action: actionAccountList},
				KindProject:        {ObjectType: KindProject, Action: actionProjectList},
				KindUser:           {ObjectType: KindUser, Action: actionUserList},
				KindGroup:          {ObjectType: KindGroup, Action: actionGroupList},
				KindServiceAccount: {ObjectType: KindServiceAccount, Action: actionServiceAccountList},
				KindRole:           {ObjectType: KindRole, Action: actionRoleList},
				KindAccessBinding:  {ObjectType: KindAccessBinding, Action: actionAccessBindingList},
			},
			Changes: map[string]subscriptionv1.SubscriptionEvent_Change{
				changeCreated: subscriptionv1.SubscriptionEvent_CREATED,
				changeUpdated: subscriptionv1.SubscriptionEvent_UPDATED,
				changeDeleted: subscriptionv1.SubscriptionEvent_DELETED,
			},
			// Якорь колонкой, значит отображение его не даёт: два источника
			// одного якоря разошлись бы молча, и объявление это отвергает.
			Anchor: nil,
			State:  state,
		},
	}
}

// ProjectGate — страж оси `project_id`.
//
// Форма отсутствия приносится ОТ ПРОИЗВОДИТЕЛЯ, а не сочиняется здесь: отказ
// доступа обязан быть неотличим от «такого проекта нет», иначе различимый текст
// превращает подписку в способ узнать существование чужого проекта.
func ProjectGate() (subscription.ProjectGate, error) {
	form, ok := authz.OwnerNotFoundFormat(projectObjectType)
	if !ok {
		// Вторая величина проверяется, а не отбрасывается: тип без формы
		// отсутствия отвечал бы отличимым текстом, то есть выдавал бы
		// существование чужого проекта.
		return subscription.ProjectGate{}, fmt.Errorf(
			"subscriptionjournal: у типа %q нет формы отсутствия у производителя: "+
				"страж оси project_id отвечал бы текстом, отличимым от промаха "+
				"владельца, то есть выдавал бы существование чужого проекта",
			projectObjectType)
	}
	return subscription.ProjectGate{
		ObjectType: projectObjectType,
		Action:     actionProjectList,
		// Отношения берутся у ЕДИНСТВЕННОГО объявления предиката видимости
		// службы, а не выписываются рядом: второй перечень разошёлся бы с
		// первым молча, и разошёлся бы в сторону лишнего доступа.
		Relations:      authzfilter.RelationsFor(projectObjectType),
		NotFoundFormat: form,
	}, nil
}

// state — состояние предмета: журнал его НЕ производит ни по одному виду.
//
// Возвращается НАЗВАННАЯ причина, а не пустая нагрузка: у владельца, вернувшего
// `nil` без причины, сервер отдаёт `REASON_UNSPECIFIED` и пишет громко —
// подписчик тогда не отличает свойство журнала от сбоя сборки.
//
// Вид вне словаря отвечает ОШИБКОЙ, а не молчаливым отсутствием: молчаливый
// `nil` означал бы «предмет снят», и подписчик убрал бы из своего состояния
// живую строку. Ошибка здесь — «состояние собрать не из чего», и это правда.
func state(r subscription.Row) (*anypb.Any, subscription.StateAbsence, error) {
	switch r.Kind {
	case KindAccount, KindProject, KindUser, KindGroup,
		KindServiceAccount, KindRole, KindAccessBinding:
		return nil, subscription.StateNotProduced, nil
	default:
		return nil, subscription.StateAbsenceUnnamed, fmt.Errorf(
			"subscriptionjournal: вид %q вне словаря журнала службы: "+
				"состояние собрать не из чего", r.Kind)
	}
}

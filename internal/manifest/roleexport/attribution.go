// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package roleexport

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"unicode"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/contractnaming"
)

// attribution.go — привязка записи каталога прав к ДЕЙСТВИЮ модуля.
//
// # Ключ выводится из `fqn`, и это ЕДИНСТВЕННОЕ его объявление
//
// Ни `permission`, ни `scope_extractor.object_type` ключом быть не могут, и обе
// причины измерены, а не предположены:
//
//   - средний сегмент `permission` ресурс НЕ называет: у одного `subnet` он
//     принимает четыре разных значения (`vpc.subnets.get`,
//     `vpc.subnet_cidr_blocks.addCidrBlocks`, `vpc.subnet_operations.listOperations`,
//     `vpc.used_addresses.listUsedAddresses`), а последний сегмент написан то
//     верблюжьим (`addCidrBlocks`), то подчёркиванием (`add_cidr_blocks`,
//     `get_internal`). Ключ по нему разошёлся бы с деревом молча;
//   - `scope_extractor.object_type` называет тип объекта, НА КОТОРОМ спрашивают
//     отношение, а не ресурс, которому действие принадлежит: у каждого `Create`
//     он равен `project`, у административных RPC — `cluster`. То есть ровно у
//     тех действий, ради которых пакет и написан, он ресурс не называет.
//
// Остаётся `fqn`: `<владелец>.cloud.<модуль>.v1.<Служба>/<Метод>`. Служба
// называет ресурс, метод — действие, приставка `Internal` — плоскость
// исполнения.
//
// # Владелец пакета НЕ ВЫПИСЫВАЕТСЯ, а спрашивается у объявленного источника
//
// До #2168 первый сегмент сверялся с литералом `kacho`. Литерал был верен,
// пока владелец у всех пакетов был один; служба управления доступом переехала
// в `kaname.cloud.iam.v1`, и разбор перестал ВИДЕТЬ её записи — все 116. Это
// не отказ: отказа не было вовсе. Семь ключей закрытой таблицы перестали
// производиться, 119 записей встали вне формы модуля, а проверки манифеста
// вышли кодом 0.
//
// Владельца объявляет `internal/contractnaming` — там же, где объявлена форма
// имени пакета целиком, и там же она сверяется с дескриптором контракта.
// Здесь объявлено ТОЛЬКО то, чего у имени пакета нет: как из имени службы и
// метода получаются ресурс и действие.
//
// # Имя службы даёт ресурс, но НЕ ЕГО НАПИСАНИЕ
//
// Здесь объявлено, ОТКУДА берётся ресурс; каким словом он записывается —
// объявлено у закрытой таблицы типов (`authzmap.CatalogSpelling`), и второй раз
// здесь не объявляется. Причина не стилистическая: у написания таблицы есть
// читатель на пути запроса (`validateRuleCatalog` отвергает правило роли,
// назвавшее ресурс иначе; тем же ключом эмиттер резолвит тип объекта), а у
// написания, выведенного из имени службы, читателя нет ни одного.
//
// До #1884 приведения не было, и у трёх модулей из шести два написания
// расходились: `TargetGroupService` давал `targetGroup`, таблица объявляла
// `targetGroups`. Годного написания у автора манифеста не оставалось НИ ОДНОГО —
// одно не сопоставлялось ни с одной записью каталога (все действия ресурса
// выпадали из проверок молча, кодом 0), другое отвергалось на пути запроса.
//
// # Правило простое НАМЕРЕННО, и цена простоты названа
//
// Приставка `internal` добавляется к имени метода КАК ЕСТЬ: `InternalNetworkService/
// GetNetwork` → `internalGetNetwork`, а не `internalGet`. Всякое «умное»
// приведение (отрезать имя ресурса из хвоста метода, снять суффикс `Id`) есть
// правило, живущее в двух местах — здесь и в генераторе раздела `resources`
// (#1092), — и разойтись они обязаны на первом же методе, чьё имя не подошло под
// образец. Простое правило БИЕКТИВНО, и это проверяется, а не обещается:
// привязка отвергает совпадение ключа у двух записей.
//
// Следствие названо прямо: черновик манифеста воркспейса пишет действие
// `internalGet`, и по этому правилу оно каталогу не соответствует. Черновик —
// вход генератора, а генератора сегодня нет; написание действия есть контракт
// генератора, и здесь объявляется та его половина, которая уже имеет читателя.
//
// # Записи вне популяции НАЗЫВАЮТСЯ, а не отбрасываются
//
// Три записи каталога из 350 не несут сегмента версии вовсе
// (`kacho.cloud.operation.OperationService/Get` и рядом): это платформенные
// службы, ресурсом модуля они не являются. Отбрось их молча — и «ноль находок»
// станет неотличимо от «ноль прочитанного».
//
// Приставка, за которой в дереве НЕ СТОИТ владельца, — находка ОТДЕЛЬНОГО
// вида, а не та же самая. Слив их в один вид, разбор отвечал бы «вне формы
// модуля» и на законную платформенную службу, и на запись, чьего владельца
// никто не объявлял, — то есть посылал бы читателя чинить форму там, где
// предмет в принадлежности. Ровно так этот дефект и прожил свою жизнь.

var (
	// ErrEntryOutsideModuleShape — запись каталога не имеет формы
	// `<владелец>.cloud.<модуль>.v1.<Служба>/<Метод>`: ресурсом модуля она не
	// является. Каноничный такой случай — платформенная служба, у которой
	// сегмента версии нет вовсе.
	ErrEntryOutsideModuleShape = errors.New(
		"roleexport: запись каталога вне формы `<владелец>.cloud.<модуль>.v1.<Служба>/<Метод>`")
	// ErrEntryOwnerNotDeclared — форма у записи есть, а владельца пакета за этим
	// модулем дерево не объявляло (`internal/contractnaming`).
	//
	// Вид находки отдельный намеренно: «форма не та» и «форма та, владелец
	// чужой» чинятся в РАЗНЫХ местах, и общий отказ отправлял бы читателя не
	// туда. Сюда же попадает приставка, ОТСТАВШАЯ от переименования модуля, —
	// её молчаливый приём и был предметом #2168.
	ErrEntryOwnerNotDeclared = errors.New(
		"roleexport: владелец пакета контракта не объявлен за этим модулем")
	// ErrAttributionNotInjective — две записи каталога дали один ключ
	// (модуль, ресурс, действие). Правило вывода негодно, и молчать об этом
	// нельзя: одно из двух действий стало бы невидимым.
	ErrAttributionNotInjective = errors.New(
		"roleexport: две записи каталога привязаны к одному действию")
)

// Action — одно действие модуля вместе с координатами его гейта.
//
// `Relation` и `Object` лежат рядом намеренно: производимость есть свойство
// ПАРЫ, и структура, несущая только имя отношения, приглашала бы читать по имени.
type Action struct {
	// Module — модуль, которому действие принадлежит (`vpc`).
	Module string
	// Resource — ресурс в написании закрытой таблицы типов (`securityGroup`,
	// `targetGroups`). Написание ПРИВЕДЕНО (см. splitFQN): имя службы даёт
	// ресурс, слово для него объявляет таблица.
	Resource string
	// Verb — имя действия (`get`, `addCidrBlocks`, `internalAttach`).
	Verb string
	// FQN — запись каталога, из которой действие выведено. Отказ, называющий
	// действие без его записи, отправляет читателя искать её вручную.
	FQN string
	// Relation — отношение, которое спрашивает гейт. Пустая строка — гейта нет.
	Relation string
	// Object — тип объекта, на котором отношение спрашивается.
	Object string
	// Internal — действие живёт на ВНУТРЕННЕМ слушателе.
	//
	// Плоскость видна прямо в записи каталога — приставкой `Internal` у имени
	// службы, — и правило её чтения объявлено ЗДЕСЬ ЖЕ, единственным местом
	// (`splitFQN`). Поле заведено потому, что раздел `resources` объявляет ту
	// же плоскость своим признаком `internal`, и два объявления одного предмета
	// обязаны сверяться (linkage.go); прежде вычисленная плоскость
	// отбрасывалась, то есть сверять было нечем.
	Internal bool
}

// Exempt — у действия нет гейта вовсе: `required_relation` пуст.
//
// Освобождённое действие правом НЕ ВЫДАЁТСЯ — его получает всякий
// аутентифицированный, а не участник роли. Поэтому оно не входит в класс ни для
// покрытия, ни для отказа: класс объявлен не неверно, у класса просто нет
// предмета.
func (a Action) Exempt() bool { return a.Relation == "" }

// Attribute привязывает записи каталога к действиям модулей.
//
// Возвращает ВСЕ находки, а не первую: названная первая заставила бы чинить
// правило вывода по одной записи, по прогону на каждую.
func Attribute(entries []CatalogEntry) ([]Action, []error) {
	actions := make([]Action, 0, len(entries))
	var faults []error
	seen := make(map[string]string, len(entries))

	for _, e := range entries {
		module, resource, verb, internal, err := splitFQN(e.FQN)
		if err != nil {
			faults = append(faults, fmt.Errorf("%w: %s", err, e.FQN))
			continue
		}
		key := module + "." + resource + "." + verb
		if prev, dup := seen[key]; dup {
			faults = append(faults, fmt.Errorf("%w: %q и %q дали ключ %q",
				ErrAttributionNotInjective, prev, e.FQN, key))
			continue
		}
		seen[key] = e.FQN
		actions = append(actions, Action{
			Module:   module,
			Resource: resource,
			Verb:     verb,
			FQN:      e.FQN,
			Relation: e.RequiredRelation,
			Object:   e.ScopeObjectType,
			Internal: internal,
		})
	}

	// Порядок — документа, а не карты: перечень, зависящий от обхода карты,
	// читался бы по-разному от прогона к прогону.
	sort.SliceStable(actions, func(i, j int) bool { return actions[i].FQN < actions[j].FQN })
	return actions, faults
}

// splitFQN — единственное объявление правила «запись каталога → (модуль,
// ресурс, действие)».
//
// Возвращает ПРИЧИНУ, а не «не вышло»: у отказа два вида, и вызывающий обязан
// уметь их различить (см. объявления ошибок выше).
func splitFQN(fqn string) (module, resource, verb string, internal bool, err error) {
	head, method, cut := strings.Cut(fqn, "/")
	if !cut || method == "" {
		return "", "", "", false, ErrEntryOutsideModuleShape
	}
	// Имя пакета контракта — всё, кроме последнего сегмента: форму имени пакета
	// объявляет contractnaming, здесь она второй раз не объявляется.
	lastDot := strings.LastIndex(head, ".")
	if lastDot < 0 {
		return "", "", "", false, ErrEntryOutsideModuleShape
	}
	protoPackage, service := head[:lastDot], head[lastDot+1:]
	owner, module, shaped := contractnaming.Split(protoPackage)
	if !shaped || service == "" {
		return "", "", "", false, ErrEntryOutsideModuleShape
	}
	if !contractnaming.OwnsModule(owner, module) {
		return "", "", "", false, ErrEntryOwnerNotDeclared
	}
	internal = strings.HasPrefix(service, "Internal")
	base := strings.TrimPrefix(service, "Internal")
	if !strings.HasSuffix(base, "Service") || base == "Service" {
		return "", "", "", false, ErrEntryOutsideModuleShape
	}
	// Написание ресурса ПРИВОДИТСЯ к тому, которым его называет закрытая таблица
	// типов. Приведение объявлено ОДИН раз и не здесь
	// (authzmap.catalogSpellingByServiceName): у ключа таблицы есть читатель на
	// пути запроса — validateRuleCatalog отвергает правило роли, назвавшее ресурс
	// иначе, — а у написания, выведенного из имени службы, читателя нет. Без
	// приведения оба написания негодны разом: одно не сопоставляется ни с одной
	// записью каталога, другое отвергается на пути запроса (#1884).
	resource = authzmap.CatalogSpelling(module, lowerFirst(strings.TrimSuffix(base, "Service")))
	verb = lowerFirst(method)
	if internal {
		verb = "internal" + upperFirst(verb)
	}
	return module, resource, verb, internal, nil
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToLower(r[0])
	return string(r)
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	r := []rune(s)
	r[0] = unicode.ToUpper(r[0])
	return string(r)
}

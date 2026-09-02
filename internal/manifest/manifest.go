// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package manifest — форму манифеста домена судит ОДИН исполнитель: разбор в
// Go-структуры плюс `Decoder.KnownFields(true)` (задача #1088, приёмка
// services/iam/docs/engineering/acceptance/module-manifest-seed-contract.md,
// далее module-manifest-resources-roles-deprecated.md — задача #1778).
//
// Манифест — то, что домен объявляет платформе: чем он является и что нужно
// завести при его установке. Эта под-фаза описывает ОБОЛОЧКУ (`apiVersion`,
// `module`) и раздел `seed` целиком — служебные записи, группы, выдачи и
// вступления в чужие группы.
//
// # Почему один судья, а не схема плюс структуры
//
// Библиотеки JSON Schema для Go в дереве нет ни одной, и заводить её значило бы
// завести ДВА места об одном предмете — схему и структуру, — за согласием которых
// не следит ничто. Разошлись бы они молча и ровно там, где расхождение не видно:
// оба отвечают «валидно» на валидном входе, а расходятся только на невалидном.
//
// Опубликованная схема остаётся КОНТРАКТОМ для автора манифеста и его редактора,
// а не вторым судьёй; их согласие держит отдельная проба равенства множеств
// (MOD-MF-21), а не надежда.
//
// # Почему загрузчик живёт внутри services/iam, а не в pkg/
//
// Манифест адресован iam (`apiVersion: iam/v1`), читает его iam, и закрытый
// набор модулей принадлежит домену iam — `domain.IsKnownModule`. Из `pkg/` тот же
// вызов не собирается (правило видимости `internal`), и загрузчику пришлось бы
// нести ВТОРУЮ копию перечня модулей — ровно то, что запрещено абзацем выше.
// Прод-читателей манифеста вне `services/iam` сегодня ноль; появится второй —
// переезжает ФОРМА (структуры и разбор), а членство остаётся у iam.
//
// # Два свойства, которые держатся ЗДЕСЬ, а не в валидаторе связности
//
// Первое — неизвестный ключ. `KnownFields(true)` называет и поле, и номер строки
// на любой глубине; замер, из которого свойство выведено, дал
// `line 7: field clazz not found in type verb` на глубине 3.
//
// Второе — ключ-НЕ-строка, и оно тем более не может ждать связности: к тому
// моменту предмета уже нет. Типизированная цель `map[string]map[string]string`
// приводит ключ `true` к строке `"true"` с `err == nil`, а нетипизированная карта
// схлопывает `null:` и `~:` в один ключ, теряя одно значение без единого
// признака. Поэтому тип ключа судится по ТЕГУ узла разбора — см. keys.go.
//
// # Разделов ЧЕТЫРЕ, и все четыре описаны
//
// Оболочка плюс `resources` (что модуль объявляет платформе о своих правах),
// `roles` (роли аккаунта и проекта), `deprecatedVerbs` (принимаем на чтении, не
// производим) и `seed` (что заводит установка модуля). Каждый живёт в своём
// файле пакета — resources.go, roles.go, deprecated.go — вместе со своим
// разбором и своими отказами.
//
// Неизвестный раздел отвергается `KnownFields(true)`: он называет и ключ, и
// номер строки. Молча принять и выбросить нельзя — вызывающий получил бы успех
// и уверенность, что его раздел применён.
package manifest

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// Отказы различаются не ради красоты: «документ не той формы», «ключ не строка»,
// «раздел ещё не описан» и «модуль вне набора» чинятся разными правками разными
// людьми, и вызывающий (цель сборки, проверяющая дерево) вправе их различать.
var (
	// ErrEmptyDocument — на входе нет документа вовсе: пусто либо одни
	// комментарии. Не то же, что манифест без разделов.
	ErrEmptyDocument = errors.New("manifest: empty document")
	// ErrMultipleDocuments — в потоке больше одного документа. Манифест — один
	// документ: второй молча не читался бы никем.
	ErrMultipleDocuments = errors.New("manifest: multiple documents in one stream")
	// ErrRootNotMapping — корень документа не отображение.
	ErrRootNotMapping = errors.New("manifest: document root is not a mapping")
	// ErrNonStringKey — ключ отображения не является строкой (см. keys.go).
	ErrNonStringKey = errors.New("manifest: mapping key is not a string")
	// ErrShape — документ не ложится на объявленную форму: неизвестное поле либо
	// значение не того типа. Несёт сообщение библиотеки, называющее поле и строку.
	ErrShape = errors.New("manifest: document does not match the declared shape")
	// ErrSeedDeclaredNull — ключ `seed` объявлен без значения.
	//
	// Отдельный отказ, а не молчаливое приведение к «раздела нет»: приведение
	// вернуло бы ровно ту неразличимость, ради снятия которой Seed сделан
	// указателем. Пустой посев пишется как `seed: {}`.
	ErrSeedDeclaredNull = errors.New("manifest: seed is declared with no value")
	// ErrAPIVersionRequired — оболочка не сказала, по какой версии её читать.
	ErrAPIVersionRequired = errors.New("manifest: apiVersion is required")
	// ErrUnsupportedAPIVersion — версия оболочки этому загрузчику неизвестна.
	ErrUnsupportedAPIVersion = errors.New("manifest: unsupported apiVersion")
	// ErrModuleRequired — оболочка не сказала, чей это манифест.
	ErrModuleRequired = errors.New("manifest: module is required")
	// ErrUnknownModule — модуль вне закрытого платформенного набора.
	ErrUnknownModule = errors.New("manifest: module is outside the closed platform set")
)

// supportedAPIVersions — версии оболочки, которые этот загрузчик читает.
// Перечень попадает В ТЕКСТ ОТКАЗА: автор манифеста, ошибшийся версией, обязан
// узнать не только что ошибся, но и чем это чинить.
var supportedAPIVersions = []string{"iam/v1"}

// Manifest — оболочка манифеста домена.
//
// Раздел `seed` — УКАЗАТЕЛЬ: «модуль ничего не сеет» и «модуль объявил посев, и
// он пуст» суть разные утверждения, и вызывающий обязан их различать.
type Manifest struct {
	APIVersion string `yaml:"apiVersion"`
	Module     string `yaml:"module"`
	// Resources — что модуль объявляет платформе о своих правах. Раздел
	// НЕОДНОРОДЕН: часть ключей порождается из аннотаций, часть пишет человек —
	// см. resources.go.
	Resources []Resource `yaml:"resources"`
	// Roles — роли уровня аккаунта и проекта. Системную роль манифест не
	// объявляет: её сеет применённая миграция — см. roles.go.
	Roles []Role `yaml:"roles"`
	// DeprecatedVerbs — глаголы, принимаемые на чтении и не производимые на
	// записи. Ключ карты — само имя глагола, значение — запись с предикатом
	// снятия; см. deprecated.go.
	DeprecatedVerbs map[string]DeprecatedVerb `yaml:"deprecatedVerbs"`
	Seed            *Seed                     `yaml:"seed"`

	// linkage — перепись валидатора связности, снятая при загрузке. Поле
	// неэкспортируемое и без yaml-тега: это НЕ ключ документа, а результат
	// его проверки, и обход полей структур (MOD-MF-21) его не видит.
	linkage LinkageCensus
}

// Linkage — объём, осмотренный валидатором связности при загрузке.
//
// «Ноль находок» обязано быть отличимо от «ноль прочитанного»: валидатор, не
// заглянувший ни в одну выдачу, молчит ровно так же уверенно, как проверивший
// все. Число печатает потребитель загрузчика.
func (m *Manifest) Linkage() LinkageCensus { return m.linkage }

// Seed — что заводит УСТАНОВКА модуля. Ни один из четырёх подразделов не
// обязателен: модуль без своих групп и без вступлений — законный случай, а не
// неполный манифест.
type Seed struct {
	// ServiceAccounts — личности самого модуля: под ними он ходит к соседям.
	ServiceAccounts []ServiceAccount `yaml:"serviceAccounts"`
	// Groups — группы, которые этот модуль заводит для своих потребителей.
	// Создаются пустыми и без прав: что группа получает, сказано в AccessBindings.
	Groups []Group `yaml:"groups"`
	// AccessBindings — выдачи, которые делает установка модуля.
	AccessBindings []AccessBinding `yaml:"accessBindings"`
	// Joins — ЧУЖИЕ группы, в которые вступает служебная запись этого модуля.
	// Членство заявляет вступающий, а не перечисляет владелец группы: владелец
	// своих потребителей не знает и знать не должен.
	Joins []Join `yaml:"joins"`
}

// ServiceAccount — служебная запись, заводимая установкой этого модуля.
type ServiceAccount struct {
	Name    string `yaml:"name"`
	Account string `yaml:"account"`
	// Description — под что ИМЕННО эта личность. Поле названо как в продукте
	// (`service_accounts.description`), а не выдуманным синонимом: второе слово
	// для того же предмета разошлось бы с первым.
	Description string `yaml:"description"`
}

// Group — группа, заводимая установкой этого модуля.
type Group struct {
	Name        string `yaml:"name"`
	Account     string `yaml:"account"`
	Description string `yaml:"description"`
}

// AccessBinding — выдача. Имена полей взяты ДОСЛОВНО у контракта
// `CreateAccessBinding`: иначе манифест заводит второй словарь для того же
// предмета, и он разойдётся с первым.
type AccessBinding struct {
	Subjects  []Subject `yaml:"subjects"`
	RoleID    string    `yaml:"roleId"`
	ScopeType string    `yaml:"scopeType"`
	ScopeID   string    `yaml:"scopeId"`
	Target    string    `yaml:"target"`
	// Resources — закрытый перечень объектов, когда Target назван `resources`.
	Resources []TargetResource `yaml:"resources"`
}

// Subject — субъект выдачи. Назван ИМЕНЕМ, а не идентификатором: идентификаторы
// присваивает запись, манифест их знать не может.
type Subject struct {
	Type string `yaml:"type"`
	Name string `yaml:"name"`
}

// TargetResource — один объект закрытого перечня выдачи.
type TargetResource struct {
	Type string `yaml:"type"`
	ID   string `yaml:"id"`
}

// Join — вступление служебной записи модуля в чужую группу.
type Join struct {
	ServiceAccount SubjectRef `yaml:"serviceAccount"`
	Group          SubjectRef `yaml:"group"`
	// Why — зачем вступаем. Членство без причины некому снять: следующий не
	// знает, действует ли ещё основание.
	Why string `yaml:"why"`
}

// SubjectRef — сторона вступления, адресуемая ПАРОЙ (аккаунт, имя): так они
// уникальны в продукте (`groups_account_name_unique`,
// `service_accounts_account_name_unique`). Аккаунты сторон смеют различаться —
// `group_members` связи с аккаунтом не несёт вовсе.
type SubjectRef struct {
	Account string `yaml:"account"`
	Name    string `yaml:"name"`
}

// Load разбирает манифест домена, отвергает всё, что не ложится на объявленную
// форму, и проверяет СВЯЗНОСТЬ разобранного (linkage.go). Возвращаемый манифест
// непуст ТОЛЬКО при nil-ошибке: отвергнутый документ вызывающему не отдаётся ни
// в каком виде, поэтому дальше по пути такой вход не уезжает вовсе.
//
// Порядок проверок — часть контракта, а не деталь: тип ключа судится ДО
// приведения к типизированной цели (иначе предмета уже нет), известный, но не
// описанный раздел — ДО проверки неизвестных полей (иначе автор получил бы
// «неизвестное поле resources» вместо «раздел ещё не описан»), а связность —
// ПОСЛЕ формы и внутри той же загрузки: вынесенная отдельным вызовом, она стала
// бы шагом, который вызывающий вправе забыть, и манифест с выдачей на
// несуществующую роль уехал бы дальше, получив «годен».
func Load(data []byte) (*Manifest, error) {
	var root yaml.Node
	if err := yaml.Unmarshal(data, &root); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrShape, err)
	}
	if root.Kind == 0 || len(root.Content) == 0 {
		return nil, ErrEmptyDocument
	}
	doc := root.Content[0]
	if doc.Kind != yaml.MappingNode {
		return nil, fmt.Errorf("%w: line %d: root node is %s, a manifest is a mapping",
			ErrRootNotMapping, doc.Line, nodeKindName(doc.Kind))
	}

	if faults := checkStringKeys(doc); len(faults) > 0 {
		return nil, fmt.Errorf("%w: %s", ErrNonStringKey, joinFaults(faults))
	}
	if err := refuseNullSeed(doc); err != nil {
		return nil, err
	}

	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrShape, err)
	}
	// Второй документ в потоке молча не прочёл бы никто.
	var extra yaml.Node
	switch err := dec.Decode(&extra); {
	case err == nil:
		return nil, fmt.Errorf("%w: line %d", ErrMultipleDocuments, extra.Line)
	case errors.Is(err, io.EOF):
	default:
		return nil, fmt.Errorf("%w: %w", ErrShape, err)
	}

	if err := m.validateEnvelope(); err != nil {
		return nil, err
	}

	// Разделы судятся В ПОРЯДКЕ ДОКУМЕНТА, и находки собираются ВСЕ: названная
	// первая заставила бы автора чинить их по одной, по прогону на каждую.
	faults := validateResources(&m, doc)
	faults = append(faults, validateRoles(&m, doc)...)
	faults = append(faults, validateDeprecatedVerbs(&m, doc)...)

	// Связность — последняя ступень той же загрузки; почему не отдельным
	// вызовом, сказано в шапке Load. Перечень ролей приезжает ИЗ РАЗОБРАННОГО
	// ДОКУМЕНТА: послабление #1088, при котором он подавался параметром, истекло
	// вместе с описанием раздела.
	census, linkFaults := validateSeedLinkage(&m, doc, roleIDsOf(doc, &m))
	faults = append(faults, linkFaults...)
	if len(faults) > 0 {
		return nil, errors.Join(faults...)
	}
	m.linkage = census
	return &m, nil
}

// roleIDsOf — роли, объявленные РАЗОБРАННЫМ документом.
//
// Состояний ТРИ, а не два, и различает их присутствие самого ключа в документе:
// «раздел не объявлен» значит «сверять не с чем», «объявлен и пуст» — «автор
// сказал, что ролей у него нет», и всякая выдача тогда ссылается в пустоту.
// Схлопни их в одно — и правило замолчит ровно там, где автор ошибся.
func roleIDsOf(doc *yaml.Node, m *Manifest) roleIDs {
	if mapValue(doc, "roles") == nil {
		return rolesNotDeclared()
	}
	ids := make([]string, 0, len(m.Roles))
	for _, r := range m.Roles {
		ids = append(ids, r.ID)
	}
	return rolesDeclared(ids...)
}

// validateEnvelope — оболочка: по какой версии читать и чей это манифест.
func (m *Manifest) validateEnvelope() error {
	switch {
	case m.APIVersion == "":
		return fmt.Errorf("%w: supported: %s", ErrAPIVersionRequired, strings.Join(supportedAPIVersions, ", "))
	case !contains(supportedAPIVersions, m.APIVersion):
		return fmt.Errorf("%w: got %q, supported: %s",
			ErrUnsupportedAPIVersion, m.APIVersion, strings.Join(supportedAPIVersions, ", "))
	}

	if m.Module == "" {
		return fmt.Errorf("%w: the platform module set is closed: %s",
			ErrModuleRequired, strings.Join(domain.KnownModules(), ", "))
	}
	// Набор БЕРЁТСЯ У ВЛАДЕЛЬЦА. Своя копия перечня разошлась бы с литералом
	// молча — этот самый набор уже переживал такое, когда шестое имя добавили, а
	// комментарий рядом остался при пяти.
	if !domain.IsKnownModule(m.Module) {
		return fmt.Errorf("%w: got %q, the platform module set is closed: %s",
			ErrUnknownModule, m.Module, strings.Join(domain.KnownModules(), ", "))
	}
	return nil
}

// refuseNullSeed — `seed:` без значения. Отличить «ключа нет» от «ключ есть и
// пуст» по разобранному указателю уже нельзя: YAML даёт null, указатель — nil.
func refuseNullSeed(doc *yaml.Node) error {
	for i := 0; i+1 < len(doc.Content); i += 2 {
		key, value := doc.Content[i], doc.Content[i+1]
		if key.Value != "seed" || value.Tag != "!!null" {
			continue
		}
		return fmt.Errorf(
			"%w: line %d: write `seed: {}` to declare an empty seed, or omit the key entirely",
			ErrSeedDeclaredNull, key.Line)
	}
	return nil
}

func contains(set []string, v string) bool {
	for _, s := range set {
		if s == v {
			return true
		}
	}
	return false
}

func nodeKindName(k yaml.Kind) string {
	switch k {
	case yaml.DocumentNode:
		return "a document"
	case yaml.SequenceNode:
		return "a sequence"
	case yaml.MappingNode:
		return "a mapping"
	case yaml.ScalarNode:
		return "a scalar"
	case yaml.AliasNode:
		return "an alias"
	default:
		return "of an unknown kind"
	}
}

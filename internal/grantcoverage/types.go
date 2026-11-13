// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package grantcoverage доказывает включение явно нормализованных эффектов.
// Он не читает Rule, preview, БД или модель и сам не разрешает мутации.
// Производитель обязан вывести ВСЕ эффекты из одного writer snapshot и
// закреплённых модели/каталога, раскрыть реальный каскад в точные Anchor,
// разрешить creator в конкретного субъекта и сохранить неизвестное как
// Unsupported. Complete — утверждение производителя, не проверка полноты БД.
// Совпадение идентификаторов не доказывает добросовестность нормализатора.
package grantcoverage

import "github.com/PRO-Robotech/kaname/internal/domain"

// Identity закрепляет модель, каталог и версию проекции обеих сторон
// одного доказательства. Пустая версия и расхождение любой оси закрывают proof.
// Идентификаторы должны меняться при изменении соответствующего содержимого.
type Identity struct {
	ModelID          string
	CatalogID        string
	ProjectorVersion string
}

// Anchor — уже эффективная область. Наследование здесь не выводится.
type Anchor = domain.ScopeAnchor

type EffectKind uint8

const (
	ResourceUse EffectKind = iota + 1
	CreateBinding
	BindRole
	Unsupported
)

type ActionKind uint8

const (
	Verb ActionKind = iota + 1
	Relation
	AllVerbs
)

// Action хранит одно действие. AllVerbs — символическое множество, включая
// будущие глаголы этого типа; оно не включает Relation или meta-эффекты.
// Relation допустимо только после доказанной нормализации отношения модели.
// Сырые custom relation, children и condition передаются как Unsupported.
type Action struct {
	Kind ActionKind
	Name string
}

type ObjectKind uint8

const (
	AllObjects ObjectKind = iota + 1
	ObjectIDs
)

// Objects не подменяет универсум текущей выборкой живых объектов.
type Objects struct {
	Kind ObjectKind
	IDs  []string
}

type CreatorKind uint8

const (
	AnyCreator CreatorKind = iota + 1
	ExactCreator
)

// Creator содержит разрешённого субъекта, а не относительное «сам получатель».
// Group/system_class не являются конкретным создателем.
type Creator struct {
	Kind    CreatorKind
	Subject domain.Subject
}

// Region — пересечение Objects, равенств Labels и Creator. Пустая карта
// Labels означает отсутствие ограничений по меткам. Фактические метки
// сегодняшнего объекта нельзя добавлять сюда как вечные ограничения права.
// Наличие IDs и Labels вместе отражает уже доказанное пересечение target и
// селектора, а не изменение публичного XOR-контракта Rule.
type Region struct {
	Objects Objects
	Labels  map[string]string
	Creator Creator
}

type Resource struct {
	Module string
	Type   string
	Action Action
	Region Region
}

// Effect — закрытое объединение. ResourceUse использует только Resource;
// BindRole — только RoleID; CreateBinding — только Anchor. У meta-эффектов
// модуль, тип и действие заданы самим Kind и не зависят от resource wildcard.
// Unsupported хранит только UnsupportedReason. Чужие payload-поля запрещены.
// RoleID источника resource-use здесь намеренно отсутствует: роли объединяются.
type Effect struct {
	Kind              EffectKind
	Anchor            Anchor
	Resource          Resource
	RoleID            domain.RoleID
	UnsupportedReason string
}

type EffectSet struct {
	Identity Identity
	Complete bool
	Effects  []Effect
}

type EmptyPolicy uint8

const (
	RejectEmpty EmptyPolicy = iota
	ProveEmpty
)

type Request struct {
	Identity Identity
	Actor    EffectSet
	Proposed EffectSet
	// Только явный ProveEmpty разрешает математическое включение пустого
	// результата, ПОСЛЕ проверки обеих сторон. Это не право создать binding.
	Empty EmptyPolicy
}

type Status uint8

const (
	NotProved Status = iota
	Invalid
	Proved
)

type Reason string

const (
	ReasonNone        Reason = ""
	ReasonMalformed   Reason = "malformed"
	ReasonIncomplete  Reason = "incomplete_normalization"
	ReasonIdentity    Reason = "model_or_catalog_mismatch"
	ReasonUnsupported Reason = "unsupported_effect"
	ReasonUncovered   Reason = "uncovered_effect"
	ReasonEmpty       Reason = "empty_proposal_requires_explicit_policy"
	ReasonLimit       Reason = "structural_limit"
	ReasonWorkLimit   Reason = "proof_work_limit"
)

type Side uint8

const (
	RequestSide Side = iota
	ActorSide
	ProposedSide
)

// Result не является boolean-authorizer. Index относится к Effects указанной
// стороны; -1 означает весь запрос/набор. Нулевой Result не доказывает ничего.
type Result struct {
	Status Status
	Reason Reason
	Side   Side
	Index  int
}

// Лимиты вычисления, не ограничения публичного API. Производитель обязан
// собрать все страницы; превышение нельзя лечить усечением входа. Отдельные
// вызовы для страниц не заменяют доказательства полного предлагаемого эффекта.
const (
	MaxEffects         = 16384
	MaxSelectorEntries = 131072
	MaxStringBytes     = 4096
	MaxInputBytes      = 8 << 20
	MaxProofSteps      = 1 << 20
)

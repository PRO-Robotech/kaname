// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package granteffect компилирует символический эффект выдачи без опроса объектов.
// Наличие результата не удостоверяет действительность источника actor: её обязан
// установить писатель в том же снимке. Компилятор не разрешает мутации.
package granteffect

import (
	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
)

type Kind uint8

const (
	Use Kind = iota + 1
	CreateBinding
	BindRole
	ScopeAdmin
)

// Condition хранит неизменённый предикат конкретного источника. Поддержанная
// импликация — тождество Name+Parameters либо безусловный покрывающий источник.
// Parameters — JSON без лишних пробелов; порядок ключей сохраняется.
// Вычисление предиката «сейчас» не заменяет условие на всём множестве запросов.
type Condition struct{ Name, Parameters string }

// Constraint ограничивает объект на полном пути от объекта проверяемого права.
// Within — символическая принадлежность области из текущего producer; nil
// допустим для точного scope-self объекта. Метки сегодняшнего объекта не нужны.
type Constraint struct {
	Path   []authzmodel.EffectHop
	Type   string
	Region grantcoverage.Region
	Within *domain.ScopeAnchor
}

type Provenance struct {
	SourceID        string
	RoleID          domain.RoleID
	AuthoredRuleFP  string
	ProjectedRuleFP string
	Primitive       string
	ModelOrigin     string
}

type Effect struct {
	Kind        Kind
	Type        string
	Action      grantcoverage.Action
	Anchor      domain.ScopeAnchor
	RoleID      domain.RoleID
	Constraints []Constraint
	Condition   Condition
	Provenance  Provenance
}

type Obligation struct {
	Code, Detail string
	Provenance   Provenance
}

// Set выдаётся только компилятором. Закрытые поля исключают подстановку
// caller-provided Complete=true; Effects возвращает независимую копию.
type Set struct {
	identity    grantcoverage.Identity
	effects     []Effect
	obligations []Obligation
	steps       int
	outputBytes int
	limited     bool
}

func (s Set) Identity() grantcoverage.Identity { return s.identity }
func (s Set) Complete() bool {
	return s.identity.ModelID != "" && s.identity.CatalogID != "" && s.identity.ProjectorVersion == ProjectorVersion && len(s.obligations) == 0
}
func (s Set) Effects() []Effect         { return cloneEffects(s.effects) }
func (s Set) Obligations() []Obligation { return append([]Obligation(nil), s.obligations...) }

// Binding описывает один полный предлагаемый источник на одного получателя.
// Для нескольких получателей Compile вызывается для каждого, не только первого.
// Subjects содержит полный перечень получателей источника; для system_class
// обязателен, поскольку ключ public_reader зависит от всех классов сразу.
// Непустой перечень проверяется на валидность, уникальность и наличие Recipient.
// CapabilityVersion=0 сохраняет ordinary семантику старого carrier.
type Binding struct {
	SourceID          string
	Role              domain.Role
	Scope             domain.ScopeAnchor
	Target            domain.AccessTarget
	Recipient         domain.Subject
	Subjects          []domain.Subject
	CapabilityVersion int
}

// Direct — конкретный source-backed факт actor или иной явный producer.
// Его существование, условие и принадлежность actor проверяет writer adapter.
type Direct struct {
	SourceID                       string
	ObjectType, ObjectID, Relation string
	Recipient                      domain.Subject
	Condition                      Condition
}

const MaxEffects = 16384
const MaxSteps = 1 << 20
const MaxInputBytes = 8 << 20

func cloneEffects(in []Effect) []Effect {
	out := append([]Effect(nil), in...)
	for i := range out {
		out[i].Constraints = cloneConstraints(out[i].Constraints)
	}
	return out
}
func cloneConstraints(in []Constraint) []Constraint {
	out := append([]Constraint(nil), in...)
	for i := range out {
		out[i].Path = append([]authzmodel.EffectHop(nil), out[i].Path...)
		out[i].Region.Objects.IDs = append([]string(nil), out[i].Region.Objects.IDs...)
		if out[i].Region.Labels != nil {
			m := map[string]string{}
			for k, v := range out[i].Region.Labels {
				m[k] = v
			}
			out[i].Region.Labels = m
		}
		if out[i].Within != nil {
			a := *out[i].Within
			out[i].Within = &a
		}
	}
	return out
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzformbench

// planalias.go — прибор берёт разбор модели и компиляцию плана ИЗ ПРОДУКТА.
//
// # Почему псевдонимы, а не копия
//
// Разбор канонического DSL и компиляция отношения в план вердикта переехали в
// `services/iam/internal/authzplan` как продуктовый код (XC-12, Ф0). Прибор продолжает ими
// пользоваться — но НЕ своей копией: две реализации одного разбора разошлись бы
// молча, и прибор доказывал бы эквивалентность не тому, что исполняет продукт.
// Ровно это и есть его предмет, поэтому копия здесь была бы отрицанием его смысла.
//
// Псевдонимы типов (`=`), а не обёртки: тип взаимозаменяем с источником, никаких
// преобразований на границе.
import "github.com/PRO-Robotech/kacho-iam/internal/authzplan"

type (
	Model         = authzplan.Model
	ModelType     = authzplan.ModelType
	Relation      = authzplan.Relation
	Term          = authzplan.Term
	TermKind      = authzplan.TermKind
	DirectSubject = authzplan.DirectSubject
	Plan          = authzplan.Plan
	Atom          = authzplan.Atom
	AtomKind      = authzplan.AtomKind
	Census        = authzplan.Census
)

const (
	VerbPrefix      = authzplan.VerbPrefix
	MaxPointerDepth = authzplan.MaxPointerDepth
)

// Константы видов терма и атома — того же перечисления, что у продукта.
const (
	TermDirect   = authzplan.TermDirect
	TermComputed = authzplan.TermComputed
	TermTTU      = authzplan.TermTTU

	AtomBinding = authzplan.AtomBinding
	AtomFact    = authzplan.AtomFact
)

var (
	ParseModel            = authzplan.ParseModel
	ResolveCanonicalModel = authzplan.ResolveCanonicalModel
	IsVerb                = authzplan.IsVerb
)

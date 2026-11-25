// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package granteffect

import (
	"strings"
	"unicode"
	"unicode/utf8"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/grantcapability"
	"github.com/PRO-Robotech/kaname/internal/grantcoverage"
)

// CompileMaterializedTuple выводит эффекты одного кортежа на точном объекте,
// включая унаследованные отношения модели. Писатель передаёт координату
// объекта из того же снимка, что и кортеж, и ведёт остаток отдельно для
// каждого получателя и срока выдачи. MembershipTuple не содержит условия,
// поэтому подходит только прямое безусловное объявление для данного субъекта.
// Пути вывода сохраняются символически. Принадлежность области, фактические
// предки и будущие совпадения селектора требуют самостоятельного доказательства.
func (b *Bundle) CompileMaterializedTuple(bindingID domain.AccessBindingID, object domain.ResourceRef, recipient domain.Subject, tuple domain.MembershipTuple) Set {
	if b.Validate() != nil {
		return Set{}
	}
	fail := func(detail string) Set {
		return Set{identity: b.Identity(), obligations: []Obligation{{Code: "materialized_tuple", Detail: detail}}}
	}
	if !materializedToken(string(bindingID)) || !materializedToken(object.Type) || !materializedToken(object.ID) || !materializedToken(tuple.Relation) {
		return fail("invalid binding, object or relation")
	}
	if !materializedToken(string(recipient.Type)) || !materializedToken(string(recipient.ID)) || recipient.Validate() != nil ||
		tuple.User != domain.FGASubjectRef(string(recipient.Type), string(recipient.ID)) {
		return fail("recipient mismatch")
	}
	typ, known := b.compiler.facts.FGAObjectType(object.Type)
	if !known || !materializedToken(typ) || grantcapability.IsInternalObjectType(typ) || tuple.Object != typ+":"+object.ID {
		return fail("materialized object does not match live catalog coordinate")
	}
	return b.CompileDirect(Direct{
		SourceID: "materialized:" + string(bindingID), ObjectType: typ, ObjectID: object.ID,
		Relation: tuple.Relation, Recipient: recipient,
	})
}

// Разделители кортежа допустимы только в форме, построенной из его частей.
func materializedToken(s string) bool {
	return s != "" && len(s) <= grantcoverage.MaxStringBytes && utf8.ValidString(s) && !strings.ContainsAny(s, ":#*") &&
		strings.IndexFunc(s, func(r rune) bool { return unicode.IsControl(r) || unicode.IsSpace(r) }) < 0
}

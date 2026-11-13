// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

import (
	"errors"
	"strings"
	"time"
)

var ErrProducerReceipt = errors.New("invalid producer receipt")

const (
	RegistrationOwnerReceipt = "registration_owner"
	PublicationReceipt       = "publication"
)

// ProducerReceipt — данные фактически принятого producer, не authority.
// Bundle identity намеренно отсутствует: этот порт не вправе подтвердить её.
// Conditions нынешних производителей безусловны; иной ввод отвергается.
type ProducerReceipt struct {
	Kind, Module, CatalogType, ObjectType, ObjectID, Relation string
	Subject                                                   Subject
	ConditionName, ConditionParameters                        string
	Scopes                                                    []ContainerScope
	SourceVersion                                             time.Time
}

func (r ProducerReceipt) Validate() error {
	atom := func(s string) bool { return s != "" && !strings.ContainsAny(s, " :#*\t\r\n\x00") }
	if !atom(r.Module) || !atom(r.ObjectType) || !atom(r.ObjectID) || !strings.HasPrefix(r.CatalogType, r.Module+".") || !atom(r.CatalogType) || r.Subject.Validate() != nil || !atom(string(r.Subject.ID)) || r.ConditionName != "" || r.ConditionParameters != "" || len(r.Scopes) == 0 || len(r.Scopes) > 256 {
		return ErrProducerReceipt
	}
	switch r.Kind {
	case RegistrationOwnerReceipt:
		if r.Relation != "owner" || (r.Subject.Type != SubjectTypeUser && r.Subject.Type != SubjectTypeServiceAccount) {
			return ErrProducerReceipt
		}
	case PublicationReceipt:
		if string(r.Subject.Type)+":"+string(r.Subject.ID) != PublicationSubject || r.Relation != PublicationRelation {
			return ErrProducerReceipt
		}
	default:
		return ErrProducerReceipt
	}
	seen := map[string]bool{}
	for _, s := range r.Scopes {
		if !s.Registered || !atom(s.AccountID) || (s.ProjectID != "" && !atom(s.ProjectID)) {
			return ErrProducerReceipt
		}
		key := s.AccountID + ":" + s.ProjectID
		if seen[key] {
			return ErrProducerReceipt
		}
		seen[key] = true
	}
	return nil
}

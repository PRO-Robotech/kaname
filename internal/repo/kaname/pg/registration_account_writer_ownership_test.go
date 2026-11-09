// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzguard"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Одного совпавшего журнала или проекции недостаточно для системного отзыва.
// Отказ проверяется и тогда, когда обе подменённые формы согласны между собой.
func TestRegistrationWriterOwnershipRequiresItsGrantAndEntireSubjectSet(t *testing.T) {
	a := writerAssignment{id: "assignment", binding: "acb00000000000000001", account: "acc00000000000000001", module: "registry"}
	expected := domain.Subject{Type: domain.SubjectTypeServiceAccount, ID: domain.SubjectID(authzguard.ServiceAccountIDForService(a.module))}
	foreign := domain.SubjectID(authzguard.ServiceAccountIDForService("vpc"))
	lawful := domain.AccessBinding{
		ID: domain.AccessBindingID(a.binding), System: true,
		SubjectType: expected.Type, SubjectID: expected.ID,
		ResourceType: domain.ResourceType("account"), ResourceID: a.account,
		GrantedRelation: authzguard.RelationWriteRelation,
	}
	for _, tc := range []struct {
		name   string
		mutate func(*domain.AccessBinding, *[]domain.Subject)
	}{
		{"foreign-binding", func(b *domain.AccessBinding, _ *[]domain.Subject) { b.ID = "acb00000000000000002" }},
		{"foreign-account", func(b *domain.AccessBinding, _ *[]domain.Subject) { b.ResourceID = "acc00000000000000002" }},
		{"foreign-resource-kind", func(b *domain.AccessBinding, _ *[]domain.Subject) { b.ResourceType = "project" }},
		{"not-system", func(b *domain.AccessBinding, _ *[]domain.Subject) { b.System = false }},
		{"role-grant", func(b *domain.AccessBinding, _ *[]domain.Subject) { b.RoleID = "rol00000000000000001" }},
		{"foreign-relation", func(b *domain.AccessBinding, _ *[]domain.Subject) { b.GrantedRelation = "viewer" }},
		{"wrong-projected-type", func(b *domain.AccessBinding, _ *[]domain.Subject) { b.SubjectType = domain.SubjectTypeGroup }},
		{"wrong-projected-id", func(b *domain.AccessBinding, _ *[]domain.Subject) { b.SubjectID = foreign }},
		{"missing-set", func(_ *domain.AccessBinding, subjects *[]domain.Subject) { *subjects = nil }},
		{"extra-subject", func(_ *domain.AccessBinding, subjects *[]domain.Subject) {
			*subjects = append(*subjects, domain.Subject{Type: expected.Type, ID: foreign})
		}},
		{"foreign-set-subject", func(_ *domain.AccessBinding, subjects *[]domain.Subject) { (*subjects)[0].ID = foreign }},
		{"matching-foreign-projection-and-set", func(b *domain.AccessBinding, subjects *[]domain.Subject) {
			b.SubjectID = foreign
			(*subjects)[0].ID = foreign
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			b := lawful
			subjects := []domain.Subject{expected}
			if !registrationWriterOwnsGrant(b, a, subjects) {
				t.Fatal("законная выдача и полный набор отвергнуты до инъекции")
			}
			tc.mutate(&b, &subjects)
			if registrationWriterOwnsGrant(b, a, subjects) {
				t.Fatal("чужая выдача или изменённый набор признаны собственными")
			}
		})
	}
}

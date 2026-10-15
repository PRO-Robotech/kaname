// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

import (
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

// TestProxyWriteRefusesAClassSubjectOnAHierarchyRelation — путь регистрации
// (FGA-прокси соседа: RegisterResource и его пары) не принимает класс
// субъектов (`system_class:…`) субъектом отношения иерархии (kaname#838).
//
// Класс означает «всякий такой субъект»: предком либо владельцем ресурса он
// раздал бы доступ целому классу мимо выдачи прав, где грант перечислим,
// ограничен областью и отзываем. Наблюдаемое на этой границе — код и текст
// отказа, поэтому проба судит их, а не «какую-то ошибку».
//
// Каждая строка отказа стоит рядом с законным близнецом, который меняет ровно
// один факт — тип субъекта — и проходит: отказ даёт класс, а не отношение,
// объект или домен.
func TestProxyWriteRefusesAClassSubjectOnAHierarchyRelation(t *testing.T) {
	t.Parallel()

	for _, tt := range []struct {
		name, domain, subject, relation, object string
		refused                                 bool
	}{
		{"class as project", "vpc", "system_class:anonymous", "project", "vpc_network:net1", true},
		{"twin: project as project", "vpc", "project:prj1", "project", "vpc_network:net1", false},
		{"class as parent", "vpc", "system_class:authenticated", "parent", "vpc_subnet:sub1", true},
		{"twin: network as parent", "vpc", "vpc_network:net1", "parent", "vpc_subnet:sub1", false},
		{"class as owner", "vpc", "system_class:authenticated", "owner", "vpc_network:net1", true},
		{"twin: user as owner", "vpc", "user:usr1", "owner", "vpc_network:net1", false},
		// Неизвестный домен снимает связывание по домену, но не отказ классу.
		{"class as project, domain unknown", "", "system_class:anonymous", "project", "vpc_network:net1", true},
		{"twin: project as project, domain unknown", "", "project:prj1", "project", "vpc_network:net1", false},
	} {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := validateProxyTuple(tt.domain, tt.subject, tt.relation, tt.object)
			if !tt.refused {
				if err != nil {
					t.Fatalf("законный близнец (%s %s %s) отвергнут: %v", tt.subject, tt.relation, tt.object, err)
				}
				return
			}
			if err == nil {
				t.Fatalf("класс субъекта %s принят на отношении иерархии %s объекта %s",
					tt.subject, tt.relation, tt.object)
			}
			if got := status.Code(err); got != codes.PermissionDenied {
				t.Fatalf("код = %v; ожидался %v", got, codes.PermissionDenied)
			}
			if got := status.Convert(err).Message(); got != "permission denied" {
				t.Fatalf("текст = %q; ожидался %q", got, "permission denied")
			}
		})
	}
}

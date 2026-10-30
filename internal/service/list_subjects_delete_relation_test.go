// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

// list_subjects_delete_relation_test.go — «кто может удалить X» спрашивает то же
// отношение, что `Check(delete)` (приёмка role-rights-stay-within-what-is-named.md,
// ESC-06 а; задачи PRO-Robotech/kaname#1035, PRO-Robotech/kaname#1039).
//
// Прежде действие удаления разрешалось ярусом `admin`. Глагол удаления больше не
// выводит яруса (Р1), поэтому ярусный ответ потерял бы держателя одного удаления,
// которого `Check(delete)` пропускает. Отношение берётся у типа объекта из
// каталога модуля — тем же `moduleVerbRelation`, что у `Check`.

import (
	"context"
	"sync"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
)

// relationRecorder — хранилище, запоминающее отношение вопроса ListSubjects.
type relationRecorder struct {
	mockRelations
	mu       sync.Mutex
	listedBy string
}

func (r *relationRecorder) ListSubjects(_ context.Context, _, _, relation string, _ int, _ string) ([]string, string, error) {
	r.mu.Lock()
	r.listedBy = relation
	r.mu.Unlock()
	return []string{"user:usr-1"}, "", nil
}

// TestListSubjects_DeleteAsksTheVerbOfTheType — строки отличаются ровно глаголом
// либо типом объекта.
func TestListSubjects_DeleteAsksTheVerbOfTheType(t *testing.T) {
	cases := []struct {
		name, action, objectType, want string
	}{
		{"удаление репозитория — глагол типа", "registry.repositories.delete", "registry_repository", "v_delete"},
		{"чтение репозитория — ярус, как прежде", "registry.repositories.get", "registry_repository", "viewer"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			rec := &relationRecorder{}
			svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: rec, Catalog: catalog.Fixed{F: moduleVerbFacts(t)}})
			res, err := svc.ListSubjects(context.Background(), ListSubjectsRequest{
				ResourceType: c.objectType, ResourceID: "reg1/app", Action: c.action, PageSize: 10,
			})
			if err != nil {
				t.Fatalf("ListSubjects(%s): %v", c.action, err)
			}
			if len(res.Subjects) != 1 {
				t.Fatalf("ListSubjects(%s): ответ хранилища не дошёл: %v", c.action, res.Subjects)
			}
			if rec.listedBy != c.want {
				t.Errorf("ListSubjects(%s на %s) спросил отношение %q, ждали %q", c.action, c.objectType, rec.listedBy, c.want)
			}
		})
	}
}

// TestListSubjects_DeleteOfATypeWithoutTheVerbIsRefused — тип, не объявивший
// удаления, ответа «кто может удалить» не получает: `Check(delete)` на нём
// разрешает лишь администратор облака, а ярусного ответа больше нет. Отказ —
// «вход не назван», как у неизвестного глагола; хранилище не спрашивается.
func TestListSubjects_DeleteOfATypeWithoutTheVerbIsRefused(t *testing.T) {
	rec := &relationRecorder{}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: rec, Catalog: catalog.Fixed{F: moduleVerbFacts(t)}})
	_, err := svc.ListSubjects(context.Background(), ListSubjectsRequest{
		ResourceType: "vpc_network", ResourceID: "net1", Action: "vpc.network.delete", PageSize: 10,
	})
	if err == nil || err.Error() != `Illegal argument action "vpc.network.delete"` {
		t.Fatalf("удаление типа без глагола: ждали отказ «Illegal argument action», получили %v (спрошено %q)", err, rec.listedBy)
	}
	if rec.listedBy != "" {
		t.Errorf("хранилище спрошено отношением %q при отказе", rec.listedBy)
	}
}

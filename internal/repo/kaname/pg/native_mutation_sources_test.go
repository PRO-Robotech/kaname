// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmap"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg/relverdict"
)

func TestMutationSourceLeafBoundaryPreservesNativeGrantArm(t *testing.T) {
	for _, typ := range []string{"account", "project", "iam_role", "iam_group", "iam_service_account", "registry_registry", "registry_repository"} {
		for _, relation := range append(authzmap.VerbRelationsOfType(typ), "admin", "owner", "editor", "viewer", "system_admin", "system_viewer", "any_admin", "public_reader") {
			if !mutationSourceRelation(relation) {
				t.Fatalf("не проверяется источник %s#%s", typ, relation)
			}
		}
	}
	// Отсутствие глагола в статическом словаре не даёт обойти живое доказательство.
	for _, relation := range []string{"v_retired", "v_not_declared_yet"} {
		if !mutationSourceRelation(relation) {
			t.Fatalf("неизвестный глагольный leaf принят за структурный: %s", relation)
		}
	}

	sources := &nativeAdministrativeSources{}
	for _, relation := range []string{"", "subject", "member", "parent", "project", "account", "cluster"} {
		if mutationSourceRelation(relation) {
			t.Fatalf("структурный путь принят за producer: %s", relation)
		}
		for _, question := range []string{"editor", "viewer", "v_update", "v_list"} {
			ok, err := sources.verify(context.Background(), relverdict.AdministrativeFact{Relation: relation, QuestionRelation: question}, &relverdict.AdministrativeReadBudget{})
			if err != nil || !ok {
				t.Fatalf("native grant/structural arm изменён: %s/%s: %v %v", relation, question, ok, err)
			}
		}
	}
}

func TestMutationContainerSourceUsesDeclaredParent(t *testing.T) {
	halves := catalog.Halves{Live: catalog.Rows{Resources: []catalog.ResourceRow{{Module: "iam", Resource: "serviceAccount", ObjectType: "iam_service_account"}}, Verbs: []catalog.VerbRow{{Module: "iam", Resource: "serviceAccount", Verb: "create", ContainerParent: "account", ContainerRelation: "service_account_creator"}, {Module: "iam", Resource: "serviceAccount", Verb: "probe", PerObject: true}}}}
	relations := mutationCatalogRelations(halves)
	if !relations[[2]string{"iam_service_account", "v_probe"}] || !relations[[2]string{"account", "service_account_creator"}] || relations[[2]string{"project", "service_account_creator"}] || relations[[2]string{"account", "subject"}] {
		t.Fatal("контейнерный источник потерял точного родителя")
	}
}

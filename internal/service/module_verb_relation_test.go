// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

// module_verb_relation_test.go — вывод отношения вопроса без отношения по
// каталогу модуля (kaname#994). Настоящий решатель утверждает исход в
// `access_binding/anonymous_self_check_module_verb_integration_test.go`; здесь —
// ЧТО именно спрашивается у хранилища и где подстановки умолчанием нет.

import (
	"context"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

// moduleVerbFacts — синтетический живой каталог: реестр с репозиториями и тип,
// которого порождённая сборкой таблица не знает (`billing_invoice`) — без него
// «ответил каталог» было бы неотличимо от «ответила таблица сборки».
func moduleVerbFacts(t *testing.T) *catalog.Facts {
	t.Helper()
	f, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{
		Modules: []string{"billing", "registry"},
		Resources: []catalog.ResourceRow{
			{Module: "billing", Resource: "invoice", ObjectType: "billing_invoice"},
			{Module: "registry", Resource: "registries", ObjectType: "registry_registry"},
			{Module: "registry", Resource: "repositories", ObjectType: "registry_repository"},
		},
		Verbs: []catalog.VerbRow{
			{Module: "billing", Resource: "invoice", Verb: "get", PerObject: true},
			{Module: "registry", Resource: "registries", Verb: "get", PerObject: true},
			{Module: "registry", Resource: "registries", Verb: "list", PerObject: true},
			{Module: "registry", Resource: "registries", Verb: "create", PerObject: true},
			{Module: "registry", Resource: "repositories", Verb: "get", PerObject: true},
			{Module: "registry", Resource: "repositories", Verb: "list", PerObject: true},
			{Module: "registry", Resource: "repositories", Verb: "delete", PerObject: true},
			{Module: "registry", Resource: "repositories", Verb: "create", PerObject: false},
		},
	}})
	if err != nil {
		t.Fatalf("фикстура каталога не собралась: %v", err)
	}
	return f
}

func TestModuleVerbRelation_TakesTheVerbOfTheObjectTypeFromTheCatalog(t *testing.T) {
	facts := moduleVerbFacts(t)
	for _, tc := range []struct {
		name, action, objectType, want string
	}{
		{"глагол типа объекта", "registry.repositories.get", "registry_repository", "v_get"},
		{"второй глагол того же типа", "registry.repositories.list", "registry_repository", "v_list"},
		{"глагол записи берётся так же", "registry.repositories.delete", "registry_repository", "v_delete"},
		{"реестр", "registry.registries.get", "registry_registry", "v_get"},
		{"глагол в верблюжьей записи RPC", "registry.registries.Get", "registry_registry", "v_get"},
		{"тип, неизвестный сборке", "billing.invoice.get", "billing_invoice", "v_get"},
		{"глагол без пообъектного отношения", "registry.repositories.create", "registry_repository", ""},
		{"глагол, которого тип не объявляет", "registry.repositories.update", "registry_repository", ""},
		{"действие о другом ресурсе", "registry.registries.get", "registry_repository", ""},
		{"тип без глаголов в каталоге", "iam.cluster.get", "cluster", ""},
		{"ресурс вне каталога", "vpc.networks.get", "vpc_network", ""},
		{"две части", "registry.get", "registry_repository", ""},
		{"пустой глагол", "registry.repositories.", "registry_repository", ""},
		{"пустое действие", "", "registry_repository", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := moduleVerbRelation(facts, tc.action, tc.objectType); got != tc.want {
				t.Fatalf("moduleVerbRelation(%q, %q) = %q; want %q", tc.action, tc.objectType, got, tc.want)
			}
		})
	}
	if got := moduleVerbRelation(nil, "registry.repositories.get", "registry_repository"); got != "" {
		t.Fatalf("без каталога отношения нет; got %q", got)
	}
}

// TestCheck_RelationByModuleVerbAsksTheModuleVerb — вопрос с флагом спрашивает у
// хранилища глагол типа; близнец без флага — общее умолчание, как прежде.
// Отличие близнецов — один флаг.
func TestCheck_RelationByModuleVerbAsksTheModuleVerb(t *testing.T) {
	src := catalog.Fixed{F: moduleVerbFacts(t)}
	req := CheckRequest{
		Subject:  domain.SpeakerAnonymous,
		Resource: ResourceRef{Type: "registry_repository", ID: "reg00000000000000001/app"},
		Action:   "registry.repositories.get",
	}
	for _, tc := range []struct {
		name     string
		byVerb   bool
		wantRel  string
		wantCall int
	}{
		{"анонимная самопроверка — глагол модуля", true, "v_get", 1},
		{"вопрос без флага — умолчание, как прежде", false, "viewer", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rel := &mockRelations{checkResp: true}
			svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: rel, Catalog: src})
			r := req
			r.RelationByModuleVerb = tc.byVerb
			res, err := svc.Check(context.Background(), r)
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if !res.Allowed || rel.checkCalls != tc.wantCall || rel.lastRelation != tc.wantRel {
				t.Fatalf("allowed=%v вопросов=%d отношение=%q; want allowed, %d вопрос, %q",
					res.Allowed, rel.checkCalls, rel.lastRelation, tc.wantCall, tc.wantRel)
			}
		})
	}
}

// TestCheck_RelationByModuleVerbWithoutAVerbIsARefusal — глагола в каталоге нет
// (или каталога нет вовсе): вопроса к хранилищу об объекте нет, ответ — отказ
// без причин (аноним, SC-10), а не подстановка `viewer`.
func TestCheck_RelationByModuleVerbWithoutAVerbIsARefusal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		src    catalog.Source
		action string
	}{
		{"глагол без отношения у типа", catalog.Fixed{F: moduleVerbFacts(t)}, "registry.repositories.update"},
		{"действие о другом ресурсе", catalog.Fixed{F: moduleVerbFacts(t)}, "registry.registries.get"},
		{"каталог не провязан", nil, "registry.repositories.get"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			rel := &mockRelations{checkResp: true}
			svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: rel, Catalog: tc.src})
			res, err := svc.Check(context.Background(), CheckRequest{
				Subject:              domain.SpeakerAnonymous,
				Resource:             ResourceRef{Type: "registry_repository", ID: "reg00000000000000001/app"},
				Action:               tc.action,
				RelationByModuleVerb: true,
			})
			if err != nil {
				t.Fatalf("err: %v", err)
			}
			if res.Allowed || rel.checkCalls != 0 || len(res.DenyReasons) != 0 {
				t.Fatalf("allowed=%v вопросов=%d причины=%v; want отказ, 0 вопросов, причин нет",
					res.Allowed, rel.checkCalls, res.DenyReasons)
			}
		})
	}
}

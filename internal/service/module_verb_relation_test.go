// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package service

// module_verb_relation_test.go — вывод отношения вопроса без отношения по
// каталогу модуля (kaname#994, kaname#995). Настоящий решатель утверждает исход в
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
// Модуль vpc ключуется в единственном числе (`vpc.network`), а действие приходит
// токеном права во множественном (`vpc.networks.get`): так расходятся словари
// на настоящих манифестах (kaname#995).
func moduleVerbFacts(t *testing.T) *catalog.Facts {
	t.Helper()
	f, err := catalog.NewFacts(catalog.Halves{Live: catalog.Rows{
		Modules: []string{"billing", "registry", "vpc"},
		Resources: []catalog.ResourceRow{
			{Module: "billing", Resource: "invoice", ObjectType: "billing_invoice"},
			{Module: "registry", Resource: "registries", ObjectType: "registry_registry"},
			{Module: "registry", Resource: "repositories", ObjectType: "registry_repository"},
			{Module: "vpc", Resource: "network", ObjectType: "vpc_network"},
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
			{Module: "vpc", Resource: "network", Verb: "get", PerObject: true},
			{Module: "vpc", Resource: "network", Verb: "list", PerObject: true},
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
		{"ключ каталога в единственном числе", "vpc.network.get", "vpc_network", "v_get"},
		{"токен права во множественном числе — судится модулем", "vpc.networks.get", "vpc_network", "v_get"},
		{"токен права, глагол без отношения у типа", "vpc.networks.delete", "vpc_network", ""},
		{"токен права чужого модуля", "compute.networks.get", "vpc_network", ""},
		{"токен права модуля, не объявляющего тип", "billing.networks.get", "vpc_network", ""},
		{"модуль вне каталога", "compute.instances.get", "compute_instance", ""},
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

// TestCheck_ActionOnlyAsksTheModuleVerbForEveryCaller — вопрос без отношения
// спрашивает у хранилища глагол типа у ВСЕХ вызывающих — анонима, человека,
// служебной учётки (kaname#994, kaname#995); близнец с явным отношением
// спрашивает его дословно. Отличие близнецов — одно поле `RequiredRelation`.
func TestCheck_ActionOnlyAsksTheModuleVerbForEveryCaller(t *testing.T) {
	src := catalog.Fixed{F: moduleVerbFacts(t)}
	for _, subject := range []string{domain.SpeakerAnonymous, "user:usr00000000000000001", "service_account:sva00000000000000001"} {
		for _, tc := range []struct {
			name, action, required, wantRel string
		}{
			{"get без отношения — глагол модуля", "registry.repositories.get", "", "v_get"},
			{"list без отношения — свой глагол, не ярус", "registry.repositories.list", "", "v_list"},
			{"явное отношение — дословно", "registry.repositories.list", "viewer", "viewer"},
		} {
			t.Run(subject+"/"+tc.name, func(t *testing.T) {
				rel := &mockRelations{checkResp: true}
				svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: rel, Catalog: src})
				res, err := svc.Check(context.Background(), CheckRequest{
					Subject:          subject,
					Resource:         ResourceRef{Type: "registry_repository", ID: "reg00000000000000001/app"},
					Action:           tc.action,
					RequiredRelation: tc.required,
				})
				if err != nil {
					t.Fatalf("err: %v", err)
				}
				if !res.Allowed || rel.checkCalls != 1 || rel.lastRelation != tc.wantRel {
					t.Fatalf("allowed=%v вопросов=%d отношение=%q; want allowed, 1 вопрос, %q",
						res.Allowed, rel.checkCalls, rel.lastRelation, tc.wantRel)
				}
			})
		}
	}
}

// TestCheck_ActionOnlyWithoutAVerbIsARefusal — глагола в каталоге нет (или
// каталога нет вовсе): вопроса к хранилищу об объекте нет, ответ — отказ, а не
// подстановка яруса. Аноним причин не получает (SC-10); вошедшему отказ назван.
func TestCheck_ActionOnlyWithoutAVerbIsARefusal(t *testing.T) {
	for _, tc := range []struct {
		name   string
		src    catalog.Source
		action string
	}{
		{"глагол без отношения у типа", catalog.Fixed{F: moduleVerbFacts(t)}, "registry.repositories.update"},
		{"действие о другом ресурсе", catalog.Fixed{F: moduleVerbFacts(t)}, "registry.registries.get"},
		{"каталог не провязан", nil, "registry.repositories.get"},
	} {
		for _, subject := range []string{domain.SpeakerAnonymous, "user:usr00000000000000001"} {
			t.Run(tc.name+"/"+subject, func(t *testing.T) {
				rel := &mockRelations{checkResp: true}
				svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: rel, Catalog: tc.src})
				res, err := svc.Check(context.Background(), CheckRequest{
					Subject:  subject,
					Resource: ResourceRef{Type: "registry_repository", ID: "reg00000000000000001/app"},
					Action:   tc.action,
				})
				if err != nil {
					t.Fatalf("err: %v", err)
				}
				if res.Allowed || rel.checkCalls != 0 {
					t.Fatalf("allowed=%v вопросов=%d; want отказ, 0 вопросов", res.Allowed, rel.checkCalls)
				}
				if anon := subject == domain.SpeakerAnonymous; anon != (len(res.DenyReasons) == 0) {
					t.Fatalf("причины отказа %v у %s: анониму — ни одной, вошедшему — названы", res.DenyReasons, subject)
				}
			})
		}
	}
}

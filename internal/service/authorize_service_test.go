// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authorize_service_test.go — unit tests for AuthorizeService.
package service

import (
	"context"
	"errors"
	"strings"
	"sync"
	"testing"

	iamerr "github.com/PRO-Robotech/kacho-iam/internal/errors"
)

// mockRelations — minimal Authorizer for unit tests.
//
// ПОВЕРХНОСТЬ СУЗИЛАСЬ ВМЕСТЕ С ПОРТОМ. Дублёр отвечал на вопросы чужого
// хранилища кортежей: перечисление объектов, разворот графа, чтение кортежей
// фильтром. Ни одного из них у решающей стороны больше нет — остались четыре
// вопроса, которые задают РЕШЕНИЮ: вердикт, кто держит отношение, из чего право
// складывается и какие отношения субъект уже держит на объекте.
//
// Дублёр обязан отвечать РОВНО на них: лишний метод здесь означал бы, что проба
// держит поверхность, которой у настоящего нет, и снятие следующего метода порта
// прошло бы мимо неё молча.
//
// The counters and captures are mutex-guarded because BatchCheck resolves its
// items concurrently: a fixture that is only safe for a sequential caller cannot
// stand in for a store the production code calls from several goroutines, and
// under -race it reports the FIXTURE's unsafety as if it were the subject's.
// Recording sites take the lock; tests read the fields after the call under test
// has returned, which is ordered by that return, so no read site needs changing.
//
// Deliberately NOT extended to scClusterChecker (authorize_shortcircuit_test.go):
// its counter is serialised by clusterAdminMemo's single-flight, so leaving it
// unguarded makes -race the detector for that single-flight being lost — a
// regression that would otherwise only show up as a quiet extra super-gate
// question per item.
type mockRelations struct {
	mu sync.Mutex

	checkResp    bool
	checkErr     error
	checkCalls   int
	subjectsResp []string
	subjectsNext string
	subjectsErr  error
	sourcesResp  []string
	sourcesErr   error
	// directResp — отношения, которые субъект УЖЕ держит на объекте; из них
	// собирается хвост текста отказа. Прежде на этот вопрос отвечало чтение
	// кортежей у движка; читатель и единица те же, источник другой.
	directResp []string
	directErr  error
	// lastCondCtx — captures the condition-context the last Check passed to the
	// relation store, so a test can assert the server sanitised it (no forged
	// principal/connection attributes; server-forced current_time / trusted acr).
	lastCondCtx map[string]any
}

func (m *mockRelations) CheckWithContext(ctx context.Context, subject, relation, object string, condCtx map[string]any) (bool, error) {
	m.mu.Lock()
	m.checkCalls++
	m.lastCondCtx = condCtx
	m.mu.Unlock()
	return m.checkResp, m.checkErr
}
func (m *mockRelations) ListSubjects(ctx context.Context, objectType, objectID, relation string, pageSize int, pageToken string) ([]string, string, error) {
	return m.subjectsResp, m.subjectsNext, m.subjectsErr
}
func (m *mockRelations) Sources(ctx context.Context, objectType, objectID, relation string) ([]string, error) {
	return m.sourcesResp, m.sourcesErr
}
func (m *mockRelations) DirectRelations(ctx context.Context, subject, objectType, objectID string, limit int) ([]string, error) {
	return m.directResp, m.directErr
}

// Здесь стояло ещё одно утверждение — что ответ эхом возвращает идентификатор
// версии модели прав. Утверждать его нечем и не о чем: версия принадлежала
// внешнему движку, и снято всё — поле контракта, поле результата и настройка, из
// которой значение бралось. Закреплять пробой то, чего никто не пишет и не
// читает, значило бы приколотить мёртвое поле.
func TestAuthorize_Check_AllowsWhenTheRelationStoreAllows(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkResp: true},
	})
	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_alice",
		Resource: ResourceRef{Type: "vpc_network", ID: "vpcn_x"},
		Action:   "vpc.networks.list",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("expected allowed; deny=%v", res.DenyReasons)
	}
}

// TestAuthorize_Check_DeniesNoPath — caller has NO direct relations
// on the object → deny_reason states subject lacks the needed relation +
// reports "no direct relations granted". (Previously a flat "no path" string;
// rich-deny format ships in item-4 / KAC-WhoAmI.)
func TestAuthorize_Check_DeniesNoPath(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkResp: false /* no directResp -> no relations */},
	})
	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_bob",
		Resource: ResourceRef{Type: "vpc_network", ID: "vpcn_y"},
		Action:   "vpc.networks.delete",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Allowed {
		t.Fatalf("expected denied")
	}
	if len(res.DenyReasons) == 0 {
		t.Fatalf("expected at least one deny_reason; got empty")
	}
	got := res.DenyReasons[0]
	// Rich format must include subject, target relation, object, action,
	// and the "no direct relations granted" tail.
	for _, want := range []string{
		"user:usr_bob",
		"admin", // vpc.networks.delete -> admin
		"vpc_network:vpcn_y",
		"vpc.networks.delete",
		"no direct relations granted",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("deny_reason missing %q; got %q", want, got)
		}
	}
}

// TestAuthorize_Check_RichDenyIncludesCurrentRelations — caller has `viewer`
// but needs `admin` (delete verb). Rich deny_reason must enumerate the
// existing relations so the UI can surface "you have viewer; need admin".
func TestAuthorize_Check_RichDenyIncludesCurrentRelations(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{
			checkResp: false,
			// Отношения, которые субъект уже держит на объекте. Дедупликация —
			// свойство ОТВЕЧАЮЩЕЙ стороны (`DirectRelations` отдаёт множество
			// имён), поэтому дублировать их здесь нечего: прежняя редакция
			// подавала два одинаковых кортежа и проверяла, что переходник их
			// схлопнет, — переходника больше нет.
			directResp: []string{"viewer", "member"},
		},
	})
	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_alice",
		Resource: ResourceRef{Type: "vpc_network", ID: "vpcn_x"},
		Action:   "vpc.networks.delete",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Allowed {
		t.Fatalf("expected denied")
	}
	got := res.DenyReasons[0]
	for _, want := range []string{
		"user:usr_alice",
		`lacks relation "admin"`,
		"vpc_network:vpcn_x",
		"vpc.networks.delete",
		"current direct relations:",
		"viewer",
		"member",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("deny_reason missing %q; got %q", want, got)
		}
	}
	// "no direct relations granted" MUST NOT appear when relations exist.
	if strings.Contains(got, "no direct relations granted") {
		t.Errorf("unexpected fallback tail in rich deny: %q", got)
	}
}

// TestAuthorize_Check_RichDenyDirectRelationsFailureFallsBackCleanly — когда
// вопрос «а что у субъекта уже есть» не отвечен, отказ остаётся отказом, а хвост
// текста сваливается на "no direct relations granted".
//
// Это ДИАГНОСТИКА, и она не вправе испортить ответ: решение уже принято. Прежде
// на этот вопрос отвечало чтение кортежей у внешнего движка, теперь — своя
// таблица; свойство от смены источника не изменилось, и именно поэтому проба
// осталась, сменив только то, чей отказ она подставляет.
func TestAuthorize_Check_RichDenyDirectRelationsFailureFallsBackCleanly(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{
			checkResp: false,
			directErr: errors.New("read timeout"),
		},
	})
	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_charlie",
		Resource: ResourceRef{Type: "account", ID: "acc_xyz"},
		Action:   "iam.accounts.update",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Allowed {
		t.Fatalf("expected denied")
	}
	got := res.DenyReasons[0]
	if !strings.Contains(got, "no direct relations granted") {
		t.Errorf("expected fallback tail; got %q", got)
	}
}

// TestAuthorize_CheckRelation_RichDenyAlso — gateway / internal path
// (CheckRelation) also returns rich deny_reasons (no action segment).
func TestAuthorize_CheckRelation_RichDenyAlso(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{
			checkResp:  false,
			directResp: []string{"viewer"},
		},
	})
	res, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject:  "user:usr_dave",
		Relation: "system_admin",
		Object:   "cluster:cluster_kacho_root",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Allowed {
		t.Fatalf("expected denied")
	}
	got := res.DenyReasons[0]
	for _, want := range []string{
		"user:usr_dave",
		`lacks relation "system_admin"`,
		"cluster:cluster_kacho_root",
		"current direct relations:",
		"viewer",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("deny_reason missing %q; got %q", want, got)
		}
	}
	// No action available on CheckRelation — action segment must NOT appear.
	if strings.Contains(got, "(action") {
		t.Errorf("unexpected action segment in CheckRelation deny: %q", got)
	}
}

func TestAuthorize_Check_InvalidArgumentMissingSubject(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{},
	})
	_, err := svc.Check(context.Background(), CheckRequest{
		Resource: ResourceRef{Type: "x", ID: "y"},
		Action:   "x.x.x",
	})
	if err == nil || !strings.HasPrefix(err.Error(), "Illegal argument") {
		t.Errorf("expected Illegal argument; got %v", err)
	}
}

func TestAuthorize_BatchCheck_PerItemFailureDoesNotAbort(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkResp: true},
	})
	results, err := svc.BatchCheck(context.Background(), []CheckRequest{
		{Subject: "user:usr_alice", Resource: ResourceRef{Type: "x", ID: "1"}, Action: "x.x.list"},
		{Subject: "", Resource: ResourceRef{Type: "x", ID: "2"}, Action: "x.x.list"}, // bad
		{Subject: "user:usr_carol", Resource: ResourceRef{Type: "x", ID: "3"}, Action: "x.x.list"},
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if len(results) != 3 {
		t.Fatalf("expected 3 results; got %d", len(results))
	}
	if !results[0].Allowed {
		t.Errorf("expected idx0 allowed")
	}
	if results[1].Allowed {
		t.Errorf("expected idx1 denied (bad subject)")
	}
	if !results[2].Allowed {
		t.Errorf("expected idx2 allowed")
	}
}

// TestAuthorize_BatchCheck_UnavailableFailsWholeBatchNoLeak — «спросить не
// удалось» НЕ схлопывается в пообъектный отказ.
//
// Схлопывание стоило бы двух разных вещей сразу: (а) текст отказа хранилища
// уезжает на поверхность, которую видит арендатор, (б) временная недоступность
// подаётся как ПОСТОЯННЫЙ отказ, то есть 403 вместо повторяемого 503. Пачка
// обязана вести себя как одиночная проверка — упасть целиком с сигнальной
// ошибкой iamerr.ErrUnavailable.
//
// ФИКСТУРА ПЕРЕПИСАНА ПОД НЫНЕШНЮЮ ОТВЕЧАЮЩУЮ СТОРОНУ. Здесь стоял ответ
// HTTP-транспорта внешнего движка прав — адрес и идентификатор чужого хранилища.
// Такого текста не бывает: отвечает своя база, и утечка, которой этот файл
// стережёт, выглядит теперь как строка подключения pgx — узел, порт, учётка, имя
// базы (`security.md` §Hardening-инвариант 1 называет ровно её). Правдоподобная
// фикстура прячет дефект, который сама же и кормит, поэтому подставляется та
// форма, которую производит настоящий отказ.
func TestAuthorize_BatchCheck_UnavailableFailsWholeBatchNoLeak(t *testing.T) {
	const storeTransportLeak = "failed to connect to host=kacho-iam-pg.kacho.svc user=kacho_iam " +
		"database=kacho_iam: dial error (dial tcp 10.0.0.5:5432: connect: connection refused)"
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkErr: errors.New(storeTransportLeak)},
	})
	results, err := svc.BatchCheck(context.Background(), []CheckRequest{
		{Subject: "user:usr_alice", Resource: ResourceRef{Type: "x", ID: "1"}, Action: "x.x.list"},
	})
	if err == nil {
		t.Fatalf("ждали отказа ВСЕЙ пачки на недоступном хранилище; got results=%v err=nil", results)
	}
	if !errors.Is(err, iamerr.ErrUnavailable) {
		t.Errorf("expected ErrUnavailable sentinel (retryable, fail-closed); got %v", err)
	}
	if results != nil {
		t.Errorf("expected nil results on whole-batch failure; got %v", results)
	}
	for _, r := range results {
		for _, dr := range r.DenyReasons {
			if strings.Contains(dr, "kacho-iam-pg") || strings.Contains(dr, "10.0.0.5") {
				t.Errorf("УТЕЧКА: текст отказа несёт координаты хранилища: %q", dr)
			}
		}
	}
}

func TestAuthorize_BatchCheck_TooLarge(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkResp: true},
	})
	checks := make([]CheckRequest, 101)
	_, err := svc.BatchCheck(context.Background(), checks)
	if err == nil || !strings.Contains(err.Error(), "batch size") {
		t.Errorf("expected batch-too-large error; got %v", err)
	}
}

func TestAuthorize_RelationStoreUnavailable_ReturnsUnavailable(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkErr: errors.New("connection refused")},
	})
	_, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:x",
		Resource: ResourceRef{Type: "x", ID: "y"},
		Action:   "x.x.list",
	})
	if err == nil || !strings.Contains(err.Error(), "authz unavailable") {
		t.Errorf("expected authz unavailable; got %v", err)
	}
}

func TestResolveActionToRelation(t *testing.T) {
	cases := map[string]string{
		"vpc.networks.list":     "viewer",
		"vpc.networks.create":   "editor",
		"vpc.networks.delete":   "admin",
		"compute.instances.ssh": "ssh",
		"":                      "",
		"just-one-part":         "",
		// M2: an unknown/typo'd verb must NOT default to "viewer"
		// (over-permissive — a read-only subject already holds viewer, so a
		// typo'd MUTATING verb would be wrongly allowed). Unknown → "" (deny).
		"vpc.networks.frobnicate": "",
		"compute.instances.nuke":  "",
		// Regression guard (M2 verb-case bug): action verbs carry camelCase
		// (Get→get but ListByScope→listByScope), and the case labels are
		// lower-cased — the resolver must fold the verb to lower-case, else these
		// multi-word verbs miss every case and fall through to unknown→deny,
		// which broke AccessBindingService.ListByScope (403) in e2e.
		"iam.access_bindings_by_resources.listByScope": "viewer",
		"iam.access_bindings.listBySubject":            "viewer",
		"iam.authorize.batchCheck":                     "viewer",
		"vpc.subnets.addCidrBlocks":                    "editor",
		"vpc.subnets.removeCidrBlocks":                 "editor",
		// SAKey credential lifecycle — issuing/revoking SA OAuth keys. The
		// permission catalog gives required_relation=editor; when the relation
		// is not supplied the verb-fallback must map issue/revoke to editor
		// instead of unknown→deny (which 403'd SAKeyService.Issue in the
		// grant-check-propagation e2e — the verb-fold M2 follow-up added the
		// multi-word read verbs but missed these credential-mutation verbs).
		"iam.issue_s_a_keies.issue":   "editor",
		"iam.revoke_s_a_keies.revoke": "editor",
	}
	for in, want := range cases {
		got := resolveActionToRelation(in)
		if got != want {
			t.Errorf("resolveActionToRelation(%q) = %q; want %q", in, got, want)
		}
	}
}

// TestAuthorize_Check_UnknownVerb_DeniesEvenForViewerSubject — M2: a subject
// the relation store would happily allow at `viewer` (checkResp:true) must STILL
// be denied for an unknown verb, because the verb does not resolve to a known
// relation. Fail-closed: an unrecognised (possibly mutating) action is never
// silently downgraded to the viewer relation.
func TestAuthorize_Check_UnknownVerb_DeniesEvenForViewerSubject(t *testing.T) {
	mock := &mockRelations{checkResp: true} // the relation store would ALLOW viewer
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: mock})
	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_readonly",
		Resource: ResourceRef{Type: "vpc_network", ID: "vpcn_x"},
		Action:   "vpc.networks.frobnicate", // unknown verb
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Allowed {
		t.Fatalf("expected DENIED for unknown verb (over-permissive viewer mapping); got allowed")
	}
	if mock.checkCalls != 0 {
		t.Errorf("unknown verb must short-circuit BEFORE the per-object question; got %d calls", mock.checkCalls)
	}
	if len(res.DenyReasons) == 0 {
		t.Fatalf("expected a deny_reason explaining the unresolved action")
	}
}

// TestAuthorize_Check_KnownMutatingVerb_StillMaps — guard: the fix must NOT
// break the known-verb CRUD mappings (delete → admin).
func TestAuthorize_Check_KnownMutatingVerb_StillMaps(t *testing.T) {
	mock := &mockRelations{checkResp: true}
	svc := NewAuthorizeService(AuthorizeServiceConfig{Relations: mock})
	res, err := svc.Check(context.Background(), CheckRequest{
		Subject:  "user:usr_admin",
		Resource: ResourceRef{Type: "vpc_network", ID: "vpcn_x"},
		Action:   "vpc.networks.delete", // known mutating verb -> admin
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("known mutating verb must still resolve and allow; deny=%v", res.DenyReasons)
	}
	if mock.checkCalls != 1 {
		t.Errorf("known verb must reach the per-object question exactly once; got %d", mock.checkCalls)
	}
}

// ── CheckRelation — relation-native gate ─────────────────────────────────

func TestAuthorize_CheckRelation_AllowsWhenTheRelationStoreAllows(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkResp: true},
	})
	res, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject:  "user:usr_alice",
		Relation: "viewer",
		Object:   "vpc_network:enp_x",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if !res.Allowed {
		t.Fatalf("expected allowed; deny=%v", res.DenyReasons)
	}
}

func TestAuthorize_CheckRelation_DeniesNoPath(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkResp: false /* no directResp -> rich-deny falls back */},
	})
	res, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject:  "user:usr_bob",
		Relation: "editor",
		Object:   "vpc_network:enp_y",
	})
	if err != nil {
		t.Fatalf("err: %v", err)
	}
	if res.Allowed {
		t.Fatalf("expected deny")
	}
	if len(res.DenyReasons) != 1 {
		t.Fatalf("expected single deny_reason; got %v", res.DenyReasons)
	}
	got := res.DenyReasons[0]
	// Rich-deny format: subject + relation + object + fallback tail.
	for _, want := range []string{
		"user:usr_bob",
		`lacks relation "editor"`,
		"vpc_network:enp_y",
		"no direct relations granted",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("deny_reason missing %q; got %q", want, got)
		}
	}
}

func TestAuthorize_CheckRelation_RejectsMissingFields(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkResp: true},
	})
	cases := []CheckRelationRequest{
		{Relation: "viewer", Object: "vpc_network:e"},
		{Subject: "user:u", Object: "vpc_network:e"},
		{Subject: "user:u", Relation: "viewer"},
	}
	for i, req := range cases {
		_, err := svc.CheckRelation(context.Background(), req)
		if err == nil || !strings.HasPrefix(err.Error(), "Illegal argument") {
			t.Errorf("case %d: expected Illegal argument err; got %v", i, err)
		}
	}
}

func TestAuthorize_CheckRelation_UnavailableWhenNoRelationStore(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{})
	_, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject: "user:u", Relation: "viewer", Object: "vpc_network:e",
	})
	// Backend-unavailable is now carried by the typed iamerr.ErrUnavailable
	// sentinel (handlers classify via errors.Is, not an error-text prefix); the
	// client-facing text still reads "authz unavailable".
	if err == nil || !errors.Is(err, iamerr.ErrUnavailable) {
		t.Errorf("expected ErrUnavailable-wrapped err; got %v", err)
	}
	if !strings.Contains(err.Error(), "authz unavailable") {
		t.Errorf("expected message to mention authz unavailable; got %v", err)
	}
}

func TestAuthorize_CheckRelation_StoreErrorIsUnavailable(t *testing.T) {
	svc := NewAuthorizeService(AuthorizeServiceConfig{
		Relations: &mockRelations{checkErr: errors.New("openfga check: status 503")},
	})
	_, err := svc.CheckRelation(context.Background(), CheckRelationRequest{
		Subject: "user:u", Relation: "viewer", Object: "vpc_network:e",
	})
	if err == nil || !errors.Is(err, iamerr.ErrUnavailable) {
		t.Errorf("expected ErrUnavailable-wrapped err; got %v", err)
	}
	if !strings.Contains(err.Error(), "authz unavailable") {
		t.Errorf("expected message to mention authz unavailable; got %v", err)
	}
}

// BatchCheckWithContext — ПАКЕТНАЯ ДВЕРЬ К ТОМУ ЖЕ ОРАКУЛУ, из которого отвечает
// пообъектная. Своего ответа у неё нет намеренно: дублёр, отвечающий партии не
// то, что отвечает по одному, скрыл бы ровно то расхождение, ради которого он и
// подставляется.
func (m *mockRelations) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	out := make([]bool, len(objects))
	for i, object := range objects {
		allowed, err := m.CheckWithContext(ctx, subject, relation, object, condCtx)
		if err != nil {
			return nil, err
		}
		out[i] = allowed
	}
	return out, nil
}

// DirectRelationsMany — та же диагностика о странице, тем же оракулом.
func (m *mockRelations) DirectRelationsMany(ctx context.Context, subject, objectType string,
	objectIDs []string, limit int) (map[string][]string, error) {
	out := make(map[string][]string, len(objectIDs))
	for _, objectID := range objectIDs {
		rels, err := m.DirectRelations(ctx, subject, objectType, objectID, limit)
		if err != nil {
			return nil, err
		}
		if len(rels) > 0 {
			out[objectID] = rels
		}
	}
	return out, nil
}

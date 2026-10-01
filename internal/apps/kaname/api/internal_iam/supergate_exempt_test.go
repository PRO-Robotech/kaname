// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package internal_iam

// supergate_exempt_test.go — NTF1-F12 (а), (б): надзор администратора облака не
// решает исход внутренней двери на типах ленты уведомлений.
//
// Место — Д-3 `verdictForRelation` переписи §1.11 приёмки NTF-1: через
// `InternalIAMService/Check` идут перехватчик прав каждой службы kacho и сервер
// ленты источника (`Claim`, `Ack`). Обработчик зовётся настоящий, дверь под ним —
// настоящая `service.AuthorizeService`; дублёр стоит только на месте хранилища
// отношений и отвечает ровно посеянными фактами.
//
// Близнец по субъекту (`service:probe` / `service:notify` с посеянным кортежем)
// отличает «перечень снял надзор» от «дверь отказывает всем». Близнец по типу
// (`iam_user:<U2>` с `token_issuer`, которое администратору даёт только надзор)
// отличает «перечень снял надзор» от «надзор сломан везде».

import (
	"context"
	"sync"
	"testing"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/service"
)

const (
	exemptAdmin    = "user:usr0000000000000ca01"
	exemptTwinUser = "usr0000000000000u201"
	probeSvc       = "service:probe"
	notifySvc      = "service:notify"
	superGateRel   = "system_admin"
)

// relationFacts — хранилище отношений, отвечающее посеянными фактами.
type relationFacts struct {
	facts map[string]bool

	mu        sync.Mutex
	superAsks int
}

func newRelationFacts() *relationFacts {
	return &relationFacts{facts: map[string]bool{
		exemptAdmin + "|" + superGateRel + "|cluster:cluster_root": true,
		probeSvc + "|sender|notification_namespace:probe":          true,
		notifySvc + "|reader|notification_feed:probe":              true,
	}}
}

func (f *relationFacts) answer(subject, relation, object string) bool {
	if relation == superGateRel {
		f.mu.Lock()
		f.superAsks++
		f.mu.Unlock()
	}
	return f.facts[subject+"|"+relation+"|"+object]
}

func (f *relationFacts) asks() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.superAsks
}

func (f *relationFacts) Check(_ context.Context, subject, relation, object string) (bool, error) {
	return f.answer(subject, relation, object), nil
}

func (f *relationFacts) CheckWithContext(_ context.Context, subject, relation, object string, _ map[string]any) (bool, error) {
	return f.answer(subject, relation, object), nil
}

func (f *relationFacts) BatchCheckWithContext(_ context.Context, subject, relation string, objects []string,
	_ map[string]any) ([]bool, error) {
	out := make([]bool, len(objects))
	for i, o := range objects {
		out[i] = f.answer(subject, relation, o)
	}
	return out, nil
}

func (f *relationFacts) ListSubjects(context.Context, string, string, string, int, string) ([]string, string, error) {
	return nil, "", nil
}

func (f *relationFacts) Sources(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func (f *relationFacts) DirectRelations(context.Context, string, string, string, int) ([]string, error) {
	return nil, nil
}

func (f *relationFacts) DirectRelationsMany(context.Context, string, string, []string, int) (map[string][]string, error) {
	return nil, nil
}

func internalCheck(t *testing.T, h *Handler, subject, relation, object string) *iamv1.CheckResponse {
	t.Helper()
	resp, err := h.Check(context.Background(), &iamv1.CheckRequest{
		SubjectId: subject,
		Relation:  relation,
		Object:    object,
	})
	if err != nil {
		t.Fatalf("InternalIAMService/Check {%s %s %s}: %v", subject, relation, object, err)
	}
	return resp
}

// TestSuperGateExempt_InternalCheck_NotificationTypes — (а) `sender` на
// `notification_namespace:probe`, (б) `reader` на `notification_feed:probe`.
func TestSuperGateExempt_InternalCheck_NotificationTypes(t *testing.T) {
	for _, tc := range []struct {
		name, relation, object, twinSubject string
	}{
		{name: "(а) sender на notification_namespace", relation: "sender",
			object: "notification_namespace:probe", twinSubject: probeSvc},
		{name: "(б) reader на notification_feed", relation: "reader",
			object: "notification_feed:probe", twinSubject: notifySvc},
	} {
		t.Run(tc.name, func(t *testing.T) {
			facts := newRelationFacts()
			h := newCheckHandler(service.NewAuthorizeService(service.AuthorizeServiceConfig{
				Relations:           facts,
				ClusterAdminChecker: facts,
			}))

			resp := internalCheck(t, h, exemptAdmin, tc.relation, tc.object)
			if resp.GetAllowed() {
				t.Fatalf("%s: разрешено администратору облака без кортежа — надзор решил исход на типе перечня", tc.name)
			}
			if resp.GetReason() == "" {
				t.Fatalf("%s: отказ без причины", tc.name)
			}
			if n := facts.asks(); n != 0 {
				t.Fatalf("%s: надзор спрошен %d раз — на типе перечня он не спрашивается", tc.name, n)
			}

			if twin := internalCheck(t, h, tc.twinSubject, tc.relation, tc.object); !twin.GetAllowed() {
				t.Fatalf("%s, близнец по субъекту %s: отказ %q — дверь обязана отвечать моделью", tc.name, tc.twinSubject, twin.GetReason())
			}
			twinType := internalCheck(t, h, exemptAdmin, "token_issuer", "iam_user:"+exemptTwinUser)
			if !twinType.GetAllowed() {
				t.Fatalf("%s, близнец по типу iam_user:<U2>: отказ %q — надзор вне перечня обязан остаться в силе", tc.name, twinType.GetReason())
			}
		})
	}
}

// TestSuperGateExempt_InternalCheck_TypeIsTheModelsParse — CX1-05 (б): тип
// судится тем разбором, что кормит модель (первое двоеточие), а не строкой
// ресурса. Объект `notification_feed:x:probe` модель читает как тип
// `notification_feed` с идентификатором `x:probe`.
func TestSuperGateExempt_InternalCheck_TypeIsTheModelsParse(t *testing.T) {
	facts := newRelationFacts()
	h := newCheckHandler(service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           facts,
		ClusterAdminChecker: facts,
	}))
	if resp := internalCheck(t, h, exemptAdmin, "reader", "notification_feed:x:probe"); resp.GetAllowed() {
		t.Fatal("объект с двоеточием в идентификаторе прошёл надзором: тип судится не тем разбором, что у модели")
	}
}

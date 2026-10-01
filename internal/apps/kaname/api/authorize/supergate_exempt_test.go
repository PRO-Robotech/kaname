// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authorize

// supergate_exempt_test.go — NTF1-F12 (в)–(е): надзор администратора облака на
// типах ленты уведомлений не срабатывает ни в одном месте публичной двери.
//
// # Предмет
//
// Места Д-1 (`check`, ветка «вопроса нет»), Д-2 (`verdict`), Д-4 (`resolveRun`,
// прогон «вопроса нет») и Д-5 (`resolveRun`, пообъектный отказ) переписи §1.11
// приёмки NTF-1. Каждое достигается своим входом обработчика — `Check` либо
// `BatchCheck` — а дверь под ним настоящая (`service.AuthorizeService`). Дублёр
// стоит только на месте хранилища отношений: он отвечает ровно теми фактами,
// которые посеяны, — как модель, в которой у `U_ca` кортежей на объектах типов
// Р5 нет.
//
// # Близнецы меняют ровно один факт
//
//   - по типу — объект `iam_user:<U2>` с `token_issuer`: модель определяет это
//     отношение как `subject` без ветви администратора, поэтому `U_ca` его даёт
//     ТОЛЬКО надзор. «Да» на близнеце означает: надзор жив вне перечня, и «нет»
//     на типе перечня дал не сломанный надзор, а перечень;
//   - по субъекту — `service:notify` (`reader`) с посеянным кортежем: «да»
//     означает, что дверь отвечает моделью, а не отказывает всем подряд.
//
// # Смешанная партия (УК5, УК27)
//
// Прогон надзора в `BatchCheck` сводится по ключу «субъект · причина» без типа
// объекта. Пункты `notification_feed/*` и `iam_user/*` одного субъекта с одной
// причиной («объект не адресуем») попали бы в ОДИН прогон и получили бы один
// ответ. Пункт типа перечня обязан выйти из плана отказом раньше, чем прогон
// соберётся.

import (
	"context"
	"strings"
	"sync"
	"testing"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/service"
)

const (
	// exemptAdminID — администратор облака `U_ca`: держит `system_admin` на
	// синглтоне кластера и ничего больше.
	exemptAdminID = "usr0000000000000ca01"
	// exemptTwinUserID — `U2`, на чей объект `iam_user` спрашивает близнец по типу.
	exemptTwinUserID = "usr0000000000000u201"

	exemptAdmin  = "user:" + exemptAdminID
	notifySvc    = "service:notify"
	feedReader   = "reader"
	tokenIssuer  = "token_issuer"
	feedType     = "notification_feed"
	iamUserType  = "iam_user"
	feedProbe    = "probe"
	feedProbeC   = "probe-c"
	readAction   = "notify.feeds.get"
	unknownVerb  = "notify.feeds.frobnicate"
	superGateRel = "system_admin"
)

// exemptWorld — хранилище отношений, отвечающее посеянными фактами и ничем
// больше. Факт — «субъект|отношение|объект».
//
// Считает вопросы надзора (`system_admin` о синглтоне кластера), чтобы проба
// могла утверждать «надзор не спрошен», а не только «ответ — нет».
type exemptWorld struct {
	facts map[string]bool

	mu        sync.Mutex
	superAsks int
}

func newExemptWorld() *exemptWorld {
	return &exemptWorld{facts: map[string]bool{
		exemptAdmin + "|" + superGateRel + "|cluster:cluster_root":      true,
		notifySvc + "|" + feedReader + "|" + feedType + ":" + feedProbe: true,
	}}
}

func (w *exemptWorld) answer(subject, relation, object string) bool {
	if relation == superGateRel {
		w.mu.Lock()
		w.superAsks++
		w.mu.Unlock()
	}
	return w.facts[subject+"|"+relation+"|"+object]
}

func (w *exemptWorld) superGateAsks() int {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.superAsks
}

func (w *exemptWorld) Check(_ context.Context, subject, relation, object string) (bool, error) {
	return w.answer(subject, relation, object), nil
}

func (w *exemptWorld) CheckWithContext(_ context.Context, subject, relation, object string, _ map[string]any) (bool, error) {
	return w.answer(subject, relation, object), nil
}

func (w *exemptWorld) BatchCheckWithContext(_ context.Context, subject, relation string, objects []string,
	_ map[string]any) ([]bool, error) {
	out := make([]bool, len(objects))
	for i, o := range objects {
		out[i] = w.answer(subject, relation, o)
	}
	return out, nil
}

func (w *exemptWorld) ListSubjects(context.Context, string, string, string, int, string) ([]string, string, error) {
	return nil, "", nil
}

func (w *exemptWorld) Sources(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func (w *exemptWorld) DirectRelations(context.Context, string, string, string, int) ([]string, error) {
	return nil, nil
}

func (w *exemptWorld) DirectRelationsMany(context.Context, string, string, []string, int) (map[string][]string, error) {
	return nil, nil
}

// newExemptHandler — обработчик над НАСТОЯЩЕЙ дверью: надзор, вопрос об объекте
// и право задать вопрос отвечает один и тот же мир.
func newExemptHandler(w *exemptWorld) *Handler {
	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations:           w,
		ClusterAdminChecker: w,
	})
	return NewHandler(svc, NewWhoAmIUseCase(nil, nil)).WithCallerAuthority(w)
}

func checkItem(subject, typ, id, action, relation string) *iamv1.AuthorizeCheckRequest {
	return &iamv1.AuthorizeCheckRequest{
		Subject:          subject,
		Resource:         &iamv1.ResourceRef{Type: typ, Id: id},
		Action:           action,
		RequiredRelation: relation,
	}
}

func adminCtx() context.Context { return userCtx(exemptAdminID) }

// singleCheck — один публичный `Check` от `U_ca`.
func singleCheck(t *testing.T, h *Handler, item *iamv1.AuthorizeCheckRequest) *iamv1.AuthorizeCheckResponse {
	t.Helper()
	resp, err := h.Check(adminCtx(), item)
	if err != nil {
		t.Fatalf("Check %s %s/%s: %v", item.GetSubject(), item.GetResource().GetType(), item.GetResource().GetId(), err)
	}
	return resp
}

func requireRefusedWithReason(t *testing.T, label string, allowed bool, reasons []string) {
	t.Helper()
	if allowed {
		t.Fatalf("%s: разрешено — надзор администратора облака решил исход на типе перечня", label)
	}
	if len(reasons) != 1 || strings.TrimSpace(reasons[0]) == "" {
		t.Fatalf("%s: отказ без причины: %q", label, reasons)
	}
}

// TestSuperGateExempt_PublicCheck_NoQuestionByWildcard — (г): Д-1, ветка
// «вопроса нет» по идентификатору `*`.
func TestSuperGateExempt_PublicCheck_NoQuestionByWildcard(t *testing.T) {
	w := newExemptWorld()
	h := newExemptHandler(w)

	resp := singleCheck(t, h, checkItem(exemptAdmin, feedType, "*", readAction, feedReader))
	requireRefusedWithReason(t, "(г) notification_feed/*", resp.GetAllowed(), resp.GetDenyReasons())
	if n := w.superGateAsks(); n != 0 {
		t.Fatalf("(г): надзор спрошен %d раз на типе перечня — должен не спрашиваться вовсе", n)
	}

	twin := singleCheck(t, h, checkItem(exemptAdmin, iamUserType, "*", readAction, tokenIssuer))
	if !twin.GetAllowed() {
		t.Fatalf("(г) близнец по типу iam_user/*: отказ %q — надзор вне перечня обязан остаться в силе", twin.GetDenyReasons())
	}
}

// TestSuperGateExempt_PublicCheck_NoQuestionByAction — (д): Д-1, ветка «вопроса
// нет» по действию, не разрешающемуся в отношение.
func TestSuperGateExempt_PublicCheck_NoQuestionByAction(t *testing.T) {
	w := newExemptWorld()
	h := newExemptHandler(w)

	resp := singleCheck(t, h, checkItem(exemptAdmin, feedType, feedProbe, unknownVerb, ""))
	requireRefusedWithReason(t, "(д) notification_feed/probe", resp.GetAllowed(), resp.GetDenyReasons())
	if n := w.superGateAsks(); n != 0 {
		t.Fatalf("(д): надзор спрошен %d раз на типе перечня", n)
	}

	twin := singleCheck(t, h, checkItem(exemptAdmin, iamUserType, exemptTwinUserID, unknownVerb, ""))
	if !twin.GetAllowed() {
		t.Fatalf("(д) близнец по типу iam_user/<U2>: отказ %q", twin.GetDenyReasons())
	}
}

// TestSuperGateExempt_PublicCheck_ModelRefusal — (е): Д-2 `verdict`, надзор на
// отказе модели.
func TestSuperGateExempt_PublicCheck_ModelRefusal(t *testing.T) {
	w := newExemptWorld()
	h := newExemptHandler(w)

	resp := singleCheck(t, h, checkItem(exemptAdmin, feedType, feedProbe, readAction, feedReader))
	requireRefusedWithReason(t, "(е) notification_feed/probe", resp.GetAllowed(), resp.GetDenyReasons())
	if n := w.superGateAsks(); n != 0 {
		t.Fatalf("(е): надзор спрошен %d раз на типе перечня", n)
	}

	twinType := singleCheck(t, h, checkItem(exemptAdmin, iamUserType, exemptTwinUserID, readAction, tokenIssuer))
	if !twinType.GetAllowed() {
		t.Fatalf("(е) близнец по типу iam_user/<U2>: отказ %q", twinType.GetDenyReasons())
	}
	// Вопрос о чужом субъекте задаёт тот же U_ca: право ЗАДАТЬ вопрос у него
	// есть (authorizeCaller), ответ даёт дверь.
	twinSubject := singleCheck(t, h, checkItem(notifySvc, feedType, feedProbe, readAction, feedReader))
	if !twinSubject.GetAllowed() {
		t.Fatalf("(е) близнец по субъекту service:notify: отказ %q — дверь обязана отвечать моделью", twinSubject.GetDenyReasons())
	}
}

// TestSuperGateExempt_BatchCheck_ObjectRefusalAndNoQuestionRun — (в): Д-5
// (пообъектный отказ) и Д-4 (прогон «вопроса нет»).
func TestSuperGateExempt_BatchCheck_ObjectRefusalAndNoQuestionRun(t *testing.T) {
	w := newExemptWorld()
	h := newExemptHandler(w)

	resp, err := h.BatchCheck(adminCtx(), &iamv1.BatchAuthorizeCheckRequest{Checks: []*iamv1.AuthorizeCheckRequest{
		checkItem(exemptAdmin, feedType, feedProbe, readAction, feedReader),
		checkItem(exemptAdmin, feedType, feedProbeC, readAction, feedReader),
		checkItem(exemptAdmin, feedType, "*", readAction, feedReader),
	}})
	if err != nil {
		t.Fatalf("BatchCheck: %v", err)
	}
	if len(resp.GetResponses()) != 3 {
		t.Fatalf("ответов %d, ожидалось 3", len(resp.GetResponses()))
	}
	for i, label := range []string{"probe (Д-5)", "probe-c (Д-5)", "* (Д-4)"} {
		r := resp.GetResponses()[i]
		requireRefusedWithReason(t, "(в) notification_feed/"+label, r.GetAllowed(), r.GetDenyReasons())
	}
	if n := w.superGateAsks(); n != 0 {
		t.Fatalf("(в): надзор спрошен %d раз на партии из одних типов перечня", n)
	}

	twin, err := h.BatchCheck(adminCtx(), &iamv1.BatchAuthorizeCheckRequest{Checks: []*iamv1.AuthorizeCheckRequest{
		checkItem(exemptAdmin, iamUserType, exemptTwinUserID, readAction, tokenIssuer),
		checkItem(exemptAdmin, iamUserType, "*", readAction, tokenIssuer),
		checkItem(notifySvc, feedType, feedProbe, readAction, feedReader),
	}})
	if err != nil {
		t.Fatalf("BatchCheck близнецов: %v", err)
	}
	for i, label := range []string{"по типу iam_user/<U2> (Д-5)", "по типу iam_user/* (Д-4)", "по субъекту service:notify"} {
		if r := twin.GetResponses()[i]; !r.GetAllowed() {
			t.Fatalf("(в) близнец %s: отказ %q", label, r.GetDenyReasons())
		}
	}
}

// TestSuperGateExempt_BatchCheck_MixedNoQuestionItemsAreDecidedPerItem — УК5,
// УК27: смешанная партия `notification_feed/*` и `iam_user/*` одного субъекта
// даёт `false` и `true` — в обоих порядках, потому что прогон надзора берёт
// первый пункт за представителя.
func TestSuperGateExempt_BatchCheck_MixedNoQuestionItemsAreDecidedPerItem(t *testing.T) {
	for _, tc := range []struct {
		name  string
		items []*iamv1.AuthorizeCheckRequest
		want  []bool
	}{
		{
			name: "лента первой",
			items: []*iamv1.AuthorizeCheckRequest{
				checkItem(exemptAdmin, feedType, "*", readAction, feedReader),
				checkItem(exemptAdmin, iamUserType, "*", readAction, tokenIssuer),
			},
			want: []bool{false, true},
		},
		{
			name: "iam_user первым",
			items: []*iamv1.AuthorizeCheckRequest{
				checkItem(exemptAdmin, iamUserType, "*", readAction, tokenIssuer),
				checkItem(exemptAdmin, feedType, "*", readAction, feedReader),
			},
			want: []bool{true, false},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newExemptHandler(newExemptWorld())
			resp, err := h.BatchCheck(adminCtx(), &iamv1.BatchAuthorizeCheckRequest{Checks: tc.items})
			if err != nil {
				t.Fatalf("BatchCheck: %v", err)
			}
			got := make([]bool, len(resp.GetResponses()))
			for i, r := range resp.GetResponses() {
				got[i] = r.GetAllowed()
			}
			if len(got) != len(tc.want) || got[0] != tc.want[0] || got[1] != tc.want[1] {
				t.Fatalf("исходы партии %v, ожидалось %v — пункты разных типов решены одним прогоном надзора", got, tc.want)
			}
		})
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard_test

// own_door_batch_question_test.go — вопрос о правах, заданный НАЗВАННЫМ
// вызывающим, дверь не судит по объекту.
//
// # Предмет
//
// `AuthorizeService.{Check,BatchCheck}` — RPC, которыми у модели СПРАШИВАЮТ, а
// не действуют. Решает их ОДИН гейт обработчика (`api/authorize/caller_authority.go`),
// и он полон: безымянный проходит только проверенным сертификатом модуля,
// названный арендатор — про себя, про объект, которым администрирует, либо
// будучи администратором кластера. Второго рубежа им не нужно.
//
// Поправка звена снимала дверь ТОЛЬКО с безымянного вызывающего, а её godoc
// объявлял основание: «личности арендатора в их исходящем контексте нет by
// construction». Для `Check` это ничего не меняет — контракт объявляет его
// `scope_filtered`, и звено выходит до вопроса об объекте. Для `BatchCheck`
// меняет всё: он объявляет `required_relation: viewer` и
// `scope_extractor{project, scope_id}`, поэтому названный вызывающий доходит до
// вопроса об объекте.
//
// # Основание поправки НЕВЕРНО, и это измерено
//
// Сужатель списочной выдачи зовёт сосед под личностью ИНИЦИАТОРА:
// `pkg/listnarrow/client.go` передаёт `auth.PropagateOutgoing(ctx)`, а тот
// дописывает принципала в исходящие метаданные, когда он непуст. На пути
// «арендатор перечисляет адреса» принципал непуст всегда — значит вызывающий
// НАЗВАН, поправка не применяется, и дверь спрашивает об объекте.
//
// Объекта у этого вопроса нет: `scope_id` контракт объявляет НЕОБЯЗАТЕЛЬНЫМ
// («When set, the gateway gates the entire batch on this scope's permission
// instead of per-item»), и в этом дереве его не заполняет НИ ОДИН вызывающий.
// Пустой идентификатор объекта звено отвергает `FormatObject` — до вопроса к
// модели, то есть и до плоского надзора администратора облака, который живёт
// внутри `checkAdapter.Check`. Отказ наступает раньше любого решения.
//
// # Что наблюдалось
//
// Сквозные пробы, голова `d1c7a4a89b`: `list filter: AuthorizeService.BatchCheck
// PermissionDenied: permission denied` → код 14 → HTTP 503. В шарде vpc этим
// объясняются ВСЕ 123 отказа (118 прямых + 5 каскадом), в шарде iam — ещё 4.
// Предмет один, а шарда два: перечисление страницы ломается у всякого соседа,
// который сужает выдачу.
//
// # Инъекция в обе стороны
//
// Отрицание идёт в паре с законным близнецом: тот же названный вызывающий на
// подлинно пообъектном RPC без выдачи обязан остаться отвергнутым. Без него
// «названный прошёл» зеленело бы и на двери, снятой со всего подряд.

import (
	"testing"

	"google.golang.org/grpc"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)

// batchQuestion — RPC сужателя списочной выдачи.
const batchQuestion = "/kaname.cloud.iam.v1.AuthorizeService/BatchCheck"

// pageQuestion — вопрос о странице, какой задаёт сужатель: элементы про
// ЧУЖИЕ объекты, `scope_id` не заполнен (его не заполняет ни один вызывающий).
func pageQuestion(subject string) *iamv1.BatchAuthorizeCheckRequest {
	return &iamv1.BatchAuthorizeCheckRequest{
		Checks: []*iamv1.AuthorizeCheckRequest{
			{Subject: subject, Resource: &iamv1.ResourceRef{Type: "vpc_address", Id: "adr00000000000000001"}},
			{Subject: subject, Resource: &iamv1.ResourceRef{Type: "vpc_address", Id: "adr00000000000000002"}},
		},
	}
}

// ОТРИЦАНИЕ (RED до починки): названный арендатор задаёт вопрос о странице и
// доходит до обработчика.
func TestOwnDoor_NamedCallerAsksTheBatchQuestionAndReachesTheHandler(t *testing.T) {
	store := &grantStore{allow: map[string]bool{}}
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(ownerUser),
		pageQuestion("user:"+ownerUser),
		&grpc.UnaryServerInfo{FullMethod: batchQuestion},
		reached(&hit),
	)
	if err != nil || !hit {
		t.Fatalf("вопрос о странице отвергнут дверью: err=%v, обработчик достигнут=%v.\n"+
			"  спрошено у модели: %v\n"+
			"  `scope_id` контракт объявляет НЕОБЯЗАТЕЛЬНЫМ и не заполняет ни один вызывающий,\n"+
			"  поэтому вопрос об объекте отвергается пустым идентификатором — до модели и до надзора;\n"+
			"  сужение страницы у КАЖДОГО соседа становится отказом 503",
			err, hit, store.asked)
	}
	// Объём спрошенного: дверь не задаёт вопроса об объекте вовсе. Без этой
	// проверки «прошёл» было бы неотличимо от «прошёл, потому что выдача нашлась».
	if len(store.asked) != 0 {
		t.Fatalf("дверь спросила модель о вопросе, который решает обработчик: %v", store.asked)
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ: тот же названный вызывающий на подлинно пообъектном RPC без
// выдачи остаётся отвергнутым.
//
// Молчит и до починки, и после. Без него отрицание выше зеленело бы на двери,
// снятой со всего подряд, — то есть починка была бы неотличима от снятия двери.
func TestOwnDoor_NamedCallerStaysRefusedOnAnObjectScopedRpc(t *testing.T) {
	store := &grantStore{allow: map[string]bool{}}
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(strangerUser),
		&iamv1.DeleteProjectRequest{ProjectId: victimProject},
		&grpc.UnaryServerInfo{FullMethod: "/kaname.cloud.iam.v1.ProjectService/Delete"},
		reached(&hit),
	)
	if hit || err == nil {
		t.Fatalf("посторонний удаляет чужой проект: обработчик достигнут=%v, err=%v.\n"+
			"  спрошено у модели: %v", hit, err, store.asked)
	}
}

// ПАРИТЕТ БЛИЗНЕЦОВ: у двух RPC одного вопроса поведение двери совпадает.
//
// `Check` проходил названного вызывающего и до починки — но не поправкой звена,
// а тем, что контракт объявляет его `scope_filtered`. `BatchCheck` такого
// объявления не несёт, и различие двух братьев никем не решалось: оно возникло
// побочным следствием того, что аннотация писалась под КРАЙ. Проба судит
// РАЗНИЦУ, а не каждого по отдельности, — «решал ли кто-нибудь, что они
// различаются» есть вопрос, на который ответ существует всегда.
func TestOwnDoor_BothQuestionRpcsTreatANamedCallerAlike(t *testing.T) {
	cases := []struct {
		method string
		req    any
	}{
		{"/kaname.cloud.iam.v1.AuthorizeService/Check",
			&iamv1.AuthorizeCheckRequest{Subject: "user:" + ownerUser}},
		{batchQuestion, pageQuestion("user:" + ownerUser)},
	}
	for _, c := range cases {
		store := &grantStore{allow: map[string]bool{}}
		hit := false
		_, err := doorUnder(t, store)(
			tenantCtx(ownerUser),
			c.req,
			&grpc.UnaryServerInfo{FullMethod: c.method},
			reached(&hit),
		)
		if err != nil || !hit {
			t.Errorf("%s: названный вызывающий не задал вопрос о правах: err=%v достигнут=%v",
				c.method, err, hit)
		}
	}
	t.Logf("осмотрено RPC вопроса: %d", len(cases))
}

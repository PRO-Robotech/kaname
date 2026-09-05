// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard_test

// own_door_peer_question_test.go — ВОПРОС О ПРАВАХ задаёт не арендатор, и
// личности арендатора у него нет by construction.
//
// # Предмет
//
// `AuthorizeService.{Check,BatchCheck}` — RPC, которыми у модели СПРАШИВАЮТ
// («можно ли субъекту S сделать A с объектом O»), а не действуют. Субъект стоит
// В ЗАПРОСЕ, вызывающий — модуль: край на пути каждого запроса
// (`gateway/internal/clients/iam_authorize_client.go`) и сужатель списочной
// выдачи у соседей (`pkg/listnarrow/client.go`). Личности арендатора в их
// исходящем контексте нет: вопрос задаётся ДО решения о доступе и задаёт его не
// тот, о ком спрашивают.
//
// Кто вправе спрашивать, решает `api/authorize/caller_authority.go` — он
// называет себя единственным решателем этого вопроса и строго fail-closed:
// вызывающий без личности проходит ТОЛЬКО с проверенным сертификатом модуля.
//
// # Что проба ловит
//
// Дверь звена `pkg/authz` отвергает безымянного вызывающего РАНЬШЕ карты и
// раньше обработчика. Тогда край, задавая вопрос о правах, получает отказ на
// САМ ВОПРОС — и всякое решение о доступе на стенде становится отказом.
// Наблюдалось: пять шардов сквозных проб, у каждого 40+ записей
// `authz_no_principal` с `rpc=/kacho.cloud.iam.v1.AuthorizeService/Check`, при
// НУЛЕ таких записей на стволе.
//
// Отрицание идёт В ПАРЕ: послабление обязано покрывать РОВНО вопросы о правах,
// у которых есть производитель, — не службу целиком и не соседние RPC.

import (
	"context"
	"testing"

	"google.golang.org/grpc"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	"github.com/PRO-Robotech/kacho/pkg/authz/catalogderive"

	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
)

// ВОПРОС О ПРАВАХ ДОХОДИТ ДО ОБРАБОТЧИКА без личности арендатора.
func TestOwnDoor_AuthorizationQuestionWithoutTenantPrincipalReachesTheHandler(t *testing.T) {
	methods := authzguard.CallerAuthorityGatedMethods()
	if len(methods) == 0 {
		t.Fatal("освобождённых методов ноль: проба беспредметна — утверждать не о чем")
	}
	for _, method := range methods {
		store := &grantStore{allow: map[string]bool{}}
		hit := false
		_, err := doorUnder(t, store)(
			context.Background(), // край не пересылает личность арендатора на вопрос о правах
			&iamv1.AuthorizeCheckRequest{Subject: "user:" + ownerUser},
			&grpc.UnaryServerInfo{FullMethod: method},
			reached(&hit),
		)
		if err != nil {
			t.Errorf("%s: вопрос о правах отвергнут дверью: %v — тогда всякое решение о доступе на стенде есть отказ", method, err)
		}
		if !hit {
			t.Errorf("%s: обработчик не достигнут — решать, кто вправе спрашивать, некому", method)
		}
		if len(store.asked) != 0 {
			t.Errorf("%s: модель спрошена о безымянном вызывающем: %v", method, store.asked)
		}
	}
	t.Logf("осмотрено освобождённых методов: %d", len(methods))
}

// ПАРНОЕ ОТРИЦАНИЕ: послабление узкое.
//
// `ListSubjects` и `ExpandRelations` судит тот же гейт обработчика, но
// производителя вне iam у них в этом дереве нет — и записи им не заведено.
// Появится производитель — запись приедет вместе с ним, и эта строка
// перевернётся тем же изменением.
func TestOwnDoor_QuestionExemptionCoversNothingElse(t *testing.T) {
	cases := []struct {
		method string
		req    any
	}{
		{"/kacho.cloud.iam.v1.AuthorizeService/ListSubjects", &iamv1.ListSubjectsRequest{}},
		{"/kacho.cloud.iam.v1.AuthorizeService/ExpandRelations", &iamv1.ExpandRelationsRequest{}},
		{"/kacho.cloud.iam.v1.ProjectService/Get", &iamv1.GetProjectRequest{ProjectId: victimProject}},
		{"/kacho.cloud.iam.v1.ProjectService/Delete", &iamv1.DeleteProjectRequest{ProjectId: victimProject}},
	}
	for _, c := range cases {
		store := &grantStore{allow: map[string]bool{}}
		hit := false
		_, err := doorUnder(t, store)(
			context.Background(),
			c.req,
			&grpc.UnaryServerInfo{FullMethod: c.method},
			reached(&hit),
		)
		if hit || err == nil {
			t.Errorf("%s: безымянный вызывающий прошёл дверь — послабление шире своего предмета", c.method)
		}
	}
}

// КОНТРОЛЬ АРЕНДАТОРА: названный вызывающий по тем же RPC проходит как и прежде.
//
// Без него первая проба зеленела бы и на двери, пропускающей эти RPC всем и
// всегда по причине, к личности отношения не имеющей.
func TestOwnDoor_TenantAsksTheSameQuestionAndPasses(t *testing.T) {
	store := &grantStore{allow: map[string]bool{}}
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(ownerUser),
		&iamv1.AuthorizeCheckRequest{Subject: "user:" + ownerUser},
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.AuthorizeService/Check"},
		reached(&hit),
	)
	if err != nil || !hit {
		t.Fatalf("арендатор не задал вопрос о собственных правах: err=%v достигнут=%v", err, hit)
	}
}

// САМОИСТЕЧЕНИЕ: освобождение живёт, пока живёт его RPC.
//
// Запись, которой больше нечего освобождать, достаётся следующему, кого назовут
// этим именем. Поэтому каждый освобождённый метод обязан НАЙТИСЬ в карте,
// выведенной из аннотаций контракта, — той же, что читает дверь.
func TestOwnDoor_QuestionExemptionExpiresWithItsRpc(t *testing.T) {
	derived, err := catalogderive.Derive(authzguard.OwnDoorProtoPackages()...)
	if err != nil {
		t.Fatalf("карта не выводится: %v", err)
	}
	if len(derived) == 0 {
		t.Fatal("карта пуста: обход беспредметен, и «ноль потерянных записей» неотличимо от «ноль прочитанного»")
	}
	for _, method := range authzguard.CallerAuthorityGatedMethods() {
		if _, ok := derived[method]; !ok {
			t.Errorf("%s: освобождение пережило свой RPC — контракт метода не объявляет", method)
		}
	}
	t.Logf("перепись: методов в выведенной карте %d · освобождено %d",
		len(derived), len(authzguard.CallerAuthorityGatedMethods()))
}

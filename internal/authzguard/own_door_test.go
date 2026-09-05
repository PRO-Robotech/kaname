// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard_test

// own_door_test.go — предикат снятия полосы: у iam ЕСТЬ собственная дверь.
//
// Проба ставит iam в положение, в котором он окажется вынесенным: НАШЕГО КРАЯ
// НЕТ, запрос приходит прямо на публичный слушатель, вызывающий аутентифицирован
// и НИЧЕГО ему не выдано. Спрашивается ровно то, что увидит арендатор.
//
// Отрицание идёт В ПАРЕ с положительным близнецом: без него «отказано» было бы
// неотличимо от двери, которая отвергает всех, — и такая дверь прошла бы пробу,
// сломав продукт целиком.

import (
	"context"
	"strings"
	"testing"

	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"
	// Дверь выводит карту из дескрипторов, ВЛИНКОВАННЫХ в бинарь. Процесс iam
	// линкует все три пакета (grpc_register.go регистрирует их службы), поэтому
	// проба обязана линковать их тоже: иначе она судила бы карту, которой в
	// проде не бывает, и «не выводится» читалось бы как дефект двери.
	"github.com/PRO-Robotech/kacho-iam/internal/authzguard"
	_ "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	_ "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/quota/v1"
	"github.com/PRO-Robotech/kacho/pkg/operations"
)

// grantStore — модель прав пробы: разрешено ровно то, что перечислено.
//
// Ключ — «субъект|отношение|объект», то есть ровно тройка, которой спрашивает
// дверь. Ничего не перечислено — не разрешено ничего: умолчание здесь обязано
// быть отказом, иначе проба зеленела бы на незаполненной фикстуре.
type grantStore struct {
	allow map[string]bool
	asked []string
	err   error
}

func (g *grantStore) Check(_ context.Context, subject, relation, object string) (bool, error) {
	key := subject + "|" + relation + "|" + object
	g.asked = append(g.asked, key)
	if g.err != nil {
		return false, g.err
	}
	return g.allow[key], nil
}

// tenantCtx — контекст аутентифицированного арендатора-человека.
func tenantCtx(userID string) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: userID})
}

// doorUnder собирает дверь ровно так, как её обязан собрать композиционный
// корень: один конструктор на оба места, чтобы проба не проверяла ВТОРУЮ
// проводку, которой в проде нет.
func doorUnder(t *testing.T, store authzguard.RelationChecker) grpc.UnaryServerInterceptor {
	t.Helper()
	door, err := authzguard.NewOwnDoor(authzguard.OwnDoorOptions{SelfCheck: store})
	if err != nil {
		t.Fatalf("дверь не собралась: %v", err)
	}
	return door.Unary()
}

// reached отмечает, дошёл ли вызов до обработчика.
func reached(hit *bool) grpc.UnaryHandler {
	return func(ctx context.Context, req any) (any, error) {
		*hit = true
		return &iamv1.Project{}, nil
	}
}

const (
	victimProject = "prj00000000000000001"
	strangerUser  = "usr00000000000000009"
	ownerUser     = "usr00000000000000001"
)

// ОТРИЦАНИЕ: чужой проект аутентифицированному постороннему не отдаётся.
func TestOwnDoor_StrangerIsRefusedOnSomeoneElsesObject(t *testing.T) {
	store := &grantStore{allow: map[string]bool{}}
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(strangerUser),
		&iamv1.GetProjectRequest{ProjectId: victimProject},
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.ProjectService/Get"},
		reached(&hit),
	)
	if hit {
		t.Fatal("обработчик достигнут: дверь пропустила постороннего к чужому проекту — " +
			"именно это и происходит с вынесенным iam, у которого нашего края нет")
	}
	if err == nil {
		t.Fatal("отказа нет")
	}
	if len(store.asked) == 0 {
		t.Fatal("модель прав не спрошена ни разу: отказ вынесен не по объекту")
	}
	t.Logf("спрошено у модели: %v", store.asked)
}

// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: с выдачей — проходит.
//
// Без него отрицание выше зеленело бы на двери, отвергающей всех.
func TestOwnDoor_GrantedCallerPasses(t *testing.T) {
	store := &grantStore{allow: map[string]bool{
		"user:" + ownerUser + "|v_get|project:" + victimProject: true,
	}}
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(ownerUser),
		&iamv1.GetProjectRequest{ProjectId: victimProject},
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.ProjectService/Get"},
		reached(&hit),
	)
	if err != nil {
		t.Fatalf("выданному отказано: %v (спрошено: %v)", err, store.asked)
	}
	if !hit {
		t.Fatal("обработчик не достигнут при живой выдаче")
	}
}

// СКРЫТИЕ СУЩЕСТВОВАНИЯ: отказ по праву ПОБАЙТОВО равен промаху владельца.
//
// Различимый текст здесь есть оракул существования: по нему отличают «не твоё»
// от «нет такого», то есть ровно то, ради чего отказ и подменяется промахом.
func TestOwnDoor_DenyIsByteIdenticalToAGenuineMiss(t *testing.T) {
	store := &grantStore{allow: map[string]bool{}}
	door := doorUnder(t, store)

	// (1) объект СУЩЕСТВУЕТ, но не выдан — дверь отвечает, не доходя до данных.
	_, denyErr := door(
		tenantCtx(strangerUser),
		&iamv1.GetProjectRequest{ProjectId: victimProject},
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.ProjectService/Get"},
		reached(new(bool)),
	)
	// (2) настоящий промах владельца — тон контракта самого iam.
	missErr := status.Errorf(codes.NotFound, "Project %s not found", victimProject)

	dS, mS := status.Convert(denyErr), status.Convert(missErr)
	if dS.Code() != mS.Code() {
		t.Errorf("код отказа %v ≠ код промаха %v — вызывающий отличает их по коду",
			dS.Code(), mS.Code())
	}
	if dS.Message() != mS.Message() {
		t.Errorf("текст отказа не равен промаху ПОБАЙТОВО:\n  отказ:  %q\n  промах: %q",
			dS.Message(), mS.Message())
	}
	// Внутренний словарь модели наружу не выходит: имя типа объекта на публичной
	// поверхности не встречается, и его появление само стало бы приметой.
	if strings.Contains(dS.Message(), "project:") {
		t.Errorf("в отказе течёт имя типа модели: %q", dS.Message())
	}
}

// НЕДОСТУПНОСТЬ МОДЕЛИ — не «да». Неполученный ответ разрешением не является.
func TestOwnDoor_ModelOutageFailsClosed(t *testing.T) {
	store := &grantStore{allow: map[string]bool{}, err: context.DeadlineExceeded}
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(strangerUser),
		&iamv1.GetProjectRequest{ProjectId: victimProject},
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.ProjectService/Get"},
		reached(&hit),
	)
	if hit || err == nil {
		t.Fatal("модель не ответила, а вызов прошёл: неполученный ответ принят за разрешение")
	}
}

// МУТАЦИЯ тоже за дверью. Полоса чтения закрыта у iam и сегодня (AllowsVGet);
// открыта именно мутация — там, где цена ошибки необратима.
func TestOwnDoor_MutationIsBehindTheDoorToo(t *testing.T) {
	store := &grantStore{allow: map[string]bool{}}
	hit := false
	_, err := doorUnder(t, store)(
		tenantCtx(strangerUser),
		&iamv1.DeleteProjectRequest{ProjectId: victimProject},
		&grpc.UnaryServerInfo{FullMethod: "/kacho.cloud.iam.v1.ProjectService/Delete"},
		reached(&hit),
	)
	if hit || err == nil {
		t.Fatal("посторонний удаляет чужой проект: обработчик достигнут без выдачи")
	}
}

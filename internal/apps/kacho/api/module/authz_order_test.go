// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package module_test

// authz_order_test.go — `IAM-MA-1-38`: отказ по правам на КАЖДОМ из четырёх
// глаголов, и он приходит РАНЬШЕ разбора входа.
//
// # Что здесь утверждается наблюдаемо, а не по прочтении кода
//
// Порядок «гейт первым стейтментом» невидим в диффе: код, проверяющий право
// вторым, компилируется и выглядит так же. Наблюдаемая разница ровно одна —
// ответ на ЗАВЕДОМО НЕГОДНОМ входе: гейт впереди даёт `PERMISSION_DENIED`,
// гейт позади — `INVALID_ARGUMENT`, то есть отвечает на вопрос «годно ли имя
// модуля» тому, кому отвечать не полагается.
//
// # Положительный контроль обязателен
//
// Без него отрицание зеленело бы на реализации, отвергающей ВСЁ. Поэтому тот же
// вызывающий, но держащий право, обязан пройти гейт у всех четырёх глаголов —
// проверяется по тому, что отказ, если он и приходит, приходит НЕ по правам.
//
// # Почему у use-case'ов здесь пустые зависимости
//
// Гейт стоит до всякого обращения к базе и к доставке, поэтому непровязанные
// порты на полосе отказа не разыменовываются. Регрессия, обошедшая гейт, упала
// бы здесь паникой либо чужим кодом — и то и другое проба показывает отказом.

import (
	"context"
	"errors"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/PRO-Robotech/kacho/pkg/operations"

	moduleapp "github.com/PRO-Robotech/kacho/services/iam/internal/apps/kacho/api/module"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// clusterSingleton — синглтон назван ОДИН раз на всё дерево; проба спрашивает
// его у того же объявления, что и продукт, а не выписывает строкой.
func clusterSingleton() string { return domain.ClusterSingletonID }

// fakeRelationChecker — authzguard.RelationChecker в памяти.
type fakeRelationChecker struct {
	allow bool
	err   error

	called   int
	subject  string
	relation string
	object   string
}

func (f *fakeRelationChecker) Check(_ context.Context, subject, relation, object string) (bool, error) {
	f.called++
	f.subject, f.relation, f.object = subject, relation, object
	return f.allow, f.err
}

const probeUser = "usr0000000000000000m"

func ctxAsUser(id string) context.Context {
	return operations.WithPrincipal(context.Background(),
		operations.Principal{Type: "user", ID: id})
}

// verbs — четыре глагола ОДНИМ перечнем: сценарий требует одного и того же от
// каждого, и перечисление их порознь позволило бы забыть один молча.
//
// Вход у всех ЗАВЕДОМО НЕГОДЕН (пустое имя модуля) — в этом весь предмет пробы.
func verbs(chk *fakeRelationChecker) map[string]func(ctx context.Context) error {
	return map[string]func(ctx context.Context) error{
		"Plan": func(ctx context.Context) error {
			_, err := moduleapp.NewPlanUseCase(nil, nil, nil).WithAdminChecker(chk).Execute(ctx, "")
			return err
		},
		"Apply": func(ctx context.Context) error {
			_, err := moduleapp.NewApplyUseCase(nil, nil, nil, nil).WithAdminChecker(chk).
				Execute(ctx, "", "", nil, nil)
			return err
		},
		"Get": func(ctx context.Context) error {
			_, err := moduleapp.NewGetUseCase(nil).WithAdminChecker(chk).Execute(ctx, "")
			return err
		},
		"List": func(ctx context.Context) error {
			_, err := moduleapp.NewListUseCase(nil).WithAdminChecker(chk).Execute(ctx)
			return err
		},
	}
}

func TestModuleVerbs_MA138_PermissionDeniedPrecedesInputParsing(t *testing.T) {
	chk := &fakeRelationChecker{allow: false}
	for name, call := range verbs(chk) {
		t.Run(name, func(t *testing.T) {
			err := call(ctxAsUser(probeUser))
			require.Equal(t, codes.PermissionDenied, status.Code(err),
				"%s: вызывающий без system_admin@cluster обязан получить отказ по правам", name)
			require.NotEqual(t, codes.InvalidArgument, status.Code(err),
				"%s: отказ формы на негодном входе означает, что право проверено ПОСЛЕ разбора — "+
					"то есть вызывающему ответили на вопрос о состоянии каталога", name)
		})
	}
	// Гейт обязан СПРОСИТЬ модель, а не решить сам: вопрос задан по каждому из
	// четырёх глаголов, и его предмет — тот же синглтон и то же отношение.
	require.Equal(t, 4, chk.called, "модель обязана быть спрошена каждым глаголом")
	require.Equal(t, "system_admin", chk.relation)
	require.Equal(t, "cluster:"+clusterSingleton(), chk.object)
	require.Equal(t, "user:"+probeUser, chk.subject)
}

func TestModuleVerbs_MA138_PositiveControl_GateIsPassedWhenGranted(t *testing.T) {
	chk := &fakeRelationChecker{allow: true}
	for name, call := range verbs(chk) {
		t.Run(name, func(t *testing.T) {
			err := call(ctxAsUser(probeUser))
			// Дальше гейта вызов упирается в непровязанные порты и негодный вход —
			// это ожидаемо и не предмет пробы. Предмет один: отказ БОЛЬШЕ НЕ по
			// правам. Без этого контроля отрицание выше зеленело бы на реализации,
			// отвергающей всё.
			require.NotEqual(t, codes.PermissionDenied, status.Code(err),
				"%s: вызывающий с system_admin@cluster обязан пройти гейт", name)
		})
	}
}

func TestModuleVerbs_MA138_AnonymousDeniedWithoutAskingTheModel(t *testing.T) {
	// Анонимный вызывающий не подставляется процессным актором: гейт отказывает
	// НЕ СПРАШИВАЯ модель — спрашивать не о ком.
	chk := &fakeRelationChecker{allow: true}
	for name, call := range verbs(chk) {
		t.Run(name, func(t *testing.T) {
			err := call(context.Background())
			require.Equal(t, codes.PermissionDenied, status.Code(err),
				"%s: анонимный вызывающий обязан получить отказ", name)
		})
	}
	require.Zero(t, chk.called, "неназываемая личность не есть вопрос к модели")
}

func TestModuleVerbs_MA138_UnwiredCheckerFailsClosed(t *testing.T) {
	// Непровязанный гейт — ОТКАЗ, а не разрешение: сборка, забывшая его
	// подключить, не имеет права поднять службу, отдающую применение каталога
	// кому угодно.
	cases := map[string]func(ctx context.Context) error{
		"Plan": func(ctx context.Context) error {
			_, err := moduleapp.NewPlanUseCase(nil, nil, nil).Execute(ctx, "vpc")
			return err
		},
		"Apply": func(ctx context.Context) error {
			_, err := moduleapp.NewApplyUseCase(nil, nil, nil, nil).Execute(ctx, "vpc", "state", nil, nil)
			return err
		},
		"Get": func(ctx context.Context) error {
			_, err := moduleapp.NewGetUseCase(nil).Execute(ctx, "vpc")
			return err
		},
		"List": func(ctx context.Context) error {
			_, err := moduleapp.NewListUseCase(nil).Execute(ctx)
			return err
		},
	}
	for name, call := range cases {
		t.Run(name, func(t *testing.T) {
			err := call(ctxAsUser(probeUser))
			require.Equal(t, codes.PermissionDenied, status.Code(err),
				"%s: непровязанный проверяющий обязан отказывать", name)
		})
	}
}

func TestModuleVerbs_MA138_UnreachableModelIsNotADenial(t *testing.T) {
	// Модель не ответила — это НЕ решение о правах: тот же вопрос минутой позже
	// получит ответ. Отдав здесь отказ в правах, служба показала бы
	// администратору отзыв там, где была неполадка хранилища.
	chk := &fakeRelationChecker{err: errors.New("relation store unreachable")}
	for name, call := range verbs(chk) {
		t.Run(name, func(t *testing.T) {
			err := call(ctxAsUser(probeUser))
			require.Equal(t, codes.Unavailable, status.Code(err),
				"%s: недоступность хранилища отношений обязана быть отличима от отказа", name)
		})
	}
}

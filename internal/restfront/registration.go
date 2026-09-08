// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package restfront

import (
	"context"
	"fmt"

	"github.com/grpc-ecosystem/grpc-gateway/v2/runtime"
	"google.golang.org/grpc"

	operationpb "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/operation"
	quotav1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/quota/v1"
	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kaname/cloud/iam/v1"
)

// registration.go — какие службы несёт каждый фронт.
//
// # Перечни ЗЕРКАЛЯТ слушатели, и это проверяется машиной
//
// Здесь два объявления, и оба — вторые: первым для каждого фронта служит
// перечень регистраций его gRPC-слушателя. Расхождение означает либо маршрут,
// которого нет (служба на слушателе, но не на фронте), либо отказ соединения
// вместо отказа по существу (наоборот). Молча разойтись им нечем: гейт
// требует равенства множеств в ОБЕ стороны по каждому фронту.
//
// # Регистрация НЕДЕЛИМА ПО МЕТОДАМ
//
// Порождённая форма поднимает привязки службы ЦЕЛИКОМ — части у неё нет. Отсюда
// два следствия, оба измерены и оба неочевидны:
//
//   - служба, стоящая на ОБОИХ слушателях, приносит свои публичные маршруты и
//     на внутренний фронт. Расширением внутренней поверхности это не является:
//     внутренний фронт не выставлен наружу, а запрет говорит об обратном
//     направлении — внутреннее не публикуется на внешнем;
//   - служба, у которой привязок ноль, регистрируется наравне с прочими. Её
//     регистрация не добавляет ни одного маршрута, а исключение её из перечня
//     завело бы ВТОРОЙ перечень — тот самый предмет, ради которого сверка и
//     существует.

// registerInternalRESTServices поднимает на внутреннем фронте службы
// внутреннего gRPC-слушателя.
//
// Идёт первой намеренно: её поверхность наружу не выставлена, поэтому ошибка
// здесь дешевле — на ней и отрабатывается форма.
func registerInternalRESTServices(
	ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption,
) error {
	registrations := []struct {
		service string
		bind    func(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error
	}{
		{"InternalUserService", iamv1.RegisterInternalUserServiceHandlerFromEndpoint},
		{"InternalIAMService", iamv1.RegisterInternalIAMServiceHandlerFromEndpoint},
		// AuthorizeService стоит и на публичном слушателе, и на внутреннем.
		// Оба фронта поднимают её привязки целиком — см. шапку.
		{"AuthorizeService", iamv1.RegisterAuthorizeServiceHandlerFromEndpoint},
		{"InternalClusterService", iamv1.RegisterInternalClusterServiceHandlerFromEndpoint},
		{"InternalInteractiveClientService", iamv1.RegisterInternalInteractiveClientServiceHandlerFromEndpoint},
		{"InternalModuleService", iamv1.RegisterInternalModuleServiceHandlerFromEndpoint},
		{"InternalLimitService", iamv1.RegisterInternalLimitServiceHandlerFromEndpoint},
		// Привязок ноль: маршрутов не добавляет, но в перечне стоит —
		// исключение завело бы второй перечень.
		{"InternalSessionRevocationsService", iamv1.RegisterInternalSessionRevocationsServiceHandlerFromEndpoint},
		{"InternalOperationsService", iamv1.RegisterInternalOperationsServiceHandlerFromEndpoint},
		// Привязок ноль — по той же причине, что и выше.
		{"InternalBootstrapTokenService", iamv1.RegisterInternalBootstrapTokenServiceHandlerFromEndpoint},
	}
	for _, r := range registrations {
		if err := r.bind(ctx, mux, endpoint, opts); err != nil {
			return fmt.Errorf("внутренний REST-фронт, служба %s: %w", r.service, err)
		}
	}
	return nil
}

// registerPublicRESTServices поднимает на публичном фронте службы публичного
// gRPC-слушателя.
//
// Ни одной службы `Internal*` здесь нет и быть не может: поверхность,
// побывавшая публичной, считается раскрытой — отката у такой ошибки нет.
// Держится это не вниманием, а гейтом дерева.
func registerPublicRESTServices(
	ctx context.Context, mux *runtime.ServeMux, endpoint string, opts []grpc.DialOption,
) error {
	registrations := []struct {
		service string
		bind    func(context.Context, *runtime.ServeMux, string, []grpc.DialOption) error
	}{
		// Операции. Без них асинхронный контракт отдельно поставленной службы
		// неисполним: мутации возвращают операцию, и опрос — единственный путь
		// клиента к её исходу. Клиент получал бы идентификатор, по которому
		// некуда обратиться.
		{"OperationService", operationpb.RegisterOperationServiceHandlerFromEndpoint},
		{"AccountService", iamv1.RegisterAccountServiceHandlerFromEndpoint},
		{"ProjectService", iamv1.RegisterProjectServiceHandlerFromEndpoint},
		{"IdentityQuotaService", quotav1.RegisterIdentityQuotaServiceHandlerFromEndpoint},
		{"UserService", iamv1.RegisterUserServiceHandlerFromEndpoint},
		{"ServiceAccountService", iamv1.RegisterServiceAccountServiceHandlerFromEndpoint},
		{"GroupService", iamv1.RegisterGroupServiceHandlerFromEndpoint},
		{"MembershipService", iamv1.RegisterMembershipServiceHandlerFromEndpoint},
		{"RoleService", iamv1.RegisterRoleServiceHandlerFromEndpoint},
		{"AccessBindingService", iamv1.RegisterAccessBindingServiceHandlerFromEndpoint},
		{"AuthorizeService", iamv1.RegisterAuthorizeServiceHandlerFromEndpoint},
		{"PermissionCatalogService", iamv1.RegisterPermissionCatalogServiceHandlerFromEndpoint},
		{"SAKeyService", iamv1.RegisterSAKeyServiceHandlerFromEndpoint},
		{"UserTokenService", iamv1.RegisterUserTokenServiceHandlerFromEndpoint},
		{"LimitService", iamv1.RegisterLimitServiceHandlerFromEndpoint},
	}
	for _, r := range registrations {
		if err := r.bind(ctx, mux, endpoint, opts); err != nil {
			return fmt.Errorf("публичный REST-фронт, служба %s: %w", r.service, err)
		}
	}
	return nil
}

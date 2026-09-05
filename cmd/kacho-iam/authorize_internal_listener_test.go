// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// authorize_internal_listener_test.go — AuthorizeService обязана быть достижима
// на ВНУТРЕННЕМ слушателе, а не только на публичном.
//
// ПРЕДМЕТ. Пообъектный фильтр страницы у потребителей (kacho-vpc / kacho-compute /
// kacho-nlb) идёт service→service: потребитель читает страницу курсором из СВОЕЙ
// базы и спрашивает у iam вердикт по идентификаторам ЭТОЙ страницы — партией. Ходит
// он по уже поднятому им ребру проверенного mTLS (:9091), тому самому, которое он
// держит ради InternalIAMService.Check. Если AuthorizeService зарегистрирована
// ТОЛЬКО на публичном слушателе (:9090), такой вызов получает codes.Unimplemented,
// фильтр отрабатывает fail-closed — и КАЖДЫЙ вызывающий видит пустой список при
// живых правах. Отдельного пути к вердикту у потребителя нет.
//
// ЧТО ИЗМЕНИЛОСЬ. Прежде эта проба вела предмет через ListObjects — «перечисли
// объекты, доступные субъекту». Этого RPC больше нет, и снят он не по недосмотру:
// перечисление у чужого хранилища имело жёсткий серверный предел и не имело
// продолжения, из-за чего объекты сверх предела становились владельцу невидимы
// НАВСЕГДА при живых правах (`security.md` §«страница → проверка страницы»).
// Фильтр давно спрашивает партией — BatchCheck, — и предмет пробы переехал на тот
// вызов, который его сегодня несёт. Утверждение то же: ребро существует.
//
// Это НЕ нарушение запрета #6. Запрет #6 запрещает `Internal.*` на ПУБЛИЧНОЙ
// поверхности; обратное — публичная служба, ДОПОЛНИТЕЛЬНО выставленная на
// кластер-внутреннем :9091 (не обращённом к арендатору), — и есть установленный
// приём для service→service.
//
// Проба чисто регистрационная (bufconn, ни базы, ни живого TLS): дублёр источника
// вердикта подставлен затем, чтобы маршрут доходил до настоящего use-case, а не
// падал на nil. Цепочка интерсепторов (CallerPolicy / SystemViewerFloor / ACRFloor)
// здесь НЕ исполняется — она собирается в serve.go и утверждается отдельно; здесь
// закрепляется РОВНО контракт регистрации.
package main

import (
	"context"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kacho/pkg/api/kacho/cloud/iam/v1"

	authorizeapp "github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/api/authorize"
	"github.com/PRO-Robotech/kacho-iam/internal/service"
)

// authzStubAuthorizer — минимальный service.Authorizer для регистрационной пробы.
//
// Отвечает детерминированно и без базы, чтобы Check / BatchCheck / ListSubjects
// доходили до настоящего use-case и утверждение оставалось ровно «маршрут есть»
// (НЕ Unimplemented), не спотыкаясь о nil.
//
// Дублёр не шире настоящего по ФОРМЕ ответа: он повторяет ту же поверхность, что
// сегодня реализует дверь решения над реляционной формой, и в ней «ошибки нет»
// означает, что вердикт действительно получен. Он снисходительнее по СОДЕРЖАНИЮ —
// отвечает «разрешено» кому угодно, — и это законно ровно потому, что предмет
// пробы не решение о доступе: кто вправе звать эти RPC, закрепляют
// api/authorize/caller_authority*_test.go и caller_policy_test.go.
type authzStubAuthorizer struct{}

func (authzStubAuthorizer) CheckWithContext(context.Context, string, string, string, map[string]any) (bool, error) {
	return true, nil
}

func (authzStubAuthorizer) ListSubjects(context.Context, string, string, string, int, string) ([]string, string, error) {
	return []string{"user:usr00000000000alice"}, "", nil
}

// Sources / DirectRelations читает ТОЛЬКО сборка текста отказа, а этот дублёр не
// отказывает никогда. Пустой ответ здесь — не заглушка «на всякий случай»: он
// означает «оснований назвать нечего», и по построению не вызывается.
func (authzStubAuthorizer) Sources(context.Context, string, string, string) ([]string, error) {
	return nil, nil
}

func (authzStubAuthorizer) DirectRelations(context.Context, string, string, string, int) ([]string, error) {
	return nil, nil
}

// newAuthorizeServicesForRegistration собирает *services с НАСТОЯЩИМ обработчиком
// AuthorizeService поверх дублёра источника вердикта (ни базы, ни внешних вызовов).
func newAuthorizeServicesForRegistration() *services {
	svc := service.NewAuthorizeService(service.AuthorizeServiceConfig{
		Relations: authzStubAuthorizer{},
	})
	// whoAmI обязателен сборщику обработчика; его зависимости здесь nil — WhoAmI
	// эта проба не исполняет.
	//
	// WithInsecureAnonymousPeer: харнесс — bufconn вовсе без TLS, поэтому вызов не
	// несёт ни личности арендатора, ни проверенного сертификата модуля, то есть
	// ровно то состояние, которое послабление описывает. Без него страж полномочий
	// вызывающего (справедливо) откажет ДО того, как маршрут будет исполнен, а
	// предмет этой пробы — МАРШРУТ.
	h := authorizeapp.NewHandler(svc, authorizeapp.NewWhoAmIUseCase(nil, nil)).
		WithInsecureAnonymousPeer(true)
	return &services{authorizeHandler: h}
}

// TestAuthorizeService_D_ReachableOnInternalListener — ребро пообъектного фильтра.
//
//	D-0 (близнец): та же связка БЕЗ обработчика → Unimplemented. Доказывает, что
//	               остальные утверждения способны упасть.
//	D-1 (предмет): BatchCheck достижим на ВНУТРЕННЕМ → НЕ Unimplemented и доходит
//	               до use-case. Это тот вызов, которым фильтр судит страницу.
//	D-2:           Check достижим на внутреннем (паритет с InternalIAMService.Check).
//	D-3:           ListSubjects достижим на внутреннем (обратный вопрос — кто держит
//	               отношение на объекте; страницей с курсором).
//	D-4:           AuthorizeService остаётся достижима и на ПУБЛИЧНОМ слушателе
//	               (регистрация аддитивна — обращённая к арендателю поверхность не
//	               сузилась).
func TestAuthorizeService_D_ReachableOnInternalListener(t *testing.T) {
	svcs := newAuthorizeServicesForRegistration()

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// ВНУТРЕННИЙ слушатель — то ребро, которое потребители (vpc/compute/nlb) уже
	// держат ради Check.
	intConn := serveBufconn(t, func(s *grpc.Server) {
		registerInternalServices(s, svcs, nil, "", nil)
	})
	intClient := iamv1.NewAuthorizeServiceClient(intConn)

	batch := &iamv1.BatchAuthorizeCheckRequest{
		Checks: []*iamv1.AuthorizeCheckRequest{{
			Subject:  "user:usr00000000000alice",
			Resource: &iamv1.ResourceRef{Type: "vpc_network", Id: "vpcn_a"},
			Action:   "vpc.networks.get",
		}, {
			Subject:  "user:usr00000000000alice",
			Resource: &iamv1.ResourceRef{Type: "vpc_network", Id: "vpcn_b"},
			Action:   "vpc.networks.get",
		}},
	}

	// D-1 — BatchCheck: тот самый вызов пообъектного фильтра страницы.
	resp, err := intClient.BatchCheck(ctx, batch)
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"D-1: BatchCheck ОБЯЗАН быть достижим на внутреннем слушателе (:9091) — иначе пообъектный "+
			"фильтр потребителя fail-closed отдаёт пустую страницу при живых правах")
	require.NoError(t, err, "D-1: маршрут дошёл до use-case")
	require.Len(t, resp.GetResponses(), len(batch.GetChecks()),
		"D-1: ответ обязан быть той же длины, что и партия, — переставленный или укороченный "+
			"вердикт отфильтровал бы страницу чужим ответом")

	// D-2 — Check: паритет с уже существующим ребром InternalIAMService.Check.
	_, err = intClient.Check(ctx, batch.GetChecks()[0])
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"D-2: Check ОБЯЗАН быть достижим на внутреннем слушателе (:9091)")
	require.NoError(t, err, "D-2: маршрут дошёл до use-case")

	// D-3 — ListSubjects: обратный вопрос, страницей с курсором.
	_, err = intClient.ListSubjects(ctx, &iamv1.ListSubjectsRequest{
		Resource: &iamv1.ResourceRef{Type: "vpc_network", Id: "vpcn_a"},
		Action:   "vpc.networks.get",
	})
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"D-3: ListSubjects ОБЯЗАН быть достижим на внутреннем слушателе (:9091)")
	require.NoError(t, err, "D-3: маршрут дошёл до use-case")

	// D-0 (законный близнец): та же связка, но обработчик не собран — маршрут
	// ОБЯЗАН отвечать Unimplemented.
	//
	// Без этого утверждения все четыре выше остаются вакуумными: `NotEqual(
	// Unimplemented)` зеленеет и на харнессе, который Unimplemented не производит
	// вовсе, а тогда проба не различает «служба зарегистрирована» и «проба ничего
	// не проверяет». Здесь воспроизводится ровно то состояние, ради которого
	// регистрация и заведена, — и на нём проба краснеет.
	bareConn := serveBufconn(t, func(s *grpc.Server) {
		registerInternalServices(s, &services{}, nil, "", nil)
	})
	_, err = iamv1.NewAuthorizeServiceClient(bareConn).BatchCheck(ctx, batch)
	require.Equal(t, codes.Unimplemented, status.Code(err),
		"D-0: предпосылка — этот харнесс ОТЛИЧАЕТ зарегистрированную службу от незарегистрированной; "+
			"иначе утверждения D-1..D-4 не могли бы упасть ни при какой провязке")

	// D-4 — ПУБЛИЧНЫЙ слушатель по-прежнему несёт AuthorizeService (аддитивно).
	pubConn := serveBufconn(t, func(s *grpc.Server) {
		registerPublicServices(s, svcs, nil)
	})
	pubClient := iamv1.NewAuthorizeServiceClient(pubConn)
	_, err = pubClient.BatchCheck(ctx, batch)
	require.NotEqual(t, codes.Unimplemented, status.Code(err),
		"D-4: AuthorizeService обязана оставаться достижимой и на публичном слушателе "+
			"(регистрация аддитивна — публичная поверхность не сузилась)")
	require.NoError(t, err, "D-4: публичный маршрут дошёл до use-case")
}

// BatchCheckWithContext — пакетная дверь к ТОМУ ЖЕ оракулу, из которого отвечает
// пообъектная: дублёр, отвечающий партии не то, что отвечает по одному, скрыл бы
// ровно то расхождение, ради которого он и подставляется.
func (a authzStubAuthorizer) BatchCheckWithContext(ctx context.Context, subject, relation string,
	objects []string, condCtx map[string]any) ([]bool, error) {
	out := make([]bool, len(objects))
	for i, object := range objects {
		allowed, err := a.CheckWithContext(ctx, subject, relation, object, condCtx)
		if err != nil {
			return nil, err
		}
		out[i] = allowed
	}
	return out, nil
}

// DirectRelationsMany — та же диагностика о странице, тем же оракулом.
func (a authzStubAuthorizer) DirectRelationsMany(ctx context.Context, subject, objectType string,
	objectIDs []string, limit int) (map[string][]string, error) {
	out := make(map[string][]string, len(objectIDs))
	for _, objectID := range objectIDs {
		rels, err := a.DirectRelations(ctx, subject, objectType, objectID, limit)
		if err != nil {
			return nil, err
		}
		if len(rels) > 0 {
			out[objectID] = rels
		}
	}
	return out, nil
}

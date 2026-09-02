// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package authzguard_test

// deny_next_step_test.go — отказ в правах называет СЛЕДУЮЩИЙ ШАГ, а не только
// сам факт отказа.
//
// ПРЕДМЕТ. Отказ существует затем, чтобы вызывающий построил следующий шаг.
// Голый отказ его не восстанавливает: администратор не знает, какое право
// запросить, и тем более — у кого. Дальше идёт обращение в поддержку, и это
// единственный путь.
//
// ГДЕ ЖИВЁТ СЛЕДУЮЩИЙ ШАГ И ПОЧЕМУ НЕ В ПРОЗЕ. Текст сообщения остаётся
// ДОСЛОВНО прежним — «permission denied», байт в байт на всех отказах, — потому
// что различимая проза на отказе есть оракул существования: по ней отличают
// «нет доступа» от «не существует». Шаг едет в ДЕТАЛЯХ, ровно той формой,
// которой уже едет требование повысить уровень аутентификации
// (`acr_floor.go`, `PreconditionFailure` типа `authz.step_up`). Форма взята
// оттуда, а не изобретена.
//
// ЧЕМ ЭТО БЕЗОПАСНО. Деталь — ЧИСТАЯ ФУНКЦИЯ ИМЕНИ МЕТОДА: ни запрос, ни
// идентификатор объекта, ни субъект в неё не входят. Значит отказ по
// существующему объекту и отказ по несуществующему остаются побайтово
// одинаковыми, и анти-оракульное свойство не тронуто. Это утверждается
// отдельно — `TestDenyNextStep_IsAFunctionOfTheMethodOnly`.

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"google.golang.org/genproto/googleapis/rpc/errdetails"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzguard"
)

// grantRequirement извлекает нарушение предусловия, называющее недостающую
// выдачу, — или nil.
func grantRequirement(st *status.Status) *errdetails.PreconditionFailure_Violation {
	for _, d := range st.Details() {
		pf, ok := d.(*errdetails.PreconditionFailure)
		if !ok {
			continue
		}
		for _, v := range pf.GetViolations() {
			if v.GetType() == "authz.grant_required" {
				return v
			}
		}
	}
	return nil
}

// TestDenyNextStep_NamesWhatIsMissingAndWhereToAskForIt — несущее утверждение.
func TestDenyNextStep_NamesWhatIsMissingAndWhereToAskForIt(t *testing.T) {
	reg := mustRegistry(t)

	// Метод с областью в каталоге: у него есть и право, и объект, на котором
	// это право выдают, — то есть оба ответа, которых отказу не хватало.
	const method = "/kacho.cloud.iam.v1.AccessBindingService/Get"

	st := denyThrough(t, reg, method)
	require.Equal(t, codes.PermissionDenied, st.Code())
	require.Equal(t, "permission denied", st.Message(),
		"проза отказа обязана остаться дословно прежней: различимый текст здесь есть оракул")

	v := grantRequirement(st)
	require.NotNil(t, v,
		"отказ не называет следующего шага — вызывающий не знает, какое право просить и у кого")

	entry, ok := reg.LookupFQN(strings.TrimPrefix(method, "/"))
	require.True(t, ok)

	assert.Contains(t, v.GetDescription(), entry.Permission,
		"следующий шаг обязан назвать НЕДОСТАЮЩЕЕ право именем каталога — тем самым, "+
			"которым его выдают")
	assert.Contains(t, v.GetDescription(), "ask an administrator",
		"следующий шаг обязан сказать, У КОГО просить, а не только чего не хватает")

	info := errorInfo(st)
	require.NotNil(t, info)
	assert.NotEmpty(t, info.GetMetadata()["scope"],
		"область обязана быть и машинно читаемой: разбор прозы вызывающему запрещён")
	assert.Equal(t, info.GetMetadata()["scope"], v.GetSubject(),
		"машинная и человеческая половины обязаны говорить об одном ярусе")
}

// TestDenyNextStep_NamesTheTierNotTheModelType — ГРАНИЦА словаря, и она
// перемерена, а не предположена.
//
// Тип объекта в записи каталога — ЦЕЛЬ проверки (`iam_access_binding`,
// `compute_instance`, `vpc_cidr_group`), а не область, у администратора которой
// просят выдачу. Отдав его дословно, отказ вернул бы арендатору словарь модели
// прав — того, чего в клиентских текстах ноль, — и вдобавок дал бы неверный
// совет. Первая редакция этого кода делала ровно так; проба закрепляет
// исправление.
func TestDenyNextStep_NamesTheTierNotTheModelType(t *testing.T) {
	reg := mustRegistry(t)

	allowedTiers := map[string]bool{"cluster": true, "account": true, "project": true, "resource": true}

	checked, resourceTier := 0, 0
	for _, e := range reg.All() {
		if !strings.HasPrefix(e.FQN, "kacho.cloud.iam.") ||
			e.Permission == "" || e.ScopeExtractor.ObjectType == "" {
			continue
		}
		st := denyThrough(t, reg, "/"+e.FQN)
		v := grantRequirement(st)
		require.NotNil(t, v, e.FQN)
		checked++

		require.True(t, allowedTiers[v.GetSubject()],
			"%s: ярус %q вне словаря продукта — похоже, отдан тип объекта модели прав",
			e.FQN, v.GetSubject())

		// Три яруса иерархии названы в каталоге теми же словами, что и в
		// продукте (`cluster` / `account` / `project`), — совпадение здесь
		// законно и утверждать «не равно» на них нельзя. Предмет запрета —
		// КОНКРЕТНЫЕ типы модели прав (`iam_access_binding`, `vpc_cidr_group`).
		if allowedTiers[e.ScopeExtractor.ObjectType] {
			continue
		}
		resourceTier++
		require.Equal(t, "resource", v.GetSubject(),
			"%s: наружу ушёл тип объекта модели прав дословно", e.FQN)
		require.NotContains(t, v.GetDescription(), e.ScopeExtractor.ObjectType,
			"%s: имя типа модели прав просочилось в совет", e.FQN)
	}
	require.NotZero(t, checked, "методов с областью прочитано 0 — вердикт беспредметен")
	t.Logf("перепись: методов с областью %d · из них по КОНКРЕТНОМУ типу модели прав %d "+
		"(все обязаны свестись к ярусу «resource»)", checked, resourceTier)
	require.NotZero(t, resourceTier,
		"ни одна запись не дала яруса «resource» — предпосылка перевода не проверена")
}

// TestDenyNextStep_IsAFunctionOfTheMethodOnly — ГРАНИЦА анти-оракула,
// утверждённая, а не обещанная.
//
// Отказ по существующему объекту и отказ по несуществующему обязаны быть
// ОДНИМ И ТЕМ ЖЕ сообщением. Проверяется тем, что ответ перехватчика не зависит
// ни от чего, кроме имени метода: два прохода с РАЗНЫМИ запросами дают равные
// статусы и дословно равную прозу.
//
// Сравнение идёт по РАЗОБРАННЫМ деталям, а не по байтам, и это не послабление,
// а исправление первой редакции пробы. Порядок пар в map-поле protobuf не
// определён: сериализация ОДНОГО И ТОГО ЖЕ сообщения различается от прогона к
// прогону, и упакованные байты внутри `Any` — тоже. Побайтовое равенство здесь
// мерило бы порядок обхода карты в Go, а не свойство продукта, и краснело бы на
// исправном коде.
//
// Требование `security.md` о ПОБАЙТОВОМ совпадении относится к тексту
// сообщения, и оно утверждается отдельной строкой ниже. Разнобой порядка ключей
// в карте оракулом не является by construction: он не зависит от запроса — а
// именно зависимость от запроса и делает отказ различимым.
func TestDenyNextStep_IsAFunctionOfTheMethodOnly(t *testing.T) {
	reg := mustRegistry(t)
	const method = "/kacho.cloud.iam.v1.AccessBindingService/Get"

	deny := func(req any) *status.Status {
		t.Helper()
		ic := authzguard.DenyDetailUnary(reg)
		_, err := ic(context.Background(), req,
			&grpc.UnaryServerInfo{FullMethod: method},
			func(context.Context, any) (any, error) { return nil, authzguard.PermissionDenied() })
		st, ok := status.FromError(err)
		require.True(t, ok)
		return st
	}

	existing := deny(map[string]string{"access_binding_id": "abd_exists"})
	absent := deny(map[string]string{"access_binding_id": "abd_does_not_exist_at_all"})

	require.Equal(t, existing.Code(), absent.Code())
	require.Equal(t, existing.Message(), absent.Message(),
		"проза отказа обязана совпадать дословно — она и есть та часть, которую читает человек")

	ed, ad := existing.Details(), absent.Details()
	require.Len(t, ad, len(ed), "число деталей отказа зависит от запроса")
	for i := range ed {
		em, ok := ed[i].(proto.Message)
		require.True(t, ok)
		am, ok := ad[i].(proto.Message)
		require.True(t, ok)
		require.True(t, proto.Equal(em, am),
			"деталь %d зависит от запроса — по ней можно отличить существующий объект от несуществующего", i)
	}
}

// TestDenyNextStep_CatalogMissStaysBare — положительный контроль в обратную
// сторону. Метод, которого каталог не знает, ОБЯЗАН остаться голым: пустое
// действие — это и есть способ, которым вызывающий узнаёт промах каталога, и
// выдуманный следующий шаг стёр бы различие, ради которого деталь заведена.
func TestDenyNextStep_CatalogMissStaysBare(t *testing.T) {
	reg := mustRegistry(t)
	st := denyThrough(t, reg, "/kacho.cloud.iam.v1.AccessBindingService/NoSuchMethodHere")
	require.Equal(t, codes.PermissionDenied, st.Code())
	require.Nil(t, grantRequirement(st),
		"промах каталога не имеет следующего шага, который можно назвать честно")
}

// TestDenyNextStep_StepUpRefusalKeepsItsOwnStep — второй положительный
// контроль. Отказ, УЖЕ называющий свой следующий шаг (повысить уровень
// аутентификации), второго шага не получает: вызывающий там мог обладать
// выдачей полностью, и совет «попросите право» увёл бы его не туда.
func TestDenyNextStep_StepUpRefusalKeepsItsOwnStep(t *testing.T) {
	reg := mustRegistry(t)

	stepUp := status.New(codes.PermissionDenied, "permission denied")
	withStepUp, err := stepUp.WithDetails(&errdetails.PreconditionFailure{
		Violations: []*errdetails.PreconditionFailure_Violation{{
			Type:        "authz.step_up",
			Subject:     "acr_values:2",
			Description: "insufficient_user_authentication: higher ACR required",
		}},
	})
	require.NoError(t, err)

	st := throughInterceptor(t, reg, "/kacho.cloud.iam.v1.AccessBindingService/Get", withStepUp.Err())
	require.Nil(t, grantRequirement(st),
		"к отказу, уже назвавшему свой шаг, второй совет не приписывается")
}

// TestDenyNextStep_EveryScopedMethodNamesItsStep — класс, а не случай: перепись
// печатает ОБЕ величины, потому что одно число скрывает ровно тот случай, ради
// которого проверка заводится.
func TestDenyNextStep_EveryScopedMethodNamesItsStep(t *testing.T) {
	reg := mustRegistry(t)

	total, named := 0, 0
	var bare []string
	for _, e := range reg.All() {
		if !strings.HasPrefix(e.FQN, "kacho.cloud.iam.") {
			continue
		}
		if e.Permission == "" || e.ScopeExtractor.ObjectType == "" {
			// Область не названа каталогом — назвать её честно нечем.
			continue
		}
		total++
		if grantRequirement(denyThrough(t, reg, "/"+e.FQN)) != nil {
			named++
			continue
		}
		bare = append(bare, e.FQN)
	}
	require.NotZero(t, total, "методов с областью прочитано 0 — вердикт беспредметен")
	t.Logf("перепись: методов iam с названной областью %d · отказ называет следующий шаг у %d · голых %d",
		total, named, len(bare))
	require.Empty(t, bare, "у %d методов отказ остаётся голым", len(bare))

	// Отрицание в паре с положительным: перепись обязана быть непустой, иначе
	// «голых 0» означало бы «прочитано 0».
	assert.Equal(t, total, named)
}

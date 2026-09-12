// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzguard

// own_front_hop_caller_policy_test.go — хоп собственного REST-фронта проходит ПОЛ
// и не проходит круг края (задача продукта #2371).
//
// # Предмет
//
// Внутренний REST-фронт — обычный клиент своего же gRPC-слушателя, и
// представляется он клиентским листом самой службы. Учётная запись у службы
// СВОЯ, приставки платформенных модулей она не несёт, поэтому разбор имени
// модуля на такой строке не срабатывает — и пол отвергал КАЖДЫЙ запрос,
// пришедший через фронт, в боевой посадке.
//
// # Почему это невидимо на стенде — и почему проба поэтому судит ОБЕ посадки
//
// В не-боевой посадке пол и круг края вырождаются целиком (`if !p.prodMode {
// return nil }`), поэтому на стенде фронт обслуживает ВСЁ, а в боевой — НИЧЕГО.
// Проба, снявшая вердикт на одной посадке, о другой не утверждает ничего;
// именно поэтому сплошной отказ прожил незамеченным.
//
// # Чем держится «круг не расширен»
//
// Равенством множеств: хоп допускается ровно к тому, к чему допущен ЛЮБОЙ
// проверенный модуль. Утверждение двустороннее by construction — оно краснеет и
// когда хоп получил лишнее (круг края), и когда потерял положенное (пол).
// Односторонняя проба «хоп проходит пол» зеленела бы на политике, пропускающей
// его всюду.

import (
	"context"
	"sort"
	"testing"

	"google.golang.org/genproto/googleapis/api/annotations"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	"github.com/PRO-Robotech/corelib/grpcsrv"
)

// ownFrontHopSAN — имя клиентского листа самой службы.
//
// Взято из чарта, который этот сертификат выдаёт (charts/kaname:
// mtls.spiffe.{trustDomain,namespace,saName}), а не написано по образцу соседей:
// сегмент учётной записи у службы СВОЙ и приставки платформенных модулей не
// несёт — ровно поэтому её лист и не разбирается в имя модуля.
//
// Боевой корень эту строку НЕ выписывает: он читает её из того сертификата,
// который фронт предъявляет (cmd/kaname/ownfronthop.go). Здесь она стоит
// величиной пробы, а согласие с чартом утверждается отдельно —
// TestOwnFrontHopSANMatchesTheChart в пакете корня.
// Домен доверия и пространство имён фикстуры — ПРОИЗВОЛЬНЫЕ, и это решение.
//
// Политика сравнивает предъявленное имя ЦЕЛИКОМ и о его содержании не судит:
// домен приходит к ней величиной, а не константой. Поэтому фикстуре довольно
// любой пары, и настоящая пара установки здесь ничего не доказывала бы сверх.
//
// Взята нейтральная: имя платформы на поверхности, которой продукт называет
// СЕБЯ, ведётся ведомостью остатка (internal/repohygiene). Литерал, ничего не
// утверждающий, растил бы остаток на ровном месте — и рос бы с каждой новой
// фикстурой.
//
// Связь с ЧАРТОМ держит соседний пакет (cmd/kaname,
// TestOwnFrontHopSANMatchesTheChart): там величина обязана совпадать с выдачей
// чарта by construction, и там она под записью «решено остаться».
const (
	ownFrontTrustDomain = "kaname.test"
	ownFrontNamespace   = "identity"
)

const ownFrontHopSAN = "spiffe://" + ownFrontTrustDomain + "/ns/" + ownFrontNamespace + "/sa/kaname"

// internalListenerServices — службы, поднятые на ВНУТРЕННЕМ слушателе
// (cmd/kaname/grpc_register.go, registerInternalServices).
//
// Перечень выписан здесь намеренно, как и у соседнего гейта фронтов: проба
// обязана судить поверхность независимо от того, что о ней думает дверь.
var internalListenerServices = map[string]bool{
	"InternalUserService":               true,
	"InternalIAMService":                true,
	"AuthorizeService":                  true,
	"InternalClusterService":            true,
	"InternalInteractiveClientService":  true,
	"InternalModuleService":             true,
	"InternalLimitService":              true,
	"InternalSessionRevocationsService": true,
	"InternalOperationsService":         true,
	"InternalBootstrapTokenService":     true,
}

// internalMethods — полные имена ВСЕХ методов внутреннего слушателя, выведенные
// из дескрипторов контракта.
//
// Выводятся, а не выписываются: рукописный перечень стареет молча, и его
// «отвергнуто 0» означало бы «о новых методах не спрашивали».
func internalMethods(t *testing.T) []string {
	t.Helper()
	var out []string
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if string(fd.Package()) != "kaname.cloud.iam.v1" {
			return true
		}
		for i := 0; i < fd.Services().Len(); i++ {
			svc := fd.Services().Get(i)
			if !internalListenerServices[string(svc.Name())] {
				continue
			}
			for j := 0; j < svc.Methods().Len(); j++ {
				out = append(out, "/"+string(svc.FullName())+"/"+string(svc.Methods().Get(j).Name()))
			}
		}
		return true
	})
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatal("методов внутреннего слушателя не найдено ни одного — обход пуст, вердикт беспредметен")
	}
	return out
}

// routedInternalMethods — те из них, У КОТОРЫХ ЕСТЬ маршрут HTTP, то есть ровно
// то, что внутренний REST-фронт способен обслужить.
func routedInternalMethods(t *testing.T) []string {
	t.Helper()
	var out []string
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if string(fd.Package()) != "kaname.cloud.iam.v1" {
			return true
		}
		for i := 0; i < fd.Services().Len(); i++ {
			svc := fd.Services().Get(i)
			if !internalListenerServices[string(svc.Name())] {
				continue
			}
			for j := 0; j < svc.Methods().Len(); j++ {
				m := svc.Methods().Get(j)
				if r, _ := proto.GetExtension(m.Options(), annotations.E_Http).(*annotations.HttpRule); r == nil {
					continue
				}
				out = append(out, "/"+string(svc.FullName())+"/"+string(m.Name()))
			}
		}
		return true
	})
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatal("маршрутизируемых методов внутреннего слушателя не найдено — обход пуст, вердикт беспредметен")
	}
	return out
}

// hopPolicy — политика посадки, где собственный REST-фронт ПОДНЯТ.
func hopPolicy(prod bool) *CallerPolicy {
	return testPolicy(prod).WithOwnFrontHop(ownFrontHopSAN)
}

// newOwnFrontHopCtx — мир развёрнутой посадки: запрос пришёл через собственный
// REST-фронт, и фронт назвался своим клиентским листом.
func newOwnFrontHopCtx() context.Context {
	return grpcsrv.WithCertIdentityIn(
		context.Background(), grpcsrv.NewTrustDomain(ownFrontTrustDomain), ownFrontHopSAN, true)
}

// hopDecision — решение о вызывающем на одном методе.
//
// Тип, а не прямой вызов политики: доказательство способности утверждения упасть
// (own_front_hop_injection_test.go) подставляет сюда СЛОМАННЫЕ реализации — в
// том числе ту соблазнительную, которая пропускает хоп мимо круга края. Без шва
// инъекции пришлось бы переписывать сравнение, то есть проверять свою копию, а
// не действующий код.
type hopDecision func(ctx context.Context, fullMethod string) error

// admittedBy — множество методов, которые данное решение пропускает.
func admittedBy(decide hopDecision, ctx context.Context, methods []string) map[string]bool {
	out := make(map[string]bool, len(methods))
	for _, m := range methods {
		if decide(ctx, m) == nil {
			out[m] = true
		}
	}
	return out
}

// admitted — то же самое для действующей политики.
func admitted(p *CallerPolicy, ctx context.Context, methods []string) map[string]bool {
	return admittedBy(p.allow, ctx, methods)
}

// hopVersusModule — РАСХОЖДЕНИЕ допуска хопа с допуском проверенного модуля.
//
// Возвращает две величины, и обе несущие: `extra` — что хопу позволено сверх
// модуля (полоса HTTP шире полосы gRPC), `missing` — чего ему не хватает
// (поверхность поднята и не обслуживает). Одна величина скрыла бы ровно тот
// случай, ради которого утверждение и написано.
func hopVersusModule(decide hopDecision, methods []string) (extra, missing []string) {
	hop := admittedBy(decide, newOwnFrontHopCtx(), methods)
	module := admittedBy(decide, newVPCCtx(), methods)
	return diff(hop, module), diff(module, hop)
}

func diff(a, b map[string]bool) []string {
	var only []string
	for m := range a {
		if !b[m] {
			only = append(only, m)
		}
	}
	sort.Strings(only)
	return only
}

// ─────────────────────────────────────────────────────────────────────────────
// НЕСУЩЕЕ УТВЕРЖДЕНИЕ

// TestOwnFrontHop_AdmittedToExactlyWhatAnyVerifiedModuleIs — хоп фронта получает
// РОВНО допуск проверенного модуля: ни методом больше, ни методом меньше.
//
// Утверждение двустороннее, и обе стороны несущие:
//
//   - «не меньше» — предмет задачи: сегодня хоп не проходит даже пол;
//   - «не больше» — предмет безопасности: пропусти его круг края, и полоса HTTP
//     стала бы ШИРЕ полосы gRPC. Держатель любого листа внутреннего центра
//     дотянулся бы через фронт до глаголов, которые ему на gRPC запрещены, —
//     ровно то повышение прав, ради которого круг края и заведён.
//
// Сверяется на ОБЕИХ посадках: в не-боевой политика вырождается целиком, и
// вердикт одной посадки о другой не говорит ничего.
func TestOwnFrontHop_AdmittedToExactlyWhatAnyVerifiedModuleIs(t *testing.T) {
	methods := internalMethods(t)
	for _, prod := range []bool{true, false} {
		p := hopPolicy(prod)
		hop := admitted(p, newOwnFrontHopCtx(), methods)
		module := admitted(p, newVPCCtx(), methods)
		extra, missing := hopVersusModule(p.allow, methods)

		if len(extra) > 0 {
			t.Errorf("prod=%v: хопу фронта позволено БОЛЬШЕ, чем проверенному модулю (%d из %d): %v — "+
				"полоса HTTP шире полосы gRPC, и держатель листа внутреннего центра дотянулся бы "+
				"через фронт до запрещённого ему глагола",
				prod, len(extra), len(methods), extra)
		}
		if len(missing) > 0 {
			t.Errorf("prod=%v: хопу фронта позволено МЕНЬШЕ, чем проверенному модулю (%d из %d): %v — "+
				"фронт поднят, маршруты зарегистрированы, и эти вызовы он не обслужит ни один",
				prod, len(missing), len(methods), missing)
		}
		t.Logf("prod=%-5v : методов внутреннего слушателя %d · хопу позволено %d · модулю позволено %d",
			prod, len(methods), len(hop), len(module))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ИСХОД, А НЕ ОБЪЯВЛЕНИЕ: перепись по маршрутизируемой поверхности

// TestOwnFrontHop_RoutedSurfaceCensus — сколько маршрутов внутреннего фронта
// отвергает и пропускает ЭТОТ СТРАЖ, В ОБЕИХ ПОСАДКАХ и ДО/ПОСЛЕ объявления
// хопа.
//
// # Величина здесь — про рукав, а НЕ про путь запроса
//
// Названа так намеренно. За этим стражем в той же цепочке стоят ещё два, и
// один из них судит хоп ТЕМ ЖЕ разбором имени модуля, — поэтому «пропущено N»
// по одному рукаву ШИРЕ того, что доживает до обработчика. Отчётная величина
// живёт в переписи цепочки (own_front_hop_chain_census_test.go); здесь она
// была бы заявлением шире сделанного.
//
// «До» здесь — не прошлая ревизия дерева, а политика ТОЙ ЖЕ сборки без
// объявленного хопа: одна и та же полоса кода, один изменённый факт. Так
// перепись остаётся воспроизводимой и после того, как дефекта не станет.
//
// Печатается ВСЕГДА: «ноль отвергнутых» обязано быть отличимо от «ноль
// осмотренных».
func TestOwnFrontHop_RoutedSurfaceCensus(t *testing.T) {
	routed := routedInternalMethods(t)
	ctx := newOwnFrontHopCtx()

	type row struct {
		posture  string
		declared bool
		denied   int
	}
	var rows []row
	for _, prod := range []bool{true, false} {
		for _, declared := range []bool{false, true} {
			p := testPolicy(prod)
			if declared {
				p = p.WithOwnFrontHop(ownFrontHopSAN)
			}
			denied := 0
			for _, m := range routed {
				if p.allow(ctx, m) != nil {
					denied++
				}
			}
			posture := "стенд"
			if prod {
				posture = "боевая"
			}
			rows = append(rows, row{posture, declared, denied})
			t.Logf("посадка %-7s · хоп объявлен %-5v : маршрутов %d · отвергнуто %2d · пропущено %2d",
				posture, declared, len(routed), denied, len(routed)-denied)
		}
	}

	// Несущее следствие переписи: в БОЕВОЙ посадке необъявленный хоп отвергается
	// ЦЕЛИКОМ, а объявленный — обслуживает свою полосу. Утверждается пара, а не
	// половина: без первой строки вторая зеленела бы на политике, пропускающей
	// всё.
	prodUndeclared, prodDeclared := rows[0], rows[1]
	if prodUndeclared.denied != len(routed) {
		t.Errorf("боевая посадка, хоп НЕ объявлен: отвергнуто %d из %d, ожидалось всё — "+
			"перепись перестала воспроизводить предмет задачи, и «после» больше ничего не доказывает",
			prodUndeclared.denied, len(routed))
	}
	if prodDeclared.denied >= len(routed) {
		t.Errorf("боевая посадка, хоп объявлен: отвергнуто %d из %d — "+
			"фронт по-прежнему не обслуживает НИ ОДНОГО маршрута",
			prodDeclared.denied, len(routed))
	}
	if prodDeclared.denied == 0 {
		t.Errorf("боевая посадка, хоп объявлен: отвергнуто 0 из %d — хоп проходит и круг края, "+
			"то есть полоса HTTP стала шире полосы gRPC", len(routed))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ЗАКОННЫЕ БЛИЗНЕЦЫ: круг не расширен

// TestOwnFrontHop_NeverSatisfiesTheGatewayOnlyArm — хоп не становится краем ни
// на одном методе круга края.
//
// Проверяется поимённо по всему кругу, а не на представителе: круг растёт, и
// представитель о новом методе не утверждает ничего.
func TestOwnFrontHop_NeverSatisfiesTheGatewayOnlyArm(t *testing.T) {
	p := hopPolicy(true)
	ctx := newOwnFrontHopCtx()
	gw := GatewayFrontedInternalRPCs()
	if len(gw) == 0 {
		t.Fatal("круг края пуст — сверять нечего, вердикт беспредметен")
	}
	for _, m := range gw {
		err := p.allow(ctx, m)
		if err == nil {
			t.Errorf("хоп фронта допущен к глаголу круга края %s: фронт краем не является и о том, "+
				"кто за ним стоит, не сообщает ничего", m)
			continue
		}
		if codes.PermissionDenied != status.Code(err) {
			t.Errorf("отказ хопу на %s = %v, ожидался %v", m, status.Code(err), codes.PermissionDenied)
		}
	}
	t.Logf("круг края: методов %d · хопу отвергнуты все", len(gw))
}

// TestOwnFrontHop_UndeclaredHopIsDenied — посадка БЕЗ собственного фронта не
// открывает полосу, которой на ней нет.
//
// Без этой пробы объявление хопа могло бы оказаться не нужным вовсе: политика
// пропускала бы лист и без него, а несущее утверждение выше этого не показало
// бы — оно сравнивает хоп с модулем, а не с самим собой.
func TestOwnFrontHop_UndeclaredHopIsDenied(t *testing.T) {
	if err := testPolicy(true).allow(newOwnFrontHopCtx(), floorOnlyMethod); err == nil {
		t.Fatal("политика без объявленного хопа пропустила лист фронта — величина ни на что не влияет, " +
			"и «после» доказывает не то, что заявлено")
	}
}

// TestOwnFrontHop_ForeignLeafIsStillDenied — ЗАКОННЫЙ БЛИЗНЕЦ круга: допущена
// ОДНА личность, а не класс строк.
//
// Соседние формы, каждая по своей оси: чужое пространство имён, чужое имя
// учётной записи, чужой домен доверия. Разбор имени модуля их всех отвергает и
// сегодня — утверждение здесь в том, что объявление хопа этого НЕ ИЗМЕНИЛО.
func TestOwnFrontHop_ForeignLeafIsStillDenied(t *testing.T) {
	p := hopPolicy(true)
	d := grpcsrv.NewTrustDomain(ownFrontTrustDomain)
	for _, tc := range []struct {
		name string
		dom  grpcsrv.TrustDomain
		san  string
	}{
		{"чужое пространство имён", d, "spiffe://" + ownFrontTrustDomain + "/ns/other/sa/kaname"},
		{"чужое имя учётной записи", d, ownFrontHopSAN + "-shadow"},
		{"приставка нашего имени", d, "spiffe://" + ownFrontTrustDomain + "/ns/" + ownFrontNamespace + "/sa/kanam"},
		{"чужой домен доверия", grpcsrv.NewTrustDomain("evil.example"), "spiffe://evil.example/ns/" + ownFrontNamespace + "/sa/kaname"},
	} {
		ctx := grpcsrv.WithCertIdentityIn(context.Background(), tc.dom, tc.san, true)
		if err := p.allow(ctx, floorOnlyMethod); err == nil {
			t.Errorf("%s (%s) прошёл пол — объявление хопа допустило КЛАСС строк вместо одной личности",
				tc.name, tc.san)
		}
	}
}

// TestOwnFrontHop_UnverifiedPeerNamingItselfIsDenied — имя само по себе
// удостоверением не является.
//
// Строка публична: она стоит в чарте и в этой пробе. Пропусти политика
// непроверенного предъявителя, назвавшегося ею, — «хоп» стал бы паролем.
func TestOwnFrontHop_UnverifiedPeerNamingItselfIsDenied(t *testing.T) {
	ctx := grpcsrv.WithCertIdentityIn(
		context.Background(), grpcsrv.NewTrustDomain(ownFrontTrustDomain), ownFrontHopSAN, false)
	if err := hopPolicy(true).allow(ctx, floorOnlyMethod); err == nil {
		t.Fatal("непроверенный предъявитель, назвавшийся именем фронта, прошёл пол — " +
			"имя стало паролем")
	}
}

// TestOwnFrontHop_MintStaysDeniedToTheFront — третий рукав хоп не смягчает.
//
// Чеканка кластерного администратора маршрута HTTP не имеет вовсе, и это её
// первая защита; вторая — явный перечень листов, в котором фронта нет. Проба
// утверждает ВТОРУЮ: первая исчезнет вместе с появлением маршрута, а вторая
// обязана пережить это молча.
func TestOwnFrontHop_MintStaysDeniedToTheFront(t *testing.T) {
	if err := hopPolicy(true).allow(newOwnFrontHopCtx(), BootstrapMintFullMethod); err == nil {
		t.Fatal("хоп фронта допущен к чеканке кластерного администратора")
	}
	// И в не-боевой посадке тоже: третий рукав терминален в ЛЮБОМ режиме.
	if err := hopPolicy(false).allow(newOwnFrontHopCtx(), BootstrapMintFullMethod); err == nil {
		t.Fatal("хоп фронта допущен к чеканке в не-боевой посадке — третий рукав перестал быть терминальным")
	}
}

// TestOwnFrontHop_EmptyDeclarationMatchesNobody — пустое объявление не совпадает
// ни с чем, включая пустое имя.
//
// Тот же класс, что у пустого перечня третьего рукава: величина, которую забыли
// задать, не должна открывать полосу.
func TestOwnFrontHop_EmptyDeclarationMatchesNobody(t *testing.T) {
	p := testPolicy(true).WithOwnFrontHop("   ")
	ctx := grpcsrv.WithCertIdentityIn(
		context.Background(), grpcsrv.NewTrustDomain(ownFrontTrustDomain), "", true)
	if err := p.allow(ctx, floorOnlyMethod); err == nil {
		t.Fatal("пустое объявление хопа совпало с пустым именем — незаданная величина открыла полосу")
	}
}

// TestOwnFrontHop_GRPCPathOfAModuleIsUnchanged — правка не тронула того, ради
// кого политика написана.
//
// Без этой пробы «круг не расширен» доказывало бы только про хоп, а изменение
// стоит в общей ветви пола, через которую проходит КАЖДЫЙ вызывающий.
func TestOwnFrontHop_GRPCPathOfAModuleIsUnchanged(t *testing.T) {
	methods := internalMethods(t)
	for _, prod := range []bool{true, false} {
		before := admitted(testPolicy(prod), newVPCCtx(), methods)
		after := admitted(hopPolicy(prod), newVPCCtx(), methods)
		if extra := diff(after, before); len(extra) > 0 {
			t.Errorf("prod=%v: модулю стало позволено больше: %v", prod, extra)
		}
		if missing := diff(before, after); len(missing) > 0 {
			t.Errorf("prod=%v: модулю стало позволено меньше: %v", prod, missing)
		}
		gw := admitted(hopPolicy(prod), newGatewayCtx(), methods)
		gwBefore := admitted(testPolicy(prod), newGatewayCtx(), methods)
		if len(diff(gw, gwBefore))+len(diff(gwBefore, gw)) > 0 {
			t.Errorf("prod=%v: допуск края изменился", prod)
		}
	}
}

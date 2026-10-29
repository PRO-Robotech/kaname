// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// module_roster_probe_test.go — личность модуля и перечень методов внутреннего
// слушателя на каждую личность (kaname#984).
//
// Пробы DoD:
//
//  1. лист с учёткой модуля из пространства, которого установка не объявила,
//     модулем не признаётся, и вызов метода модуля отвергается;
//  2. личность плоскости данных зовёт метод вне своего перечня —
//     `PermissionDenied`, в том числе метод, освобождённый от проверки
//     отношений;
//  3. законный близнец: объявленная личность зовёт метод своего перечня — проход;
//  4. на одном наборе форм идентификатора все пути признания вызывающего этого
//     пакета решают одинаково (путь обработчика решений — в его пакете, на том
//     же наборе `testsupport/moduleroster`).
//
// Перепись (п. 5 ниже) держит перечни честными: каждое имя перечня существует
// в контракте, и каждый метод служб внутреннего слушателя отнесён к профилю
// либо к рукаву точных идентификаторов.
package authzguard

import (
	"context"
	"sort"
	"strings"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"

	_ "github.com/PRO-Robotech/corelib/api/corelib/subscription"

	"github.com/PRO-Robotech/kaname/internal/moduleidentity"
	"github.com/PRO-Robotech/kaname/internal/testsupport/moduleroster"
	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"
)

// Идентификаторы личностей набора.
const (
	rosterGatewaySAN   = "spiffe://" + moduleroster.DomainName + "/ns/kacho/sa/kacho-api-gateway"
	rosterDataPlaneSAN = "spiffe://" + moduleroster.DomainName + "/ns/registry/sa/kacho-registry-dp"
	rosterIntruderSAN  = "spiffe://" + moduleroster.DomainName + "/ns/intruder/sa/kacho-vpc"
)

// rosterPolicy — боевая политика внутреннего слушателя с перечнем набора.
func rosterPolicy(t *testing.T) *CallerPolicy {
	t.Helper()
	return NewCallerPolicy(true, GatewayFrontedInternalRPCs()).WithModuleRoster(moduleroster.Roster(t))
}

// allowingChecker — модель доступа, отвечающая «да» на любой вопрос: пробы
// признания судят признание, а не отношения.
type allowingChecker struct{ calls int }

func (c *allowingChecker) Check(context.Context, string, string, string) (bool, error) {
	c.calls++
	return true, nil
}

// requireDenied — отказ ровно кодом PermissionDenied и дословным текстом.
func requireDenied(t *testing.T, err error, what string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: прошло, ожидался отказ PermissionDenied", what)
	}
	if st, _ := status.FromError(err); st.Code() != codes.PermissionDenied || st.Message() != "permission denied" {
		t.Fatalf("%s: отказ %v %q, ожидался PermissionDenied \"permission denied\"", what, st.Code(), st.Message())
	}
}

// TestModuleRoster_UndeclaredNamespaceLeafIsNotAModule — DoD п. 1.
//
// Учётка `kacho-vpc` объявлена в пространстве `kacho`. Тот же лист из
// пространства `intruder` — не модуль: вызов метода модуля отвергается и
// политикой вызывающего, и посредником записи отношений. Близнец — та же
// учётка в объявленном пространстве — проходит оба.
func TestModuleRoster_UndeclaredNamespaceLeafIsNotAModule(t *testing.T) {
	p := rosterPolicy(t)
	gate := NewRelationWriteGate(&allowingChecker{}).WithProductionMode(true).WithModuleRoster(moduleroster.Roster(t))

	intruder := moduleroster.IdentityContext(rosterIntruderSAN)
	requireDenied(t, p.allow(intruder, internalRegisterResourceMethod), "политика вызывающего: лист необъявленного пространства")
	_, err := gate.Authorize(intruder)
	requireDenied(t, err, "посредник записи отношений: лист необъявленного пространства")

	declared := moduleroster.IdentityContext(moduleroster.DeclaredVPC)
	if err := p.allow(declared, internalRegisterResourceMethod); err != nil {
		t.Fatalf("близнец: объявленная пара отвергнута политикой: %v", err)
	}
	domain, err := gate.Authorize(declared)
	if err != nil || domain != "vpc" {
		t.Fatalf("близнец: объявленная пара у посредника — домен %q, ошибка %v; ожидался домен vpc", domain, err)
	}
}

// TestModuleRoster_DataPlaneOutsideItsListIsRefused — DoD п. 2.
//
// Плоскости данных открыт ровно вопрос о доступе. Методы вне перечня —
// отказ, в том числе освобождённые от проверки отношений (`LookupSubject`,
// `PollSubjectChanges`, `ResolveBasicCredential`, `IsRevoked`): освобождение
// означает «вопроса к модели здесь нет», а не «звать вправе всякий».
func TestModuleRoster_DataPlaneOutsideItsListIsRefused(t *testing.T) {
	p := rosterPolicy(t)
	ctx := moduleroster.IdentityContext(rosterDataPlaneSAN)
	for _, method := range []string{
		internalLookupSubjectMethod,
		internalPollSubjectChangesMethod,
		internalResolveBasicMethod,
		internalCheckBasicLiveMethod,
		internalGetRoleCompiledMethod,
		internalRegisterResourceMethod,
		internalUnregisterResourceMethod,
		internalIsRevokedMethod,
		internalUserGetMethod,
		internalSubscribeMethod,
		authorizeBatchCheckFullMethod,
		authorizeListSubjectsFullMethod,
	} {
		requireDenied(t, p.allow(ctx, method), "плоскость данных → "+method)
	}
	if err := p.allow(ctx, internalCheckMethod); err != nil {
		t.Fatalf("близнец: плоскость данных отвергнута на своём методе Check: %v", err)
	}
}

// TestModuleRoster_DeclaredIdentityCallsEveryMethodOfItsList — DoD п. 3:
// каждая личность набора проходит на КАЖДОМ методе своего перечня.
func TestModuleRoster_DeclaredIdentityCallsEveryMethodOfItsList(t *testing.T) {
	p := rosterPolicy(t)
	byProfile := map[moduleidentity.Profile]string{
		moduleidentity.ProfileEdge:         rosterGatewaySAN,
		moduleidentity.ProfileModuleWriter: moduleroster.DeclaredVPC,
		moduleidentity.ProfileDataPlane:    rosterDataPlaneSAN,
	}
	for _, profile := range moduleidentity.Profiles() {
		san, ok := byProfile[profile]
		if !ok {
			t.Fatalf("у профиля %q нет личности в пробе", profile)
		}
		methods := ProfileMethods(profile)
		if len(methods) == 0 {
			t.Fatalf("перечень профиля %q пуст", profile)
		}
		for _, method := range methods {
			if err := p.allow(moduleroster.IdentityContext(san), method); err != nil {
				t.Errorf("%s (%s) отвергнут на методе своего перечня %s: %v", san, profile, method, err)
			}
		}
	}
}

// TestModuleRoster_EveryCallerCheckPathDecidesTheSame — DoD п. 4.
//
// Пять путей этого пакета на одном наборе форм. Решение каждого сводится к
// одному биту — признан ли вызывающий модулем `vpc`, — и бит обязан совпасть с
// ожиданием формы у каждого пути.
func TestModuleRoster_EveryCallerCheckPathDecidesTheSame(t *testing.T) {
	roster := moduleroster.Roster(t)
	internal := NewCallerPolicy(true, GatewayFrontedInternalRPCs()).WithModuleRoster(roster)
	public := NewPublicCallerPolicy(true, PublicPeerCallableRPCs(), nil, nil).WithModuleRoster(roster)
	writer := NewRelationWriteGate(&allowingChecker{}).WithProductionMode(true).WithModuleRoster(roster)
	floor := NewSystemViewerFloor(&allowingChecker{}, ReadFloorRPCs()).WithProductionMode(true).WithModuleRoster(roster)
	anonymousShape := &iamv1.AuthorizeCheckRequest{
		Resource: &iamv1.ResourceRef{Type: "vpc_network", Id: "net1"},
		Action:   "get",
	}

	paths := map[string]func(ctx context.Context) bool{
		"политика внутреннего слушателя": func(ctx context.Context) bool {
			return internal.allow(ctx, internalRegisterResourceMethod) == nil
		},
		"политика публичного слушателя": func(ctx context.Context) bool {
			return public.allow(ctx, publicProjectGetMethod) == nil
		},
		"посредник записи отношений": func(ctx context.Context) bool {
			domain, err := writer.Authorize(ctx)
			return err == nil && domain == "vpc"
		},
		"пол системного читателя": func(ctx context.Context) bool {
			return floor.allow(ctx, internalLookupSubjectMethod) == nil
		},
		"допуск анонимной самопроверки": func(ctx context.Context) bool {
			// Модуль — другой вызывающий: анонимной формой он не становится.
			return !IsAnonymousSelfCheck(ctx, anonymousShape, roster)
		},
	}
	names := make([]string, 0, len(paths))
	for name := range paths {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, form := range moduleroster.Forms() {
		for _, name := range names {
			if got := paths[name](form.Context(context.Background())); got != form.Module {
				t.Errorf("форма %q (%s): путь %q признал модулем = %v, ожидалось %v",
					form.Name, form.SAN, name, got, form.Module)
			}
		}
	}
	t.Logf("перепись: форм %d · путей %d · решений %d", len(moduleroster.Forms()), len(names), len(moduleroster.Forms())*len(names))
}

// internalListenerServiceDescriptors — службы, которые композиционный корень поднимает на
// внутреннем слушателе: все `Internal*` контракта службы, служба решений и
// поток изменений фундамента. Выводятся обходом реестра описаний, а не
// перечнем имён.
func internalListenerServiceDescriptors() []protoreflect.ServiceDescriptor {
	var out []protoreflect.ServiceDescriptor
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		pkg := string(fd.Package())
		for i := 0; i < fd.Services().Len(); i++ {
			sd := fd.Services().Get(i)
			name := string(sd.Name())
			switch {
			case pkg == "kaname.cloud.iam.v1" && (strings.HasPrefix(name, "Internal") || name == "AuthorizeService"):
				out = append(out, sd)
			case pkg == "corelib.subscription" && name == "InternalSubscriptionService":
				out = append(out, sd)
			}
		}
		return true
	})
	return out
}

// TestModuleProfiles_EveryInternalMethodIsClassifiedAndEveryEntryExists —
// перепись перечней в обе стороны.
//
// Прямая: каждый метод служб внутреннего слушателя назван хотя бы одним
// профилем либо рукавом точных идентификаторов — новый метод, не отнесённый
// никуда, был бы закрыт для всех молча. Обратная: каждое имя перечня есть
// метод контракта — запись о несуществующем методе ничего не открывает и
// читается как объявление живой поверхности.
func TestModuleProfiles_EveryInternalMethodIsClassifiedAndEveryEntryExists(t *testing.T) {
	services := internalListenerServiceDescriptors()
	if len(services) == 0 {
		t.Fatal("предпосылка: обход реестра описаний не нашёл ни одной службы внутреннего слушателя — перепись не выполнилась")
	}
	existing := map[string]struct{}{}
	for _, sd := range services {
		for i := 0; i < sd.Methods().Len(); i++ {
			existing["/"+string(sd.FullName())+"/"+string(sd.Methods().Get(i).Name())] = struct{}{}
		}
	}
	classified := classifiedInternalMethods()
	for _, f := range profileCensusFindings(classified, existing) {
		t.Error(f)
	}
	t.Logf("перепись: служб %d · методов %d · отнесённых имён %d", len(services), len(existing), len(classified))
}

// classifiedInternalMethods — имена, которые называют перечни профилей и рукав
// точных идентификаторов.
func classifiedInternalMethods() map[string]struct{} {
	out := map[string]struct{}{}
	for _, m := range SANRestrictedInternalRPCs() {
		out[m] = struct{}{}
	}
	for _, p := range moduleidentity.Profiles() {
		for _, m := range ProfileMethods(p) {
			out[m] = struct{}{}
		}
	}
	return out
}

// profileCensusFindings — суд переписи в обе стороны: метод без отнесения и
// имя перечня без метода. Вынесен функцией, чтобы его способность упасть
// доказывалась синтетикой ниже на каждом прогоне.
func profileCensusFindings(classified, existing map[string]struct{}) []string {
	var out []string
	for m := range existing {
		if _, ok := classified[m]; !ok {
			out = append(out, "метод "+m+" внутреннего слушателя не отнесён ни к одному профилю и ни к рукаву точных идентификаторов")
		}
	}
	for m := range classified {
		if _, ok := existing[m]; !ok {
			out = append(out, "перечень называет "+m+", а такого метода у служб внутреннего слушателя нет")
		}
	}
	sort.Strings(out)
	return out
}

// TestModuleProfilesCensus_FindsBothDefectsAndStaysSilentOnTheTwin — инъекция
// в обе стороны: новый метод без отнесения найден, имя перечня без метода
// найдено, совпадающие множества — молчание.
func TestModuleProfilesCensus_FindsBothDefectsAndStaysSilentOnTheTwin(t *testing.T) {
	set := func(names ...string) map[string]struct{} {
		out := map[string]struct{}{}
		for _, n := range names {
			out[n] = struct{}{}
		}
		return out
	}
	const known, added, phantom = "/svc.A/Known", "/svc.A/Added", "/svc.A/Removed"
	if got := profileCensusFindings(set(known), set(known)); len(got) != 0 {
		t.Fatalf("близнец: совпадающие множества дали находки %v", got)
	}
	got := profileCensusFindings(set(known), set(known, added))
	if len(got) != 1 || !strings.Contains(got[0], added) {
		t.Fatalf("метод без отнесения не найден с именем: %v", got)
	}
	got = profileCensusFindings(set(known, phantom), set(known))
	if len(got) != 1 || !strings.Contains(got[0], phantom) {
		t.Fatalf("имя перечня без метода не найдено с именем: %v", got)
	}
}

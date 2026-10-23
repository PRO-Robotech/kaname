// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package access_binding

// target_live_catalog_test.go — пробы-держатели S1 (unit) приёмки
// docs/engineering/acceptance/access-target-names-live-catalog-types.md
// (редакция 2, отпечаток 18360285461ee74e59c92a0445fcff9d313e8c2e3ed99bb56b4efce209ff9bd9;
// задача PRO-Robotech/kaname#904): вход ручки `Create` судит тип пообъектной цели
// ЖИВЫМ каталогом (Р1), а не закрытым перечнем в коде.
//
// # Мир М1
//
// Каталожный факт — живые строки посева (`seed.LiteralRows()`) плюс строки
// фикстуры `internal/manifest/testdata/probemod.public-read-fixture.yaml`
// (`probemod.boxes`, `probemod.items`), выведенные тем же производителем, что у
// применителя (`modulecatalog.RowsOf`).
//
// # Что наблюдается
//
// Вход идёт через настоящий обработчик (`Handler.Create`) и настоящий use-case.
// Вызывающий анонимен, поэтому у входа ровно два исхода: отказ по типу цели
// (`INVALID_ARGUMENT`, текст Т1 дословно) либо следующие за проверкой типа ворота
// (`PERMISSION_DENIED` от `RequireAuthenticated`). Второй исход и есть «тип
// принят»: до хранилища вход не доходит, поэтому пробе хранилище не нужно, а
// порядок «тип — до права выдавать» (Р2) утверждается тем же вызовом.

import (
	"context"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	iamv1 "github.com/PRO-Robotech/kaname/pkg/api/kaname/cloud/iam/v1"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/modulecatalog"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
	"github.com/PRO-Robotech/kaname/internal/catalog"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/testsupport/catalogfixture"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// t1 — текст Т1 приёмки (Р3) для типа `typ`, дословно.
func t1(typ string) string {
	return `Illegal argument target.resources[].type "` + typ +
		`" (not a live entry of the platform resource catalog; grantable types are published by GET /iam/v1/permissionCatalog)`
}

// m1Facts — каталожный факт мира М1. `without` — точечные имена ресурсов
// фикстуры, чья строка СНЯТА (ATC-06 (б)): строка уходит из живой половины,
// модуль остаётся живым, поэтому отказ приходит по ресурсу, а не по модулю.
func m1Facts(t *testing.T, without ...string) *catalog.Facts {
	t.Helper()
	doc, err := publicreadfixture.Read(publicreadfixture.ProbemodFile)
	require.NoError(t, err, "М1: фикстура probemod")
	m, err := manifest.Load(doc)
	require.NoError(t, err, "М1: загрузчик отверг probemod")
	decl, err := modulecatalog.RowsOf(m)
	require.NoError(t, err, "М1: строки каталога probemod не выведены")

	drop := map[string]bool{}
	for _, d := range without {
		drop[d] = true
	}
	live := seed.LiteralRows()
	live.Modules = append(live.Modules, decl.Module)
	var kept int
	for _, r := range decl.Resources {
		if drop[r.Module+"."+r.Resource] {
			continue
		}
		live.Resources = append(live.Resources, r)
		kept++
	}
	for _, v := range decl.Verbs {
		if drop[v.Module+"."+v.Resource] {
			continue
		}
		live.Verbs = append(live.Verbs, v)
	}
	require.Equalf(t, len(decl.Resources)-len(without), kept,
		"М1: снимаемые строки %v не найдены среди ресурсов фикстуры", without)
	f, err := catalog.NewFacts(catalog.Halves{Live: live})
	require.NoError(t, err, "М1: каталожный факт не построен")
	return f
}

// targetJudgeHandler — обработчик над настоящим use-case с каталожным фактом
// `f`. Хранилища нет: вход, принятый проверкой типа, останавливают ворота
// аутентификации, до хранилища он не доходит.
func targetJudgeHandler(f *catalog.Facts) *Handler {
	uc := NewCreateAccessBindingUseCase(nil, nil, catalog.Fixed{F: f})
	return NewHandler(uc, nil, nil, nil, nil, nil, nil)
}

// createAnon — `Create` с целью из `refs` от анонимного вызывающего.
func createAnon(h *Handler, refs ...*iamv1.ResourceRef) error {
	_, err := h.Create(context.Background(), &iamv1.CreateAccessBindingRequest{
		Subjects:  []*iamv1.Subject{{Type: iamv1.SubjectType_SUBJECT_TYPE_USER, Id: "usr00000000000000d01"}},
		RoleId:    "rol00000000000000001",
		ScopeType: "iam.project",
		ScopeId:   "prj00000000000000a01",
		Target: &iamv1.AccessTarget{Target: &iamv1.AccessTarget_Resources{
			Resources: &iamv1.AccessTargetResources{Resources: refs},
		}},
	})
	return err
}

func ref(typ, id string) *iamv1.ResourceRef { return &iamv1.ResourceRef{Type: typ, Id: id} }

// requireTypeAccepted — тип прошёл проверку: исход — следующие ворота.
func requireTypeAccepted(t *testing.T, err error, what string) {
	t.Helper()
	st, ok := status.FromError(err)
	require.Truef(t, ok, "%s: ответ не gRPC-статус: %v", what, err)
	require.Equalf(t, codes.PermissionDenied, st.Code(),
		"%s: тип цели не дошёл до ворот аутентификации — отказ %s %q", what, st.Code(), st.Message())
}

// requireT1 — синхронный отказ по типу цели, текст Т1 дословно.
func requireT1(t *testing.T, err error, typ, what string) {
	t.Helper()
	st, ok := status.FromError(err)
	require.Truef(t, ok, "%s: ответ не gRPC-статус: %v", what, err)
	require.Equalf(t, codes.InvalidArgument, st.Code(), "%s: код отказа (%q)", what, st.Message())
	require.Equalf(t, t1(typ), st.Message(), "%s: текст отказа", what)
}

// ATC-01 / близнец ATC-02: тип модуля, живой в каталоге, принимается; тот же
// модуль с ресурсом, которого нет, отвергается Т1. Отличие — один факт.
func TestATC01_ModuleTypeLiveInCatalogIsAccepted(t *testing.T) {
	h := targetJudgeHandler(m1Facts(t))
	requireTypeAccepted(t, createAnon(h, ref("probemod.boxes", "b1")), "ATC-01 probemod.boxes")
	requireT1(t, createAnon(h, ref("probemod.nope", "b1")), "probemod.nope", "ATC-02 probemod.nope")
}

// ATC-04 и близнец: канонический живой тип вне прежнего перечня принимается;
// то же имя в другом написании отвергается Т1.
func TestATC04_LiveCanonicalTypeOutsideThePriorSetIsAccepted(t *testing.T) {
	h := targetJudgeHandler(m1Facts(t))
	requireTypeAccepted(t, createAnon(h, ref("vpc.addressPool", "ap1")), "ATC-04 vpc.addressPool")
	requireT1(t, createAnon(h, ref("vpc.address_pool", "ap1")), "vpc.address_pool", "ATC-04 близнец vpc.address_pool")
}

// ATC-05 / ATC-06 (а): тип прежнего перечня принимается как сегодня; строка
// посева с `live = false` отвергается тем же текстом, что неизвестный тип (Р4).
func TestATC05_ATC06a_LiveRowAcceptedRetiredRowRefused(t *testing.T) {
	h := targetJudgeHandler(m1Facts(t))
	requireTypeAccepted(t, createAnon(h, ref("compute.instance", "i1")), "ATC-05 compute.instance")
	requireT1(t, createAnon(h, ref("compute.disk", "d1")), "compute.disk", "ATC-06 (а) compute.disk")
}

// ATC-06 (б): строка ресурса модуля снята — ручка, пересобранная на факте после
// снятия, отвергает тип Т1; близнец — тот же вход до снятия принимается.
func TestATC06b_WithdrawnModuleRowIsRefused(t *testing.T) {
	before := targetJudgeHandler(m1Facts(t))
	requireTypeAccepted(t, createAnon(before, ref("probemod.items", "i1")), "ATC-06 (б) близнец: до снятия")
	after := targetJudgeHandler(m1Facts(t, "probemod.items"))
	requireT1(t, createAnon(after, ref("probemod.items", "i1")), "probemod.items", "ATC-06 (б) после снятия")
}

// ATC-07: подстановочный и не-точечный тип отвергаются Т1 с самим типом.
func TestATC07_WildcardAndUndottedTypesAreRefused(t *testing.T) {
	h := targetJudgeHandler(m1Facts(t))
	for _, typ := range []string{"*", "probemod.*", "probemod"} {
		requireT1(t, createAnon(h, ref(typ, "b1")), typ, "ATC-07 "+typ)
	}
	requireTypeAccepted(t, createAnon(h, ref("probemod.boxes", "b1")), "ATC-07 близнец probemod.boxes")
}

// ATC-08: перечень с одним неживым типом отвергается целиком, Т1 называет
// ПЕРВЫЙ неживой тип; близнец — тот же перечень с живым вторым элементом.
func TestATC08_ListWithOneNonLiveTypeIsRefusedWhole(t *testing.T) {
	h := targetJudgeHandler(m1Facts(t))
	requireT1(t, createAnon(h, ref("compute.instance", "i1"), ref("probemod.nope", "x")),
		"probemod.nope", "ATC-08")
	requireT1(t, createAnon(h, ref("probemod.nope", "x"), ref("compute.disk", "d1")),
		"probemod.nope", "ATC-08: из двух неживых называется первый в порядке перечня")
	requireTypeAccepted(t, createAnon(h, ref("compute.instance", "i1"), ref("probemod.boxes", "b1")),
		"ATC-08 близнец")
}

// fixtureLiveTargetTypes — ответ дублёров писателя на `LockLiveTargetTypes`:
// подмножество `types`, живое в каталоге фикстуры (`catalogfixture.Facts`), —
// тот же источник, которым use-case в этих пробах судит синхронно. Дублёр,
// отвечающий «всё живое», был бы снисходительнее продукта.
func fixtureLiveTargetTypes(types []string) []string {
	f := catalogfixture.Facts()
	var out []string
	for _, ty := range types {
		if _, ok := f.FGAObjectType(ty); ok {
			out = append(out, ty)
		}
	}
	return out
}

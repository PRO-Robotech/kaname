// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acr_floor_cluster_admin_floor_test.go — ступень подтверждения личности у
// четырёх методов InternalClusterService берётся У КОНТРАКТА, а не у шапки
// (задача kaname#131).
//
// ПРЕДМЕТ. Шапка `acr_floor.go` объявляла `required_acr_min=2` сразу у всех
// четырёх, тогда как контракт объявляет `Get` и `ListAdmins` единицей, а
// `GrantAdmin` и `RevokeAdmin` двойкой. Расхождение шапки о рубеже безопасности
// с контрактом — ловушка `security-hardening.md` п. 5: следующий «чинит»
// контракт под шапку либо шапку под контракт, не спросив, что решено.
//
// ШОВ С СОСЕДНЕЙ ПРОБОЙ. Шапка `acr_floor.go` называет полы вслед за контрактом,
// и каждое её утверждение вида «…/Метод … required_acr_min=N» сверяет со
// встроенным каталогом `acr_floor_header_claims_test.go`: пересказ, разошедшийся
// с контрактом, краснеет там именем метода. Та сверка судит ТОЖДЕСТВО литералов
// и потому соглашается с любой редакцией контракта, которую шапка повторила
// верно, — в том числе с той, где чтение стало дороже мутации. Эта проба держит
// другое: ОТНОШЕНИЕ, о котором решено, а не число, которое сегодня стоит.
//
// ПОЧЕМУ УТВЕРЖДАЕТСЯ ОТНОШЕНИЕ, А НЕ ЧИСЛА. Литерал здесь был бы ещё одним
// местом об одном предмете и согласился бы с любой редакцией контракта: он
// повторяет то, что читает. Отношение — нет. Держатся две вещи, и каждая есть
// РЕШЕНИЕ, а не совпадение дня:
//
//	(1) ни один из четырёх не остаётся БЕЗ пола вовсе — иначе привилегированный
//	    путь проходит без церемонии, и объявление ступени становится инертным;
//	(2) чтение не гейтится СТРОЖЕ мутации, которой оно предшествует — иначе
//	    посмотреть, кто держит доступ, стоило бы дороже, чем его сменить, и
//	    оператор, разбирающий инцидент, упирался бы в ступень раньше нападающего.
//
// КАТАЛОГ БЕРЁТСЯ НАСТОЯЩИЙ. Подделка ответила бы то, что в неё вписали, и проба
// зеленела бы при требовании, снятом с контракта (тот же довод, что у
// `acr_floor_module_apply_test.go`). Способность предиката упасть доказана
// инъекцией ниже — обе оси, с законным близнецом.
package authzguard

import (
	"context"
	"fmt"
	"log/slog"
	"os"
	"sort"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/seed"
)

// clusterAdminReads / clusterAdminMutations — четыре метода круга, разведённые
// по тому, ЧТО они делают с доступом. Разведение и есть предмет решения: пол
// назначается не методу, а РОДУ действия.
var (
	clusterAdminReads = []string{
		"kaname.cloud.iam.v1.InternalClusterService/Get",
		"kaname.cloud.iam.v1.InternalClusterService/ListAdmins",
	}
	clusterAdminMutations = []string{
		"kaname.cloud.iam.v1.InternalClusterService/GrantAdmin",
		"kaname.cloud.iam.v1.InternalClusterService/RevokeAdmin",
	}
)

// clusterAdminFloorFindings — предикат обеих осей по ОДНОМУ каталогу. Вынесен
// функцией, а не оставлен в теле пробы: инъекция обязана звать ТОТ ЖЕ предикат,
// иначе она доказывает способность упасть у своей копии, а не у гейта.
func clusterAdminFloorFindings(lookup ACRRequirementLookup) []string {
	var out []string
	floors := map[string]string{}
	for _, fqn := range append(append([]string{}, clusterAdminReads...), clusterAdminMutations...) {
		v := lookup.RequiredACRMin(fqn)
		floors[fqn] = v
		// (1) пол существует вообще
		if v == "" || v == "0" {
			out = append(out, fmt.Sprintf(
				"%s: пола нет (%q) — привилегированный путь проходит без церемонии, "+
					"и объявление ступени инертно", fqn, v))
		}
	}
	// (2) чтение не строже мутации
	for _, r := range clusterAdminReads {
		for _, m := range clusterAdminMutations {
			if floors[r] > floors[m] {
				out = append(out, fmt.Sprintf(
					"чтение %s требует %q, мутация %s — %q: посмотреть, кто держит доступ, "+
						"стоит дороже, чем его сменить", r, floors[r], m, floors[m]))
			}
		}
	}
	sort.Strings(out)
	return out
}

// TestACRFloorClusterAdminFloorsComeFromTheContract — сам гейт.
func TestACRFloorClusterAdminFloorsComeFromTheContract(t *testing.T) {
	reg, err := seed.LoadPermissionRegistry(context.Background(),
		slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{Level: slog.LevelError})))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: каталог прав не прочитан: %v", err)
	}

	// Перепись печатает ФАКТИЧЕСКИЕ полы: «находок ноль» обязано быть отличимо
	// от «каталог ничего не вернул».
	for _, fqn := range append(append([]string{}, clusterAdminReads...), clusterAdminMutations...) {
		t.Logf("перепись: %s → required_acr_min=%q", fqn, reg.RequiredACRMin(fqn))
	}

	// Предпосылка: ступень применяется к этим методам ВООБЩЕ. Вне круга
	// гейт-фронтируемых пол не читается, и обе оси ниже были бы сказаны ни о чём.
	roster := map[string]struct{}{}
	for _, m := range GatewayFrontedInternalRPCs() {
		roster[m] = struct{}{}
	}
	for _, fqn := range append(append([]string{}, clusterAdminReads...), clusterAdminMutations...) {
		if _, ok := roster["/"+fqn]; !ok {
			t.Fatalf("%s нет в GatewayFrontedInternalRPCs(): ACRFloor применяет ступень ТОЛЬКО "+
				"к методам круга, поэтому объявленный контрактом пол инертен, а эта проба "+
				"беспредметна", fqn)
		}
	}

	if f := clusterAdminFloorFindings(reg); len(f) > 0 {
		t.Fatalf("пол ступени у InternalClusterService разошёлся с решением — %d находк(и):\n  %v\n\n"+
			"Решение: ни один из четырёх не остаётся без пола, и чтение не гейтится строже "+
			"мутации, которой оно предшествует. Числа объявляет контракт "+
			"(proto/kaname/cloud/iam/v1/internal_cluster_service.proto); шапка "+
			"`acr_floor.go` повторяет их под сверкой acr_floor_header_claims_test.go, "+
			"а отношение между ними держит только эта проба (kaname#131).", len(f), f)
	}
}

// TestACRFloorClusterAdminFloorPredicateCanFail — инъекция по КАЖДОЙ оси, с
// законным близнецом. Предикат, не краснеющий на дефекте, не удерживает ничего.
func TestACRFloorClusterAdminFloorPredicateCanFail(t *testing.T) {
	// Законный близнец — каталог, в точности повторяющий решение контракта.
	legal := fakeACRCatalog{
		clusterAdminReads[0]:     "1",
		clusterAdminReads[1]:     "1",
		clusterAdminMutations[0]: "2",
		clusterAdminMutations[1]: "2",
	}
	if f := clusterAdminFloorFindings(legal); len(f) != 0 {
		t.Fatalf("законное решение объявлено находкой — предикат ловит форму, а не "+
			"существо: %v", f)
	}

	t.Run("пол снят с чтения", func(t *testing.T) {
		bad := fakeACRCatalog{}
		for k, v := range legal {
			bad[k] = v
		}
		bad[clusterAdminReads[1]] = "" // ListAdmins остался без пола
		f := clusterAdminFloorFindings(bad)
		if len(f) != 1 {
			t.Fatalf("снятый пол находкой не стал: находок %d — %v", len(f), f)
		}
		if !contains(f[0], clusterAdminReads[1]) {
			t.Errorf("находка не называет координату: %q", f[0])
		}
	})

	t.Run("чтение строже мутации", func(t *testing.T) {
		bad := fakeACRCatalog{}
		for k, v := range legal {
			bad[k] = v
		}
		bad[clusterAdminReads[0]] = "3" // Get стал дороже, чем GrantAdmin
		f := clusterAdminFloorFindings(bad)
		if len(f) != 2 {
			t.Fatalf("перевёрнутое отношение находкой не стало: находок %d (ожидалось две, "+
				"по одной на каждую мутацию) — %v", len(f), f)
		}
		for _, one := range f {
			if !contains(one, clusterAdminReads[0]) {
				t.Errorf("находка не называет чтение: %q", one)
			}
		}
	})

	// Обе оси РАЗДЕЛЬНЫ: дефект одной не должен красить другую. Иначе инъекция
	// доказывала бы способность упасть у чего-то одного, а не у обеих.
	t.Run("оси не перекрывают друг друга", func(t *testing.T) {
		bad := fakeACRCatalog{}
		for k, v := range legal {
			bad[k] = v
		}
		bad[clusterAdminMutations[0]] = "" // пол снят с МУТАЦИИ
		f := clusterAdminFloorFindings(bad)
		if len(f) != 3 {
			t.Fatalf("ожидалось три находки (снятый пол мутации + оба чтения, ставшие "+
				"строже неё), получено %d: %v", len(f), f)
		}
	})
}

// contains — подстрока без импорта strings ради одной проверки.
func contains(s, sub string) bool {
	return len(sub) == 0 || (len(s) >= len(sub) && indexOf(s, sub) >= 0)
}

func indexOf(s, sub string) int {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return i
		}
	}
	return -1
}

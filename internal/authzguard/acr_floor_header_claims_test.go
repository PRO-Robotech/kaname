// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// acr_floor_header_claims_test.go — ШАПКА второго замка называет пол каждого
// метода так, как объявляет КОНТРАКТ (задача kaname#131).
//
// # Предмет
//
// Комментарий о рубеже безопасности, расходящийся с контрактом, — ловушка:
// следующий «починит» контракт под шапку либо шапку под контракт, не спросив,
// что решено. Шапка утверждала «Get, GrantAdmin,
// RevokeAdmin, ListAdmins … carry required_acr_min=2», тогда как контракт даёт
// «2» только мутациям, а чтениям — «1».
//
// # Чем держится
//
// Разбором ОБЪЯВЛЕННОГО: каждое утверждение шапки вида «InternalClusterService/…
// … required_acr_min=N» сверяется со встроенным каталогом прав — тем самым, из
// которого замок берёт пол на живом вызове. Шапка, не пересказывающая полов
// вовсе (только ссылка на контракт), законна: утверждений ноль, сверять нечего,
// и перепись это печатает.
//
// Способность упасть доказана инъекцией ниже: синтетическая шапка с неверным
// полом даёт находку с именем метода.
package authzguard

import (
	"encoding/json"
	"fmt"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// floorClaim — одно утверждение шапки о поле метода.
type floorClaim struct {
	Method string
	Floor  string
}

var (
	// floorValuePattern — утверждение о величине пола.
	floorValuePattern = regexp.MustCompile(`required_acr_min\s*=\s*"?(\d)"?`)
	// floorMethodPattern — метод либо перечень методов службы кластера.
	floorMethodPattern = regexp.MustCompile(`(?s)InternalClusterService/(\{[^}]*\}|[A-Za-z]+)`)
)

// headerFloorClaims — утверждения о полах в тексте шапки.
//
// Каждая величина пола относится ко ВСЕМ методам, названным между предыдущей
// величиной и ею: так читается и «{Get, GrantAdmin} … carry N», и «A and B
// carry N». Первая редакция брала один метод на величину и молча теряла второй —
// перепись «утверждений 2» при четырёх названных это и показала.
func headerFloorClaims(header string) []floorClaim {
	var out []floorClaim
	prev := 0
	for _, loc := range floorValuePattern.FindAllStringSubmatchIndex(header, -1) {
		window := header[prev:loc[0]]
		floor := header[loc[2]:loc[3]]
		prev = loc[1]
		for _, m := range floorMethodPattern.FindAllStringSubmatch(window, -1) {
			for _, n := range strings.Split(strings.Trim(m[1], "{}"), ",") {
				n = strings.TrimSpace(n)
				if n == "" {
					continue
				}
				out = append(out, floorClaim{Method: "kaname.cloud.iam.v1.InternalClusterService/" + n, Floor: floor})
			}
		}
	}
	return out
}

// catalogFloors — пол каждого метода из встроенного каталога прав.
func catalogFloors(t *testing.T) map[string]string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	root, err := platformtree.ModuleRootFrom(wd)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля: %v", err)
	}
	body, err := os.ReadFile(filepath.Join(root, "internal", "apps", "kaname", "seed", "embedded", "permission_catalog.json"))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: каталог прав не прочитан: %v", err)
	}
	var entries []struct {
		FQN            string `json:"fqn"`
		RequiredACRMin string `json:"required_acr_min"`
	}
	if err := json.Unmarshal(body, &entries); err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: каталог прав не разобран: %v", err)
	}
	out := map[string]string{}
	for _, e := range entries {
		out[e.FQN] = e.RequiredACRMin
	}
	if len(out) == 0 {
		t.Fatal("проверка НЕ ИСПОЛНЯЛАСЬ: каталог прав пуст")
	}
	return out
}

// mismatchedClaims — утверждения, расходящиеся с каталогом; метод, которого в
// каталоге нет, — тоже расхождение: шапка называет то, чего контракт не знает.
func mismatchedClaims(claims []floorClaim, floors map[string]string) []string {
	var out []string
	for _, c := range claims {
		got, ok := floors[c.Method]
		switch {
		case !ok:
			out = append(out, fmt.Sprintf("%s: шапка называет пол %q, а метода в каталоге нет", c.Method, c.Floor))
		case got != c.Floor:
			out = append(out, fmt.Sprintf("%s: шапка называет пол %q, контракт объявляет %q", c.Method, c.Floor, got))
		}
	}
	return out
}

func TestACRFloorHeaderNamesTheFloorsAsTheContractDoes(t *testing.T) {
	t.Parallel()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "acr_floor.go", nil, parser.ParseComments|parser.PackageClauseOnly)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	var header strings.Builder
	for _, cg := range f.Comments {
		if cg.Pos() < f.Package {
			header.WriteString(cg.Text())
		}
	}
	if header.Len() == 0 {
		t.Fatal("проверка НЕ ИСПОЛНЯЛАСЬ: у acr_floor.go нет шапки")
	}
	claims := headerFloorClaims(header.String())
	floors := catalogFloors(t)
	mismatches := mismatchedClaims(claims, floors)
	t.Logf("перепись: утверждений шапки о полах %d, записей каталога %d, расхождений %d", len(claims), len(floors), len(mismatches))
	for _, m := range mismatches {
		t.Error(m)
	}
}

// Инъекция: шапка с неверным полом краснеет именем метода; шапка, называющая
// полы как контракт, молчит; шапка без утверждений — ноль сверок, молчит.
func TestACRFloorHeaderClaimsInjection(t *testing.T) {
	t.Parallel()
	floors := map[string]string{
		"kaname.cloud.iam.v1.InternalClusterService/Get":        "1",
		"kaname.cloud.iam.v1.InternalClusterService/GrantAdmin": "2",
	}
	wrong := headerFloorClaims("notably InternalClusterService/{Get,\nGrantAdmin}, which already carry required_acr_min=2")
	if len(wrong) != 2 {
		t.Fatalf("утверждения из фигурных скобок с переносом не прочитаны: %v", wrong)
	}
	if m := mismatchedClaims(wrong, floors); len(m) != 1 || !strings.Contains(m[0], "/Get") {
		t.Fatalf("неверный пол чтения не назван именем метода: %v", m)
	}
	right := headerFloorClaims("GrantAdmin/RevokeAdmin carry required_acr_min=\"2\" — InternalClusterService/GrantAdmin at required_acr_min=2, InternalClusterService/Get at required_acr_min=1.")
	if len(right) != 2 {
		t.Fatalf("две одиночные формы не прочитаны: %v", right)
	}
	// Форма «A and B carry N»: оба метода получают величину, второй не теряется.
	pair := headerFloorClaims("InternalClusterService/GrantAdmin and\nInternalClusterService/RevokeAdmin carry required_acr_min=2 — and InternalClusterService/Get carries required_acr_min=1.")
	if len(pair) != 3 || pair[1].Method != "kaname.cloud.iam.v1.InternalClusterService/RevokeAdmin" || pair[1].Floor != "2" || pair[2].Floor != "1" {
		t.Fatalf("форма «A and B carry N» прочитана как %v", pair)
	}
	if m := mismatchedClaims(right, floors); len(m) != 0 {
		t.Fatalf("верная шапка объявлена расхождением: %v", m)
	}
	if none := headerFloorClaims("The floor reads required_acr_min from the catalog and restates nothing."); len(none) != 0 {
		t.Fatalf("шапка без методов дала утверждения: %v", none)
	}
}

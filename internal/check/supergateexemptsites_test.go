// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// supergateexemptsites_test.go — держатель переписи мест надзора (NTF1-F12, гейт;
// §1.11 приёмки NTF-1). Годок гейта — `supergate_exempt_sites.go`.
//
// Проба на дереве печатает объём осмотренного и число мест по классам; пустой
// обход и ведомость без мест — отказ, а не зелёное. Инъекции идут в обе
// стороны: каждый дефект меняет ровно один факт против дерева как есть и
// обязан дать ровно одну находку с координатой; законный близнец той же формы
// (одноимённая локальная функция, литерал со строкой вне перечня) — молчание.

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const superGateLedgerPath = "testdata/supergate_exempt_sites.ledger"

func loadSuperGateLedger(t *testing.T) *check.SuperGateLedger {
	t.Helper()
	f, err := os.Open(superGateLedgerPath)
	if err != nil {
		t.Fatalf("ведомость классов не читается: %v", err)
	}
	defer func() { _ = f.Close() }()
	led, err := check.ParseSuperGateLedger(f)
	if err != nil {
		t.Fatalf("%v", err)
	}
	return led
}

func scanSuperGate(t *testing.T, led *check.SuperGateLedger, overlay check.SuperGateOverlay) *check.SuperGateReport {
	t.Helper()
	root := platformtree.Require(t)
	rep, err := check.ScanSuperGateSites(context.Background(), root, led, overlay)
	if err != nil {
		t.Fatalf("перепись надзора НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if rep.Files == 0 || len(rep.Uses) == 0 {
		t.Fatalf("предпосылка нарушена: файлов %d, употреблений семейства %d — пустой обход вердиктом не является",
			rep.Files, len(rep.Uses))
	}
	return rep
}

// TestSuperGateExemptSitesMatchTheLedger — дерево как есть.
func TestSuperGateExemptSitesMatchTheLedger(t *testing.T) {
	led := loadSuperGateLedger(t)
	rep := scanSuperGate(t, led, nil)

	t.Logf("осмотрено: пакетов=%d, файлов Go=%d; перечень %v объявлен в %s; членов семейства=%d, "+
		"строк ведомости=%d, употреблений=%d; мест по классам: door=%d fixed=%d definition=%d plan=%d",
		rep.Packages, rep.Files, rep.SetTypes, rep.DeclaredSet, len(led.Family), len(led.Rows), len(rep.Uses),
		rep.PlacesBy["door"], rep.PlacesBy["fixed"], rep.PlacesBy["definition"], rep.PlacesBy["plan"])

	for _, f := range rep.Findings {
		t.Errorf("%s", f)
	}
	if rep.PlacesBy[check.SuperGateClassDoor] == 0 {
		t.Fatal("предпосылка нарушена: ни одного места класса «обобщённая дверь» — судить предикат не на чем")
	}
}

// requireOneFinding — инъекция дала РОВНО одну находку, в названном файле и с
// названной причиной.
func requireOneFinding(t *testing.T, rep *check.SuperGateReport, file, reason string) {
	t.Helper()
	if len(rep.Findings) != 1 {
		for _, f := range rep.Findings {
			t.Logf("находка: %s", f)
		}
		t.Fatalf("инъекция дала %d находок, ожидалась ровно одна (%s в %s)", len(rep.Findings), reason, file)
	}
	f := rep.Findings[0]
	if !strings.HasPrefix(f.Pos, file) || !strings.Contains(f.Reason, reason) {
		t.Fatalf("находка %q, ожидалась причина %q с координатой в %s", f, reason, file)
	}
}

func readTreeFile(t *testing.T, rel string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(platformtree.Require(t), filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("%v", err)
	}
	return string(b)
}

const (
	modulePath     = "github.com/PRO-Robotech/kaname"
	servicePkg     = modulePath + "/internal/service"
	userPkg        = modulePath + "/internal/apps/kaname/api/user"
	authzguardPkg  = modulePath + "/internal/authzguard"
	injectedFile   = "zz_supergate_injected.go"
	injectedHeader = "// Copyright (c) PRO-Robotech\n// SPDX-License-Identifier: AGPL-3.0-or-later\n\n"
)

// TestSuperGateExemptSitesInjection_DoorWithoutPredicateIsFound — снят предикат
// перед надзором в `verdict` (Д-2): место осталось, предиката над ним нет.
func TestSuperGateExemptSitesInjection_DoorWithoutPredicateIsFound(t *testing.T) {
	const guard = "\tif authzguard.SuperGateExempt(objectType) {\n\t\treturn false, nil\n\t}\n\tadmin, aerr := s.isClusterAdmin(ctx, caMemo, subject)\n\tif aerr != nil {\n\t\treturn false, superGateUnavailable(aerr)\n\t}\n\treturn admin, nil\n"
	src := readTreeFile(t, "internal/service/authorize_service.go")
	if strings.Count(src, guard) != 1 {
		t.Fatalf("предпосылка инъекции: предикат перед надзором в verdict встречается %d раз, ожидался 1", strings.Count(src, guard))
	}
	injected := strings.Replace(src, guard,
		"\t_ = authzguard.SuperGateExempt(objectType)\n\tadmin, aerr := s.isClusterAdmin(ctx, caMemo, subject)\n\tif aerr != nil {\n\t\treturn false, superGateUnavailable(aerr)\n\t}\n\treturn admin, nil\n", 1)
	rep := scanSuperGate(t, loadSuperGateLedger(t), check.SuperGateOverlay{
		servicePkg: {"authorize_service.go": injected},
	})
	requireOneFinding(t, rep, "internal/service/authorize_service.go", "не стоит под предикатом")
}

// TestSuperGateExemptSitesInjection_PlaceOutsideTheLedgerIsFound — новое место
// надзора, которого ведомость не называет.
func TestSuperGateExemptSitesInjection_PlaceOutsideTheLedgerIsFound(t *testing.T) {
	rep := scanSuperGate(t, loadSuperGateLedger(t), check.SuperGateOverlay{
		userPkg: {injectedFile: injectedHeader + "package user\n\nimport (\n\t\"context\"\n\n\t\"" + authzguardPkg + "\"\n)\n\n" +
			"func injectedSuperGate(ctx context.Context, c authzguard.RelationChecker) (bool, error) {\n\treturn authzguard.IsClusterAdminE(ctx, c)\n}\n"},
	})
	requireOneFinding(t, rep, "internal/apps/kaname/api/user/"+injectedFile, "вне ведомости")
}

// TestSuperGateExemptSitesInjection_SecondDeclarationIsFound — перечень
// объявлен второй раз.
func TestSuperGateExemptSitesInjection_SecondDeclarationIsFound(t *testing.T) {
	rep := scanSuperGate(t, loadSuperGateLedger(t), check.SuperGateOverlay{
		userPkg: {injectedFile: injectedHeader + "package user\n\nvar injectedExempt = map[string]bool{\"notification_feed\": true}\n"},
	})
	requireOneFinding(t, rep, "internal/apps/kaname/api/user/"+injectedFile, "вторая декларация")
}

// TestSuperGateExemptSitesInjection_LedgerRowWithoutPlaceIsFound — строка
// ведомости, которой в дереве нечего называть.
func TestSuperGateExemptSitesInjection_LedgerRowWithoutPlaceIsFound(t *testing.T) {
	led := loadSuperGateLedger(t)
	led.Rows = append(led.Rows, check.SuperGateLedgerRow{
		Line: 9999, Class: "fixed", Enclosing: "internal/apps/kaname/api/user.injectedGone", Member: "IsClusterAdminE", Count: 1,
	})
	rep := scanSuperGate(t, led, nil)
	requireOneFinding(t, rep, "ведомость, строка 9999", "без места")
}

// TestSuperGateExemptSitesInjection_LawfulTwinsAreSilent — та же форма без
// предмета: одноимённая функция пакета (не член семейства по идентичности) и
// составной литерал со строкой вне перечня.
func TestSuperGateExemptSitesInjection_LawfulTwinsAreSilent(t *testing.T) {
	rep := scanSuperGate(t, loadSuperGateLedger(t), check.SuperGateOverlay{
		userPkg: {injectedFile: injectedHeader + "package user\n\n" +
			"// IsClusterAdminE — одноимённая функция пакета user: не член семейства.\n" +
			"func IsClusterAdminE() bool { return false }\n\n" +
			"var injectedTwin = map[string]bool{\"notification_feed_x\": IsClusterAdminE()}\n"},
	})
	for _, f := range rep.Findings {
		t.Errorf("законный близнец дал находку: %s", f)
	}
}

// TestSuperGateExemptSitesInjection_EveryGuardFormIsJudged — каждая форма охраны,
// которой стоят места в дереве, снимается по одной; и предикат, ослабленный
// конъюнкцией, охраной не засчитывается. Каждая инъекция — ровно одна находка
// в файле своего места.
func TestSuperGateExemptSitesInjection_EveryGuardFormIsJudged(t *testing.T) {
	for _, tc := range []struct {
		name, pkg, file, from, to string
	}{
		{
			name: "Д-5: предшествующий if с continue снят",
			pkg:  servicePkg, file: "internal/service/authorize_service.go",
			from: "\t\tif authzguard.SuperGateExempt(run.objectType) {\n\t\t\tdenied = append(denied, i)\n\t\t\tdeniedIDs = append(deniedIDs, plans[i].objectID)\n\t\t\tcontinue\n\t\t}\n",
			to:   "\t\t_ = authzguard.SuperGateExempt(run.objectType)\n",
		},
		{
			name: "Д-7: надзор вынесен из тела if !предикат",
			pkg:  authzguardPkg, file: "internal/authzguard/read_authz.go",
			from: "\tif !SuperGateExempt(objectType) {\n\t\t// Cluster-admin short-circuit (D-9): a cluster-admin reads ANY object even\n\t\t// without a per-object tuple.\n\t\tadmin, adminErr = SubjectIsClusterAdminPlainE(ctx, checker, subject)\n\t\tif admin {\n\t\t\treturn true, nil\n\t\t}\n\t}\n",
			to:   "\t_ = SuperGateExempt(objectType)\n\tadmin, adminErr = SubjectIsClusterAdminPlainE(ctx, checker, subject)\n\tif admin {\n\t\treturn true, nil\n\t}\n",
		},
		{
			name: "Д-6: предикат ослаблен конъюнкцией",
			pkg:  authzguardPkg, file: "internal/authzguard/own_door.go",
			from: "\tobjectType, _, _ := SplitModelObject(object)\n\tif SuperGateExempt(objectType) {\n\t\treturn false, nil\n\t}\n",
			to:   "\tobjectType, parsed, _ := SplitModelObject(object)\n\tif parsed == \"\" && SuperGateExempt(objectType) {\n\t\treturn false, nil\n\t}\n",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			src := readTreeFile(t, tc.file)
			if n := strings.Count(src, tc.from); n != 1 {
				t.Fatalf("предпосылка инъекции: охрана встречается %d раз в %s, ожидался 1", n, tc.file)
			}
			rep := scanSuperGate(t, loadSuperGateLedger(t), check.SuperGateOverlay{
				tc.pkg: {filepath.Base(tc.file): strings.Replace(src, tc.from, tc.to, 1)},
			})
			requireOneFinding(t, rep, tc.file, "не стоит под предикатом")
		})
	}
}

// TestSuperGateLedgerParse_RefusesWhatItCannotRead — ведомость, которую гейт не
// понимает, — отказ разбора, а не пропущенная строка.
func TestSuperGateLedgerParse_RefusesWhatItCannotRead(t *testing.T) {
	head := "predicate p.F\nset p.v\nfamily p.G\n"
	for name, body := range map[string]string{
		"класс вне словаря": head + "site comment a.F G 1\n",
		"место дважды":      head + "site door a.F G 1\nsite plan a.F G 1\n",
		"число не число":    head + "site door a.F G x\n",
		"вид строки":        head + "sites door a.F G 1\n",
		"нет предиката":     "set p.v\nfamily p.G\n",
	} {
		if _, err := check.ParseSuperGateLedger(strings.NewReader(body)); err == nil {
			t.Errorf("%s: ведомость принята", name)
		}
	}
	if _, err := check.ParseSuperGateLedger(strings.NewReader(head + "site door a.F G 2 Д-1\n")); err != nil {
		t.Errorf("законная ведомость отвергнута: %v", err)
	}
}

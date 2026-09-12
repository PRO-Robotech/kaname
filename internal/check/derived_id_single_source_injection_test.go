// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// derived_id_single_source_injection_test.go — доказательство способности
// гейта упасть И смолчать.
//
// Инъекция подаёт настоящий вход — тот, из которого гейт и выведен в
// монорепо: до сведения объявлений деривации в прод-дереве было ДВА
// (`bootstrap_token/ids.go` и `authzguard/fgaproxy.go`). Законный близнец —
// та же форма записи там, где она законна: в пробе и в тексте комментария.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// derivedIDInjectionSrc — файл, объявляющий деривацию своей рукой. Та форма,
// которой были `bootstrap_token/ids.go` и `authzguard/fgaproxy.go` до
// сведения на монорепо.
const derivedIDInjectionSrc = `package guard

import (
	"crypto/md5"
	"encoding/hex"
)

func serviceAccountID(svc string) string {
	sum := md5.Sum([]byte("kacho-" + svc))
	return "sva" + hex.EncodeToString(sum[:])[:17]
}
`

// derivedIDTwinSrc — законный близнец: путь назван в КОММЕНТАРИИ и в СТРОКЕ, а
// импорта нет. Гейт судит узел разбора, а не подстроку, поэтому обязан
// молчать — иначе он краснел бы на собственном объяснении.
const derivedIDTwinSrc = `package guard

// Идентификатор считает domain.DerivedIDSuffix; "crypto/md5" здесь только назван.
const why = "формула живёт в crypto/md5 и объявлена один раз"

func id() string { return why }
`

// TestDerivedIDGateRedsOnASecondDeclaration — инъекция обязана краснеть И
// называть координату.
func TestDerivedIDGateRedsOnASecondDeclaration(t *testing.T) {
	const rel = "internal/authzguard/fgaproxy.go"
	sites, census, err := check.ScanDerivedIDDeclarations(rel, []byte(derivedIDInjectionSrc))
	if err != nil {
		t.Fatalf("разбор инъекции: %v", err)
	}
	if census.Imports == 0 {
		t.Fatalf("перепись инъекции пуста — разбор ничего не прочитал, и его молчание "+
			"сказано ни о чём: %+v", census)
	}
	findings := derivedIDFindings(sites, "internal/domain/derived_id.go")
	if len(findings) != 1 {
		t.Fatalf("второе объявление деривации НЕ стало находкой: находок %d при переписи %+v\n"+
			"Гейт, не краснеющий на дефекте, из которого он выведен, не удерживает ничего",
			len(findings), census)
	}
	if !strings.Contains(findings[0], rel) {
		t.Errorf("находка не называет координату: %q", findings[0])
	}
	if !strings.Contains(findings[0], check.DerivedIDPackage) {
		t.Errorf("находка не называет предмет (%s): %q", check.DerivedIDPackage, findings[0])
	}
}

// TestDerivedIDGateStaysSilentOnLegalTwins — законные близнецы, каждый своей
// осью: (а) упоминание пути в комментарии и строке; (б) тот же импорт в
// ПРОБЕ; (в) файл самого дома.
func TestDerivedIDGateStaysSilentOnLegalTwins(t *testing.T) {
	t.Run("путь назван в тексте, импорта нет", func(t *testing.T) {
		sites, census, err := check.ScanDerivedIDDeclarations("internal/authzguard/fgaproxy.go",
			[]byte(derivedIDTwinSrc))
		if err != nil {
			t.Fatalf("разбор близнеца: %v", err)
		}
		if census.Imports != 0 {
			t.Fatalf("близнец импортов не несёт, а перепись насчитала %d", census.Imports)
		}
		if f := derivedIDFindings(sites, "internal/domain/derived_id.go"); len(f) != 0 {
			t.Fatalf("гейт судит подстроку, а не узел разбора: находок %d на файле "+
				"БЕЗ импорта — он краснел бы на собственном объяснении: %v", len(f), f)
		}
	})

	t.Run("тот же импорт в пробе", func(t *testing.T) {
		const rel = "internal/authzguard/fgaproxy_test.go"
		if derivedIDWalkable(rel) {
			t.Fatalf("отбор гейта берёт пробу %s — тогда законная сверка деривации "+
				"внутри пробы стала бы находкой", rel)
		}
		// Живой контроль: такая проба в дереве ЕСТЬ, и отбор обязан её пропускать
		// именно потому, что предмет там законен.
		if !derivedIDWalkable("internal/authzguard/fgaproxy.go") {
			t.Fatalf("отбор гейта не берёт прод-файл — тогда осматривать нечего")
		}
	})

	t.Run("сам дом деривации", func(t *testing.T) {
		const owner = "internal/domain/derived_id.go"
		sites, _, err := check.ScanDerivedIDDeclarations(owner, []byte(derivedIDInjectionSrc))
		if err != nil {
			t.Fatalf("разбор дома: %v", err)
		}
		if len(sites) == 0 {
			t.Fatalf("импорт в доме не опознан — тогда предпосылка «дом существует» " +
				"не может быть проверена")
		}
		if f := derivedIDFindings(sites, owner); len(f) != 0 {
			t.Fatalf("единственный дом объявлен находкой: %v", f)
		}
	})
}

// TestDerivedIDScannerKnowsEveryImportForm — распознаватель обязан знать ВСЕ
// законные формы записи предмета. Форма, которой он не знает, даёт МОЛЧАНИЕ, а
// не находку: объявление уезжает вне наблюдения.
func TestDerivedIDScannerKnowsEveryImportForm(t *testing.T) {
	const src = `package p

import (
	"crypto/md5"
	md5b "crypto/md5"
	. "crypto/md5"
	_ "crypto/md5"
	"strings"
)
`
	sites, census, err := check.ScanDerivedIDDeclarations("internal/x/a.go", []byte(src))
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if census.Imports != 5 {
		t.Fatalf("прочитано %d объявлений импорта из пяти", census.Imports)
	}
	got := map[string]int{}
	for _, s := range sites {
		got[s.Form]++
	}
	for _, form := range []string{"plain", "alias", "dot", "blank"} {
		if got[form] != 1 {
			t.Errorf("форма импорта %q не опознана (найдено %d) — объявление в этой форме "+
				"уехало бы вне наблюдения: %v", form, got[form], got)
		}
	}
	if len(sites) != 4 {
		t.Errorf("опознано %d импортов из четырёх: %v", len(sites), sites)
	}
	_ = md5bUnusedGuard
}

// md5bUnusedGuard — имя существует, чтобы синтетика выше читалась как код, а
// не как строка без предмета.
const md5bUnusedGuard = "crypto/md5"

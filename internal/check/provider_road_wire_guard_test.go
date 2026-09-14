// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_road_wire_guard_test.go — КЛИЕНТ БЕЗ ДОРОГИ ОТКАЗЫВАЕТ ПРЕЖДЕ, ЧЕМ
// ТРОНЕТ ПРОВОД: каждый метод, читающий адрес, спрашивает стража несобранной
// дороги — и спрашивает ДО чтения (задачи `kacho#2573`, `kaname#21`).
//
// # ЧТО ЭТОТ ГЕЙТ ДЕРЖИТ
//
// Предикат снятия `kacho#2573`, п. 2: «потребитель, чей контур переведён,
// получает ОТСТАВЛЕННУЮ реализацию, отказывающую названной причиной, а не
// клиента к адресу, по которому никто не пойдёт».
//
// Сегодня обещание исполняется: методов, уходящих на провод, три, и все три
// спрашивают стража. Но держится это ВНИМАНИЕМ — у типа нет ничего, что мешало
// бы завести четвёртый метод без стража. Такой метод собрал бы запрос на ПУСТОМ
// адресе, и произошло бы это молча: тип тот же, подпись та же, сборка проходит,
// ни одна существующая проба не краснеет.
//
// # ГЕЙТ ЗЕЛЁН СЕГОДНЯ — И ЭТО НЕ ДОВОД ПРОТИВ НЕГО
//
// Он требует свойство от кода, КОТОРОГО ЕЩЁ НЕТ. Способность упасть доказана не
// находкой в дереве, а инъекцией: соседний файл вносит дефект каждой оси и
// ставит рядом законного близнеца.
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

const (
	// providerRoadClientType — тип клиента административной дороги.
	providerRoadClientType = "HydraAdminClient"
	// providerRoadAddressField — поле адреса. Его пустота и есть признак
	// несобранной дороги, и страж судит по нему же.
	providerRoadAddressField = "BaseURL"
	// providerRoadGuardName — страж несобранной дороги.
	providerRoadGuardName = "roadIsBuilt"
	// providerRoadWireFloor — сколько методов, уходящих на провод, обязано
	// найтись. Ноль означал бы, что предмет переехал, а гейт стережёт пустоту.
	providerRoadWireFloor = 3
)

// providerRoadGuardExempt — методам, которым касание адреса разрешено без
// стража. Перечень ЗАКРЫТ и мал by construction: сам страж по адресу и судит,
// поэтому спросить себя он не может.
var providerRoadGuardExempt = map[string]bool{
	providerRoadGuardName: true,
}

type providerRoadWireScan struct {
	Methods []check.ProviderRoadWireMethod
	Parsed  int
	Census  check.ProviderRoadWireCensus
}

func scanProviderRoadWireTree(t *testing.T) providerRoadWireScan {
	t.Helper()
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}
	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("состав дерева: %v — вердикт беспредметен", err)
	}

	var out providerRoadWireScan
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if strings.HasSuffix(rel, "_test.go") {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь из состава дерева этого модуля
		if rderr != nil {
			continue
		}
		out.Parsed++
		ms, c, serr := check.ScanProviderRoadWireMethods(rel, src,
			providerRoadClientType, providerRoadAddressField, providerRoadGuardName,
			providerRoadGuardExempt)
		if serr != nil {
			t.Fatalf("разбор %s: %v", rel, serr)
		}
		out.Methods = append(out.Methods, ms...)
		out.Census.Methods += c.Methods
		out.Census.AddressTouching += c.AddressTouching
		out.Census.GuardCalls += c.GuardCalls
	}
	return out
}

// TestProviderRoadClientRefusesBeforeItTouchesTheWire — сам гейт.
func TestProviderRoadClientRefusesBeforeItTouchesTheWire(t *testing.T) {
	t.Parallel()
	scan := scanProviderRoadWireTree(t)

	unguarded := check.UnguardedProviderRoadWireMethods(scan.Methods)

	t.Logf("перепись: прод-файлов Go разобрано %d; методов %s осмотрено %d, из них "+
		"трогают адрес %s — %d; вызовов стража %s осмотрено %d; не спросивших стража "+
		"до касания — %d",
		scan.Parsed, providerRoadClientType, scan.Census.Methods,
		providerRoadAddressField, scan.Census.AddressTouching,
		providerRoadGuardName, scan.Census.GuardCalls, len(unguarded))

	if scan.Parsed < providerAddressCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d прод-файлов при пороге %d — "+
			"вердикт беспредметен", scan.Parsed, providerAddressCensusFloor)
	}
	if scan.Census.Methods == 0 {
		t.Fatalf("методов типа %s не найдено НИ ОДНОГО на %d файлах: тип переименован "+
			"или переехал, и гейт стережёт координату, которой больше нет",
			providerRoadClientType, scan.Parsed)
	}
	if scan.Census.AddressTouching < providerRoadWireFloor {
		t.Fatalf("методов, уходящих на провод, найдено %d при пороге %d: признак "+
			"«трогает %s» перестал их узнавать — «не спросивших стража ноль» тогда "+
			"означает «не осмотрено ничего»",
			scan.Census.AddressTouching, providerRoadWireFloor, providerRoadAddressField)
	}

	if len(unguarded) > 0 {
		var where []string
		for _, m := range unguarded {
			reason := fmt.Sprintf("страж %s не спрошен вовсе", providerRoadGuardName)
			if m.GuardLine > 0 {
				reason = fmt.Sprintf("страж спрошен на строке %d — ПОСЛЕ касания адреса",
					m.GuardLine)
			}
			where = append(where, fmt.Sprintf("%s  %s() — адрес на строке %d, %s",
				m.File, m.Method, m.AddressLine, reason))
		}
		sort.Strings(where)
		t.Fatalf("метод(ы) клиента дороги уходят на провод, не спросив стража, — %d:\n  %s\n\n"+
			"На посадке без внешнего поставщика строитель отдаёт клиента БЕЗ адреса, и "+
			"обещание его такое: всякий вызов получает ИМЕНОВАННЫЙ отказ, опознаваемый "+
			"errors.Is, а не звонок в никуда. Метод, не спросивший стража, собирает запрос "+
			"на пустом адресе — молча: тип тот же, подпись та же, сборка проходит.\n"+
			"Починка: первым оператором тела — `if !c.%s() { return c.refuseAbsentRoad(\"<что "+
			"делали>\") }`.",
			len(unguarded), strings.Join(where, "\n  "), providerRoadGuardName)
	}
}

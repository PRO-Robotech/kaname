// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_road_address_single_reader_test.go — АДРЕС АДМИНИСТРАТИВНОЙ ДОРОГИ
// РЕЗОЛВИТСЯ В ОДНОМ МЕСТЕ: у строителя дороги, и больше нигде
// (задачи `kacho#2573`, `kaname#21`).
//
// # ЧТО ЭТОТ ГЕЙТ ДЕРЖИТ, А ЧТО УЖЕ ДЕРЖИТСЯ В ДРУГОМ МЕСТЕ
//
// «Полоса спрашивается ДО построения клиента» держит сам строитель: первым его
// оператором стоит `providerAdminHopIsBuilt`, и на посадке без внешнего
// поставщика он отдаёт отставленного клиента без адреса. Это проверено там же —
// `cmd/kaname/lane_provider_road_wiring_test.go`.
//
// Здесь — ВТОРОЙ конец того же предмета: что кроме строителя адрес не резолвит
// НИКТО. Пока резолвит кто-то ещё, выбор полосы, сделанный строителем, на второе
// чтение не распространяется: резолвер пустого не возвращает никогда, поэтому
// второй читатель получает адрес, выведенный из доменного имени, — и получает
// его на посадке, у которой внешнего поставщика нет вовсе.
//
// # ЦЕНА ИЗМЕРЕНА, А НЕ ПРЕДПОЛОЖЕНА
//
// Второй читатель в дереве БЫЛ, и держал он перепись старта: `buildSAKeysHandler`
// резолвил адрес отдельной строкой и печатал его в `sa_keys wired`. На посадке
// `own` оператор читал в переписи административный адрес, по которому процесс не
// пойдёт ни разу, — то есть самоотчёт называл настроенной дорогу, которой нет.
// Ровно тот класс, ради которого заведён сам самоотчёт о посадке: доложенное
// разошлось со сделанным.
//
// # ПОЧЕМУ ГЕЙТ НА ЧИТАТЕЛЯ, А НЕ НА «БЕЗУСЛОВНЫЙ ВЫЗОВ СТРОИТЕЛЯ»
//
// Предикат снятия `kacho#2573` называет числом безусловные вызовы строителя.
// Гейт на них требовал бы условия У КАЖДОГО ПОТРЕБИТЕЛЯ — то есть четырёх копий
// одного решения, которые разойдутся молча, и разойдётся та, которую правили
// последней. Решение о полосе живёт в строителе в ЕДИНСТВЕННОМ экземпляре, и это
// верная форма; неверно было бы второе чтение адреса мимо него — оно здесь и
// судится.
//
// # ЕДИНИЦА СЧЁТА У ТОГО ПРЕДИКАТА НАЗВАНА НЕВЕРНО, И ЭТО НЕ ПРИДИРКА
//
// Предикат тела задачи — `git grep -c 'mustProviderAdminClient(' -- cmd/kaname
// ':!*_test.go'` — даёт ШЕСТЬ при четырёх вызовах: он считает ещё объявление
// самой функции и строку комментария, которая ЭТОТ ЖЕ предикат и печатает. То
// есть предикат считает СОБСТВЕННОЕ ОБЪЯСНЕНИЕ — тот самый класс, который
// проверка обязана исключать у себя, применённый не к гейту, а к человеку.
//
// Отсюда форма здесь: разбор судит по УЗЛУ ВЫЗОВА, а счёт ведётся в переписи,
// которую печатает сам гейт. Проза о предмете под него не подпадает by
// construction — и это проверено инъекцией (ось «имя в комментарии и строке»).
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
	// providerAddressResolver — резолвер, который пустого НЕ возвращает.
	providerAddressResolver = "ResolveHydraAdminURL"
	// providerAddressTwin — безопасный близнец: пуст, когда никто не объявлял.
	providerAddressTwin = "DeclaredHydraAdminURL"
	// providerAddressOwner — единственная функция, которой резолвер разрешён:
	// строитель административной дороги. Он же и спрашивает полосу.
	providerAddressOwner = "mustProviderAdminClient"
	// providerAddressCensusFloor — нижняя граница переписи. Обход, принёсший
	// меньше, предметом не обладает, и «находок ноль» означало бы «прочитано
	// ноль».
	providerAddressCensusFloor = 300
)

type providerAddressScan struct {
	Reads  []check.ProviderAddressRead
	Parsed int
	Census check.ProviderAddressCensus
}

func scanProviderAddressTree(t *testing.T) providerAddressScan {
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

	var out providerAddressScan
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
		reads, c, serr := check.ScanProviderAddressReads(rel, src,
			providerAddressResolver, providerAddressTwin)
		if serr != nil {
			t.Fatalf("разбор %s: %v", rel, serr)
		}
		out.Reads = append(out.Reads, reads...)
		out.Census.Calls += c.Calls
		out.Census.ResolverReads += c.ResolverReads
		out.Census.TwinReads += c.TwinReads
	}
	return out
}

// TestProviderRoadAddressIsResolvedOnlyByItsBuilder — сам гейт.
func TestProviderRoadAddressIsResolvedOnlyByItsBuilder(t *testing.T) {
	t.Parallel()
	scan := scanProviderAddressTree(t)

	atOwner, outside := check.SplitProviderAddressReads(scan.Reads, providerAddressOwner)

	t.Logf("перепись: прод-файлов Go разобрано %d, вызовов осмотрено %d; чтений "+
		"резолвера %s найдено %d — у строителя %d, вне его %d; чтений безопасного "+
		"близнеца %s — %d",
		scan.Parsed, scan.Census.Calls, providerAddressResolver,
		len(scan.Reads), len(atOwner), len(outside),
		providerAddressTwin, scan.Census.TwinReads)

	// Премиса обхода — ВЫЗОВ, а не четыре ветки в теле пробы: так каждая из них
	// доказывается исполнением (инъекция подаёт ей синтетический вход), а не
	// читается глазами.
	if err := check.ProviderAddressPremise(scan.Parsed, providerAddressCensusFloor,
		scan.Census, len(atOwner), len(scan.Reads),
		providerAddressResolver, providerAddressTwin, providerAddressOwner); err != nil {
		t.Fatalf("вердикт беспредметен: %v", err)
	}

	if len(outside) > 0 {
		var where []string
		for _, r := range outside {
			where = append(where, fmt.Sprintf("%s:%d  %s()", r.File, r.Line, r.Func))
		}
		sort.Strings(where)
		t.Fatalf("адрес административной дороги резолвится ВНЕ строителя %s — %d место(а):\n  %s\n\n"+
			"%s пустого не возвращает НИКОГДА: при незаданной ручке он выводит адрес из "+
			"доменного имени. Поэтому второй читатель получает непустой адрес и на посадке, "+
			"у которой внешнего поставщика нет вовсе, — выбор полосы, сделанный строителем, "+
			"на это чтение не распространяется.\n"+
			"Исходов два: взять значение у построенного клиента (он несёт адрес ровно тогда, "+
			"когда дорога построена) либо читать безопасного близнеца %s, который пуст, когда "+
			"никто ничего не объявлял.",
			providerAddressOwner, len(outside), strings.Join(where, "\n  "),
			providerAddressResolver, providerAddressTwin)
	}
}

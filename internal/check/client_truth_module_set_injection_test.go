// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_truth_module_set_injection_test.go — доказательство, что гейт перечня
// модулей СПОСОБЕН упасть и СПОСОБЕН смолчать (задача #17, семейство
// `clienttruth_iam_moduleset`).
//
// Гейт зелен на сегодняшнем дереве, и это не доказывает ничего: зелёным он был
// бы и с предикатом, который ничего не ищет. Поэтому его извлечение прогоняется
// здесь на синтетике, где ответ известен заранее.
//
// Инъекция зовёт ТУ ЖЕ функцию, что и гейт, а не свою копию: копии расходятся
// молча, и расходится та, которую не прогоняют.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// injModuleSetPkg — синтетический пакет: объявление разнесено по ДВУМ файлам,
// причём имена модулей стоят и в комментарии соседнего файла.
//
// Комментарий здесь несущий, а не декорация: он воспроизводит ровно ту ловушку,
// на которой предикат по подстроке краснел бы на собственном объяснении
// таблицы. Гейт обязан вывести набор из УЗЛОВ-КЛЮЧЕЙ и не увидеть имён в прозе.
var injModuleSetPkg = map[string]string{
	"internal/authzmap/doc.go": `package authzmap

// Написание ключа выбирает манифест модуля: у storage и registry оно
// множественное, у vpc и compute единственное. Здесь это только объяснение —
// набором эти имена не являются.
`,
	"internal/authzmap/tables_gen.go": `package authzmap

var objectTypes = map[string]string{
	"iam.account":      "account",
	"vpc.network":      "vpc_network",
	"compute.instance": "compute_instance",
	"storage.volumes":  "storage_volume",
	"bare":             "no_module_here",
}
`,
}

// TestClientTruthModuleSetDecl_InjectionBothWays — сторона ОБЪЯВЛЕНИЯ.
func TestClientTruthModuleSetDecl_InjectionBothWays(t *testing.T) {
	t.Parallel()

	t.Run("набор выводится разбором, проза соседнего файла в него не попадает", func(t *testing.T) {
		t.Parallel()
		mods, decl, err := check.ModuleSetFromDecl(injModuleSetPkg, check.ModuleSetVarName)
		if err != nil {
			t.Fatalf("объявление обязано разбираться: %v", err)
		}
		if got := strings.Join(mods, ","); got != "compute,iam,storage,vpc" {
			t.Fatalf("набор выведен как %q — ожидались четыре приставки узлов-ключей", got)
		}
		// Ключ без точки модуля НЕ ДАЁТ и себя целиком не отдаёт.
		for _, m := range mods {
			if m == "bare" {
				t.Fatal("ключ без точки попал в набор: объявлен модулем тот, кого таблица " +
					"модулем не называет")
			}
		}
		if decl.TypeKeys != 5 {
			t.Fatalf("ключей прочитано %d, а их пять — перепись не отличила бы "+
				"«таблица прочитана» от «прочитаны две строки»", decl.TypeKeys)
		}
		if decl.PkgFiles != 2 {
			t.Fatalf("файлов пакета осмотрено %d, а их два", decl.PkgFiles)
		}
		if decl.DeclFile != "internal/authzmap/tables_gen.go" {
			t.Fatalf("объявление найдено в %q — перепись обязана называть, ГДЕ именно, "+
				"потому что именно это место и переезжало", decl.DeclFile)
		}
	})

	t.Run("объявление переехало — ОТКАЗ гейта, а не находка о продукте", func(t *testing.T) {
		t.Parallel()
		_, decl, err := check.ModuleSetFromDecl(injModuleSetPkg, "objectTypesRenamed")
		if err == nil {
			t.Fatal("исчезнувшее объявление обязано давать отказ: молчание здесь было бы " +
				"зелёным прогоном над непрочитанным набором")
		}
		if !strings.Contains(err.Error(), "НЕ находка о продукте") {
			t.Fatalf("отказ обязан называть себя третьей категорией, а не находкой: %v", err)
		}
		if decl.PkgFiles != 2 {
			t.Fatalf("объём осмотренного обязан печататься и при отказе: файлов %d", decl.PkgFiles)
		}
	})

	t.Run("два объявления в пакете — ОТКАЗ: читается не один пакет", func(t *testing.T) {
		t.Parallel()
		two := map[string]string{
			"internal/authzmap/tables_gen.go": injModuleSetPkg["internal/authzmap/tables_gen.go"],
			"internal/authzmap/second.go": `package authzmap

var objectTypes = map[string]string{"registry.registries": "registry_registry"}
`,
		}
		if _, _, err := check.ModuleSetFromDecl(two, check.ModuleSetVarName); err == nil {
			t.Fatal("два объявления обязаны давать отказ: набор вышел бы склейкой двух таблиц")
		}
	})
}

// injModules — набор, о котором судятся перечни поверхности.
var injModules = []string{"compute", "iam", "loadbalancer", "registry", "storage", "vpc"}

// TestClientTruthModuleSetSurface_InjectionBothWays — сторона ПОВЕРХНОСТИ: по
// каждой оси дефект и законный близнец.
func TestClientTruthModuleSetSurface_InjectionBothWays(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name        string
		body        string
		wantFinding bool
		wantMissing string
		wantEnums   int
		wantPairs   int
	}{
		{
			// ДЕФЕКТ: перечень называет четыре из шести — ровно тот замер, на
			// котором семейство заведено.
			name:        "неполный перечень — находка с координатой",
			body:        "Модуль гранта — один из `iam`/`vpc`/`compute`/`storage`.\n",
			wantFinding: true,
			wantMissing: "loadbalancer, registry",
			wantEnums:   1,
		},
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ: та же форма записи, набор назван целиком.
			// Без него гейт ловил бы форму, а не существо.
			name: "полный перечень — гейт молчит",
			body: "Модуль гранта — один из `iam`/`vpc`/`compute`/`loadbalancer`/" +
				"`registry`/`storage`.\n",
			wantEnums: 1,
		},
		{
			// ОБЪЯВЛЕННАЯ СЛЕПАЯ ЗОНА: пара — законная форма, и она считается
			// отдельно, а не судится.
			name:      "пара из двух имён — не перечень, считается переписью",
			body:      "`vpc`/`compute` остаются label-selectable.\n",
			wantPairs: 1,
		},
		{
			// ОБЪЯВЛЕННАЯ СЛЕПАЯ ЗОНА: проза без код-форматирования не судится.
			// Ось прогоняется затем, чтобы граница была ИЗМЕРЕНА, а не обещана
			// шапкой.
			name: "проза без код-форматирования — вне охвата, и это объявлено",
			body: "Модули iam, vpc и compute принимают гранты.\n",
		},
		{
			// Форма <code>…</code> — второе законное написание той же формы.
			// Распознаватель, знающий одно, недобирал бы МОЛЧА.
			name:        "перечень в форме <code> — неполный, находка",
			body:        "<code>iam</code>/<code>vpc</code>/<code>compute</code>\n",
			wantFinding: true,
			wantMissing: "loadbalancer, registry, storage",
			wantEnums:   1,
		},
		{
			// Перечень из трёх НЕ обязан ещё и раздувать счёт пар: иначе
			// объявленная слепая зона росла бы вместе с находками.
			name:        "перечень из трёх пар не порождает",
			body:        "`iam`/`vpc`/`compute`\n",
			wantFinding: true,
			wantMissing: "loadbalancer, registry, storage",
			wantEnums:   1,
			wantPairs:   0,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			findings, scan := check.ScanModuleSetEnumerations("docs/content/x.mdx", tc.body, injModules)

			if tc.wantFinding && len(findings) == 0 {
				t.Fatal("дефект внесён, а гейт молчит — он не способен упасть по этой оси")
			}
			if !tc.wantFinding && len(findings) != 0 {
				t.Fatalf("законный вход объявлен находкой: %v — гейт ловит форму, а не существо",
					findings)
			}
			if tc.wantFinding {
				got := strings.Join(findings[0].Missing, ", ")
				if got != tc.wantMissing {
					t.Fatalf("не назван %q, ожидалось %q", got, tc.wantMissing)
				}
				// Находка обязана называть КООРДИНАТУ: находка без неё посылает
				// читателя искать самому.
				if findings[0].File == "" || findings[0].Line == 0 {
					t.Fatalf("находка без координаты: %+v", findings[0])
				}
				if !strings.Contains(findings[0].String(), "docs/content/x.mdx:1") {
					t.Fatalf("координата не напечатана: %s", findings[0].String())
				}
			}
			if scan.Enumerations != tc.wantEnums {
				t.Fatalf("перечней рассужено %d, ожидалось %d — перепись обязана быть верна и "+
					"там, где находок нет: без неё «ноль находок» неотличимо от «ноль прочитанного»",
					scan.Enumerations, tc.wantEnums)
			}
			if scan.PairSpans != tc.wantPairs {
				t.Fatalf("спанов из двух имён %d, ожидалось %d", scan.PairSpans, tc.wantPairs)
			}
		})
	}
}

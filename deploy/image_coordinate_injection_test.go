// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// image_coordinate_injection_test.go — доказательство того, что соседняя проба
// СПОСОБНА упасть, и падает ровно на своём предмете.
//
// ПОЧЕМУ ЭТО ОТДЕЛЬНАЯ ПРОБА. Зелёное на целом чарте не говорит о проверке
// ничего: проверка, потерявшая способность краснеть, на целом чарте выглядит
// точно так же. Единственное, что различает две эти вещи, — внесённый дефект.
//
// ФОРМА ДОКАЗАТЕЛЬСТВА. Вход берётся НАСТОЯЩИЙ — каталог поставки копируется во
// временный, — и каждый случай меняет против целой копии РОВНО ОДИН факт.
// Меняющий два не доказывает ничего: неизвестно, который из них дал красное.
//
// КОНТРОЛЬ В ОБРАТНУЮ СТОРОНУ ОБЯЗАТЕЛЕН: есть случаи, где проба обязана
// МОЛЧАТЬ — целая копия, координата, названная ДРУГИМ реестром, и позиция
// образа, прибитая литералом (её судит другая проба, и два места об одном
// предмете разошлись бы молча).
package deploy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// chartFixtureCase — один случай: что изменено против целой копии и чего ждём.
type chartFixtureCase struct {
	name string
	// mutate меняет РОВНО ОДИН факт во временной копии каталога поставки.
	mutate func(t *testing.T, chartDir string)
	// wantSubstring — по какому признаку узнаём находку. Пусто — ждём молчания.
	wantSubstring string
}

// copyChartDeliveryFixture кладёт во временный каталог НАСТОЯЩИЙ каталог
// поставки чарта — профили и шаблоны. Настоящий, а не синтетический: проверка,
// доказанная на выдуманном входе, доказывает работу на выдуманном входе.
//
// Файлы проб (`*.go`) не копируются: предмет обеих проб — объявления чарта, а
// не они сами.
//
// Общий для инъекций обоих новых гейтов каталога поставки — заводить второй
// значило бы держать две сборки одной фикстуры, и они разошлись бы молча.
func copyChartDeliveryFixture(t *testing.T) string {
	t.Helper()
	src := filepath.Join(serviceRoot(t), "deploy")
	dst := t.TempDir()

	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatalf("фикстура не собрана, каталог поставки не читается: %v", err)
	}
	copied := 0
	for _, e := range entries {
		if e.IsDir() || strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(src, e.Name()))
		if readErr != nil {
			t.Fatalf("фикстура не собрана, %s не прочитан: %v", e.Name(), readErr)
		}
		if err := os.WriteFile(filepath.Join(dst, e.Name()), raw, 0o644); err != nil {
			t.Fatalf("фикстура не собрана: %v", err)
		}
		copied++
	}

	tmplSrc := filepath.Join(src, templatesDir)
	tmplDst := filepath.Join(dst, templatesDir)
	if err := os.MkdirAll(tmplDst, 0o755); err != nil {
		t.Fatalf("фикстура не собрана: %v", err)
	}
	tmpls, err := os.ReadDir(tmplSrc)
	if err != nil {
		t.Fatalf("фикстура не собрана, каталог шаблонов не читается: %v", err)
	}
	for _, e := range tmpls {
		if e.IsDir() {
			continue
		}
		raw, readErr := os.ReadFile(filepath.Join(tmplSrc, e.Name()))
		if readErr != nil {
			t.Fatalf("фикстура не собрана, шаблон %s не прочитан: %v", e.Name(), readErr)
		}
		if err := os.WriteFile(filepath.Join(tmplDst, e.Name()), raw, 0o644); err != nil {
			t.Fatalf("фикстура не собрана: %v", err)
		}
		copied++
	}

	// Предпосылка каждого случая: фикстура собрана. Инъекция над пустым
	// каталогом доказывала бы молчание отсутствием предмета.
	if copied < 4 {
		t.Fatalf("фикстура не собрана: скопировано файлов %d — этого мало для чарта", copied)
	}
	return dst
}

// readChartFile / writeChartFile — правка одного файла фикстуры.
func readChartFile(t *testing.T, chartDir, rel string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(chartDir, rel))
	if err != nil {
		t.Fatalf("%s не прочитан: %v", rel, err)
	}
	return string(raw)
}

func writeChartFile(t *testing.T, chartDir, rel, body string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(chartDir, rel), []byte(body), 0o644); err != nil {
		t.Fatalf("%s не записан: %v", rel, err)
	}
}

// replaceOnceIn меняет первое вхождение и ОТКАЗЫВАЕТ, если его нет. Молчаливая
// замена нуля вхождений дала бы случай, который ничего не внёс, — и его зелёное
// читалось бы как доказательство.
func replaceOnceIn(t *testing.T, body, old, new string) string {
	t.Helper()
	if !strings.Contains(body, old) {
		t.Fatalf("инъекция беспредметна: во входе нет %q", old)
	}
	return strings.Replace(body, old, new, 1)
}

// runChartFixtureCases — общий прогон случаев для аудита каталога поставки.
func runChartFixtureCases(t *testing.T, cases []chartFixtureCase,
	audit func(chartDir string) (findings []string, census string, err error), wantCoordinate string) {
	t.Helper()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			chartDir := copyChartDeliveryFixture(t)
			tc.mutate(t, chartDir)

			findings, census, err := audit(chartDir)
			if err != nil {
				t.Fatalf("обход не состоялся: %v", err)
			}
			all := strings.Join(findings, "\n")

			if tc.wantSubstring == "" {
				if len(findings) != 0 {
					t.Fatalf("ожидалось молчание, получено находок %d:\n%s\nперепись: %s",
						len(findings), all, census)
				}
				t.Logf("молчание подтверждено · перепись: %s", census)
				return
			}
			if len(findings) == 0 {
				t.Fatalf("ожидалась находка по признаку %q — проба смолчала на внесённом "+
					"дефекте\nперепись: %s", tc.wantSubstring, census)
			}
			if !strings.Contains(all, tc.wantSubstring) {
				t.Fatalf("находка есть, но не та: ждали %q, получили:\n%s", tc.wantSubstring, all)
			}
			// Координата обязательна: находка без места посылает читателя искать
			// не там, и на неё тратят прогон, а потом снимают гейт как непонятный.
			if wantCoordinate != "" && !strings.Contains(all, wantCoordinate) {
				t.Fatalf("находка не называет координату (%s):\n%s", wantCoordinate, all)
			}
			t.Logf("находка подтверждена: %s", all)
		})
	}
}

func TestImageCoordinateInjection(t *testing.T) {
	runChartFixtureCases(t, []chartFixtureCase{
		{
			// Положительный контроль. Без него все отрицания ниже зеленели бы на
			// входе, который проба вообще не читает.
			name:          "целая копия — молчание",
			mutate:        func(*testing.T, string) {},
			wantSubstring: "",
		},
		{
			// Несущий случай: вернули умолчание координаты образа — тем самым
			// тегом нашего стенда, из-за которого задача и заведена.
			name: "умолчание координаты образа вернули — находка",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "values.yaml")
				b = replaceOnceIn(t, b, "\nimage: \"\"\n", "\nimage: kaname:dev\n")
				writeChartFile(t, chartDir, "values.yaml", b)
			},
			wantSubstring: "умолчание координаты образа непусто",
		},
		{
			// Тот же вход, изменён РОВНО ОДИН факт против целой копии: боевая
			// накладка перестала называть координату.
			name: "боевая накладка не называет координату — находка",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "values.prod.yaml")
				b = replaceOnceIn(t, b, "image: \"registry.example.invalid/pro-robotech/kaname:0.1.0\"\n", "")
				writeChartFile(t, chartDir, "values.prod.yaml", b)
			},
			wantSubstring: "не названа",
		},
		{
			name: "стендовая накладка не называет координату — находка",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "values.dev.yaml")
				b = replaceOnceIn(t, b, "image: \"kaname:dev\"\n", "")
				writeChartFile(t, chartDir, "values.dev.yaml", b)
			},
			wantSubstring: "не названа",
		},
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ отрицания выше, отличается ровно значением:
			// координата названа ДРУГИМ реестром. Проба судит, НАЗВАНА ли она, и
			// не судит, что именно названо, — подставить имя чужого реестра за
			// оператора нельзя.
			name: "координата названа другим реестром — молчание",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "values.prod.yaml")
				b = replaceOnceIn(t, b, "registry.example.invalid/pro-robotech/kaname:0.1.0",
					"harbor.tenant.invalid/iam/kaname:2.4.1")
				writeChartFile(t, chartDir, "values.prod.yaml", b)
			},
			wantSubstring: "",
		},
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ по позиции: посторонний контейнер с образом,
			// прибитым ЛИТЕРАЛОМ. Он попадает в перепись и не судится здесь —
			// его предмет у другой пробы.
			name: "посторонний контейнер с литеральным образом — молчание",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "templates/deployment.yaml")
				b = replaceOnceIn(t, b, "      initContainers:\n",
					"      initContainers:\n"+
						"        - name: wait-for-db\n"+
						"          image: \"busybox:1.36\"\n"+
						"          command: [\"/bin/sh\", \"-c\", \"sleep 1\"]\n")
				writeChartFile(t, chartDir, "templates/deployment.yaml", b)
			},
			wantSubstring: "",
		},
	}, auditImageCoordinate, "values.")
}

// TestImageCoordinateEmptyTraversalIsNotGreen — обход, которому нечего читать,
// обязан быть ОТЛИЧИМ от обхода без находок: «ноль находок» и «ноль
// прочитанного» дают одинаковое зелёное, и различает их только отказ.
func TestImageCoordinateEmptyTraversalIsNotGreen(t *testing.T) {
	t.Run("шаблоны без позиции образа", func(t *testing.T) {
		chartDir := copyChartDeliveryFixture(t)
		b := readChartFile(t, chartDir, "templates/deployment.yaml")
		b = strings.ReplaceAll(b, `image: "{{ .Values.image }}"`, `image: "busybox:1.36"`)
		writeChartFile(t, chartDir, "templates/deployment.yaml", b)

		_, _, err := auditImageCoordinate(chartDir)
		if err == nil {
			t.Fatal("обход без единой позиции образа через значения дал вердикт — " +
				"беспредметное зелёное неотличимо от чистого чарта")
		}
		t.Logf("отказ подтверждён: %v", err)
	})

	t.Run("чарт без накладок", func(t *testing.T) {
		chartDir := copyChartDeliveryFixture(t)
		for _, name := range []string{"values.dev.yaml", "values.prod.yaml"} {
			if err := os.Remove(filepath.Join(chartDir, name)); err != nil {
				t.Fatalf("фикстура не собрана: %v", err)
			}
		}
		_, _, err := auditImageCoordinate(chartDir)
		if err == nil {
			t.Fatal("чарт без единой накладки дал вердикт — а утверждать, что координату " +
				"называет тот, кто ставит, тут не на чем")
		}
		t.Logf("отказ подтверждён: %v", err)
	})

	t.Run("пустой каталог", func(t *testing.T) {
		if _, _, err := auditImageCoordinate(t.TempDir()); err == nil {
			t.Fatal("пустой каталог дал вердикт вместо отказа")
		}
	})
}

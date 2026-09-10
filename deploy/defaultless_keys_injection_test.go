// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// defaultless_keys_injection_test.go — доказательство того, что соседняя проба
// СПОСОБНА упасть, и падает ровно на своём предмете.
//
// ГЛАВНОЕ ЗДЕСЬ — ПЕРЕЧЕНЬ ФОРМ. Проба ищет предмет по образцу, а форма, о
// которой распознаватель не знает, не даёт ни красного, ни зелёного — она
// МОЛЧИТ, и всё записанное в ней оказывается вне наблюдения. Поэтому каждая
// законная форма доказана СВОИМ случаем, и у всех них общий отрицательный
// близнец: тот же ключ, подставленный без формы.
//
// Фикстура — настоящий каталог поставки (`copyChartDeliveryFixture`), и каждый
// случай меняет против целой копии РОВНО ОДИН факт.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// probeKnobPath — ключ, заводимый инъекцией. Имя нарочно постороннее: случай,
// опирающийся на СУЩЕСТВУЮЩИЙ ключ чарта, менял бы два факта разом — предмет и
// то, чем он укрыт.
const probeKnobPath = "injectedProbeKnob"

// declareDefaultlessKnob — заводит в базовых значениях фикстуры ключ с пустым
// умолчанием и кладёт в шаблон строку, которая его называет.
func declareDefaultlessKnob(t *testing.T, chartDir, templateLine string) {
	t.Helper()
	values := readChartFile(t, chartDir, "values.yaml")
	writeChartFile(t, chartDir, "values.yaml",
		values+fmt.Sprintf("\n%s: \"\"\n", probeKnobPath))

	tmpl := readChartFile(t, chartDir, "templates/service.yaml")
	writeChartFile(t, chartDir, "templates/service.yaml", tmpl+"\n"+templateLine+"\n")
}

// declareDefaultlessKnobViaHelper — тот же заведённый ключ, но названный ТЕЛОМ
// именованного шаблона, а зовущий его шаблон получает величину переходом.
//
// Форма несущая: половины лежат в РАЗНЫХ файлах — путь значения называет тело,
// пустоту узнаёт зовущий, — и распознаватель, читающий их порознь, видит
// дословную подстановку на верном чарте. Случай существует ради обеих сторон:
// переход под ветвью обязан молчать, тот же переход без ветви — краснеть.
func declareDefaultlessKnobViaHelper(t *testing.T, chartDir, callerLine string) {
	t.Helper()
	values := readChartFile(t, chartDir, "values.yaml")
	writeChartFile(t, chartDir, "values.yaml",
		values+fmt.Sprintf("\n%s: \"\"\n", probeKnobPath))

	helpers := readChartFile(t, chartDir, "templates/_helpers.tpl")
	writeChartFile(t, chartDir, "templates/_helpers.tpl", helpers+fmt.Sprintf(
		"\n{{- define \"kaname-svc.injectedProbe\" -}}\n{{- .Values.%s -}}\n{{- end -}}\n",
		probeKnobPath))

	tmpl := readChartFile(t, chartDir, "templates/service.yaml")
	writeChartFile(t, chartDir, "templates/service.yaml", tmpl+"\n"+callerLine+"\n")
}

func TestDefaultlessKeysInjection(t *testing.T) {
	cases := []chartFixtureCase{
		{
			// Положительный контроль. Без него все отрицания ниже зеленели бы на
			// входе, который проба вообще не читает.
			name:          "целая копия — молчание",
			mutate:        func(*testing.T, string) {},
			wantSubstring: "",
		},
		{
			// НЕСУЩИЙ СЛУЧАЙ: перечень отказа рендера перестал называть
			// координату образа, и она подставляется дословно — ровно то
			// состояние, в котором задача #2094 оставила бы чарт, сняв умолчание
			// и не тронув перечень.
			name: "перечень отказа рендера не называет образ — находка",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "templates/_helpers.tpl")
				start := strings.Index(b, "{{- if not .Values.image -}}")
				if start < 0 {
					t.Fatal("инъекция беспредметна: во входе нет ветви образа")
				}
				tail := b[start:]
				end := strings.Index(tail, "{{- end -}}\n")
				if end < 0 {
					t.Fatal("инъекция беспредметна: ветвь образа не закрыта")
				}
				writeChartFile(t, chartDir, "templates/_helpers.tpl",
					b[:start]+tail[end+len("{{- end -}}\n"):])
			},
			wantSubstring: "подставляет ключ ДОСЛОВНО",
		},
		{
			// ОТРИЦАНИЕ ДЛЯ ВСЕХ ФОРМ НИЖЕ: тот же заведённый ключ, названный
			// шаблоном БЕЗ формы, узнающей пустоту.
			name: "ключ со снятым умолчанием подставлен без формы — находка",
			mutate: func(t *testing.T, chartDir string) {
				declareDefaultlessKnob(t, chartDir,
					fmt.Sprintf("  probe: {{ .Values.%s }}", probeKnobPath))
			},
			wantSubstring: probeKnobPath,
		},
	}

	cases = append(cases,
		chartFixtureCase{
			// НОВАЯ ФОРМА, ОБРАТНАЯ СТОРОНА: переход в именованный шаблон стоит
			// БЕЗ ветви, и пустоту не узнаёт никто. Без этого случая переход,
			// добавленный в распознаватель, прощал бы всё, что через него идёт.
			name: "путь назван телом именованного шаблона, переход без ветви — находка",
			mutate: func(t *testing.T, chartDir string) {
				declareDefaultlessKnobViaHelper(t, chartDir,
					`  probe: {{ include "kaname-svc.injectedProbe" . }}`)
			},
			wantSubstring: probeKnobPath,
		},
		chartFixtureCase{
			// ЗАКОННЫЙ БЛИЗНЕЦ той же формы: РОВНО ОДИН факт отличия — переход
			// укрыт ветвью. Так отдаётся домен доверия, и на этом чарт верен.
			name: "путь назван телом именованного шаблона, переход под ветвью — молчание",
			mutate: func(t *testing.T, chartDir string) {
				declareDefaultlessKnobViaHelper(t, chartDir,
					"{{- with (include \"kaname-svc.injectedProbe\" .) }}\n  probe: {{ . }}\n{{- end }}")
			},
			wantSubstring: "",
		},
	)

	// ЗАКОННЫЕ БЛИЗНЕЦЫ, по одному на форму. От случая выше каждый отличается
	// РОВНО ОДНИМ фактом — формой, которой ключ укрыт.
	for _, form := range []struct{ name, line string }{
		{"if", fmt.Sprintf("{{- if .Values.%s }}\n  probe: yes\n{{- end }}", probeKnobPath)},
		{"else if", fmt.Sprintf("{{- if false }}\n{{- else if .Values.%s }}\n  probe: yes\n{{- end }}", probeKnobPath)},
		{"with", fmt.Sprintf("{{- with .Values.%s }}\n  probe: {{ . }}\n{{- end }}", probeKnobPath)},
		{"range", fmt.Sprintf("{{- range .Values.%s }}\n  - {{ . }}\n{{- end }}", probeKnobPath)},
		{"required", fmt.Sprintf(`  probe: {{ required "не задано" .Values.%s }}`, probeKnobPath)},
		{"default", fmt.Sprintf(`  probe: {{ default "x" .Values.%s }}`, probeKnobPath)},
	} {
		line := form.line
		cases = append(cases, chartFixtureCase{
			name: "форма `" + form.name + "` узнаёт пустоту — молчание",
			mutate: func(t *testing.T, chartDir string) {
				declareDefaultlessKnob(t, chartDir, line)
			},
			wantSubstring: "",
		})
	}

	runChartFixtureCases(t, cases, auditDefaultlessKeys, "")
}

// TestDefaultlessKeysEmptyTraversalIsNotGreen — обход, которому нечего читать,
// обязан быть ОТЛИЧИМ от обхода без находок.
func TestDefaultlessKeysEmptyTraversalIsNotGreen(t *testing.T) {
	t.Run("ни одного снятого умолчания", func(t *testing.T) {
		chartDir := copyChartDeliveryFixture(t)
		b := readChartFile(t, chartDir, "values.yaml")
		// Один факт: каждое снятое умолчание чем-нибудь заполнено. Популяция
		// пуста, и судить нечего — это отказ, а не чистый чарт.
		//
		// Популяция ВЫВОДИТСЯ, а не перечисляется поимённо. Перечень был бы
		// вторым местом об одном предмете и разошёлся бы молча: соседняя полоса
		// завела ключ `trustDomain`, его в перечне не было, популяция пустой не
		// стала, и самопроверка покраснела на верном чарте. Замена по образцу
		// «пустая величина → заполненная» опустошает популяцию by construction.
		b = regexp.MustCompile(`: ""`).ReplaceAllString(b, `: "filled"`)
		writeChartFile(t, chartDir, "values.yaml", b)

		_, census, err := auditDefaultlessKeys(chartDir)
		if err == nil {
			t.Fatalf("популяция пуста, а вердикт вынесен — беспредметное зелёное "+
				"неотличимо от чистого чарта\nперепись: %s", census)
		}
		t.Logf("отказ подтверждён: %v", err)
	})

	t.Run("шаблоны без единого действия", func(t *testing.T) {
		chartDir := copyChartDeliveryFixture(t)

		// Популяция ВЫВОДИТСЯ из фикстуры, а не перечисляется поимённо — по той
		// же причине, что и у соседней полосы выше, и цена уже уплачена дважды.
		// Здесь стоял список из четырёх шаблонов; поставка правил тревоги завела
		// пятый (`templates/prometheusrule.yaml`), его в списке не было, шаблон
		// сохранил свои действия — и популяция пустой не стала. Самопроверка
		// покраснела на ВЕРНОМ чарте, обвинив предмет, к которому отношения не
		// имеет.
		entries, err := os.ReadDir(filepath.Join(chartDir, "templates"))
		if err != nil {
			t.Fatalf("каталог шаблонов фикстуры не читается: %v", err)
		}
		blanked := 0
		for _, e := range entries {
			if e.IsDir() {
				continue
			}
			writeChartFile(t, chartDir, filepath.Join("templates", e.Name()), "# шаблон без действий\n")
			blanked++
		}
		if blanked == 0 {
			t.Fatal("фикстура не дала ни одного шаблона — инъекция беспредметна, " +
				"и «отказа не было» означало бы «обнулять было нечего»")
		}

		if _, _, err := auditDefaultlessKeys(chartDir); err == nil {
			t.Fatalf("шаблоны без единого действия (обнулено %d) дали вердикт вместо отказа", blanked)
		}
	})

	t.Run("пустой каталог", func(t *testing.T) {
		if _, _, err := auditDefaultlessKeys(t.TempDir()); err == nil {
			t.Fatal("пустой каталог дал вердикт вместо отказа")
		}
	})
}

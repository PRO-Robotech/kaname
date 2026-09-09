// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// operator_keys_carry_no_foreign_prefix_injection_test.go — доказательство того,
// что соседняя проба СПОСОБНА упасть, и падает ровно на своём предмете.
//
// ФОРМА. Вход НАСТОЯЩИЙ — каталог поставки копируется во временный, — и каждый
// случай меняет против целой копии РОВНО ОДИН факт. Меняющий два не доказывает
// ничего: неизвестно, который из них дал красное.
//
// КОНТРОЛЬ В ОБРАТНУЮ СТОРОНУ. Случаев молчания здесь ТРИ, и каждый — законный
// близнец соседнего отрицания, отличающийся от него одной величиной: ключ
// аннотации со СВОИМ доменом, ключ аннотации БЕЗ домена вовсе и выборка,
// привязанная не к дереву значений, а к псевдониму.
//
// ТРЕТИЙ ПРОГОН — ИЗОЛЯЦИЯ. Инъекция, попутно роняющая СУЩЕСТВУЮЩИЙ контроль,
// доказательством не является: красное пришло бы от соседа, и новая проба могла
// бы оказаться вакуумной, не показав этого ничем. Поэтому прогонов три:
// контроль (молчат обе) · новый дефект (краснеет только новая) · существующий
// дефект (краснеет только существующая). Без третьего молчание существующего
// контроля неотличимо от молчания мёртвого.
package deploy_test

import (
	"strings"
	"testing"
)

// Якоря инъекции — то, что стоит в целой копии. Вынесены константами, потому
// что каждый обязан в ней НАЙТИСЬ: молчаливая замена нуля вхождений дала бы
// случай, который ничего не внёс, и его зелёное читалось бы как доказательство.
const (
	wholeImageAnnotation  = "kaname.cloud/image-id: {{ . | quote }}"
	wholeConfigAnnotation = "kaname.cloud/config-checksum:"
	wholeImageIdGuard     = "{{- with .Values.imageId }}"
	wholeAliasDig         = `dig "mode" "" $cur`
)

// ВНОСИМЫЕ ДЕФЕКТЫ. Приставка платформы здесь НЕ воспроизводится дословно, и это
// решение, а не осторожность: файл уезжает арендатору вместе с каталогом
// поставки (ведомость `delivery_roster_test.go`), поэтому чужой бренд в нём —
// ровно та витрина, которую снимает эта же задача.
//
// Точность при этом не теряется. Правила пробы ПОЛОЖИТЕЛЬНЫЕ: «домен обязан
// быть доменом продукта» и «первый сегмент обязан быть объявлен профилем». Обе
// ветви исполняются любым чужим доменом и любым необъявленным ключом одинаково,
// и текст находки получается тот же. Историческая приставка названа словами в
// шапке соседней пробы — там она прозой, а не ключом манифеста.
const (
	foreignDomainAnnotation = "example.invalid/image-id: {{ . | quote }}"
	foreignDomainChecksum   = "example.invalid/config-checksum:"
	foreignDigGuard         = `{{- with dig "imageIdsByService" "iam" "" (.Values.global | default dict) }}`
	foreignPathGuard        = "{{- with .Values.imageIdsByService }}"
)

func TestOperatorKeyPrefixesInjection(t *testing.T) {
	runChartFixtureCases(t, []chartFixtureCase{
		{
			// ПОЛОЖИТЕЛЬНЫЙ КОНТРОЛЬ. Без него все отрицания ниже зеленели бы на
			// входе, который проба вообще не читает.
			name:          "целая копия — молчание",
			mutate:        func(*testing.T, string) {},
			wantSubstring: "",
		},
		{
			// НЕСУЩИЙ СЛУЧАЙ вида А: вернули домен чужой платформы тому самому
			// ключу, из-за которого задача и заведена.
			name: "чужой домен у ключа образа — находка",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "templates/deployment.yaml")
				b = replaceOnceIn(t, b, wholeImageAnnotation,
					foreignDomainAnnotation)
				writeChartFile(t, chartDir, "templates/deployment.yaml", b)
			},
			wantSubstring: "объявлен доменом",
		},
		{
			// Тот же вид, вторая позиция: ключ отпечатка настроек. Названа
			// отдельно, потому что позиции две, а не одна.
			name: "чужой домен у ключа отпечатка настроек — находка",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "templates/deployment.yaml")
				b = replaceOnceIn(t, b, wholeConfigAnnotation, foreignDomainChecksum)
				writeChartFile(t, chartDir, "templates/deployment.yaml", b)
			},
			wantSubstring: "объявлен доменом",
		},
		{
			// НЕСУЩИЙ СЛУЧАЙ вида Б, форма ВТОРАЯ: ключ значений приходит
			// строковым доводом выборки. Именно эта форма осталась вне
			// наблюдения соседнего предмета и дала там ложный ноль.
			name: "ключ чужой накладки строковым доводом выборки — находка",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "templates/deployment.yaml")
				b = replaceOnceIn(t, b, wholeImageIdGuard,
					foreignDigGuard)
				writeChartFile(t, chartDir, "templates/deployment.yaml", b)
			},
			wantSubstring: "строковый довод выборки",
		},
		{
			// Тот же вид, форма ПЕРВАЯ: путь после `.Values`, не объявленный
			// профилем чарта.
			name: "ключ значений путём, не объявленный чартом — находка",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "templates/deployment.yaml")
				b = replaceOnceIn(t, b, wholeImageIdGuard, foreignPathGuard)
				writeChartFile(t, chartDir, "templates/deployment.yaml", b)
			},
			wantSubstring: "не объявлен в values.yaml",
		},
		{
			// ВЕДОМОСТЬ ЧИТАТЕЛЯ — молчание. Ключи объявления сбора называет
			// СОБИРАТЕЛЬ, и читает он их по этим именам; названные нашим доменом,
			// они не были бы прочитаны никем (задача #2338).
			//
			// Случай стоит ПОЛОЖИТЕЛЬНЫМ КОНТРОЛЕМ записи ведомости: без него
			// молчание пробы на действующем чарте было бы неотличимо от молчания,
			// наступившего оттого, что запись прощает лишнее.
			name: "домен читателя объявления сбора — молчание",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "templates/deployment.yaml")
				b = replaceOnceIn(t, b, "prometheus.io/path: /metrics",
					"prometheus.io/path: /metrics\n        prometheus.io/timeout: 5s")
				writeChartFile(t, chartDir, "templates/deployment.yaml", b)
			},
			wantSubstring: "",
		},
		{
			// ГРАНИЦА ЗАПИСИ: ведомость разрешает ДОМЕН, а не приставку. Домен,
			// лишь начинающийся с разрешённого, обязан оставаться находкой —
			// иначе запись стала бы маской для любого чужого имени, начатого
			// правильными буквами.
			name: "домен, лишь похожий на разрешённый, — находка",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "templates/deployment.yaml")
				b = replaceOnceIn(t, b, "prometheus.io/path: /metrics",
					"prometheus.io.example.invalid/path: /metrics")
				writeChartFile(t, chartDir, "templates/deployment.yaml", b)
			},
			wantSubstring: "объявлен доменом",
		},
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ отрицания вида А, отличается ровно доменом:
			// ключ переименован, но домен остался своим.
			name: "свой домен, другое имя ключа — молчание",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "templates/deployment.yaml")
				b = replaceOnceIn(t, b, wholeImageAnnotation,
					"kaname.cloud/image-digest: {{ . | quote }}")
				writeChartFile(t, chartDir, "templates/deployment.yaml", b)
			},
			wantSubstring: "",
		},
		{
			// ВТОРОЙ ЗАКОННЫЙ БЛИЗНЕЦ того же отрицания: ключ БЕЗ домена вовсе.
			// Плоский ключ ничьего бренда не несёт, и правило его не судит.
			name: "ключ аннотации без домена — молчание",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "templates/deployment.yaml")
				b = replaceOnceIn(t, b, wholeImageAnnotation, "image-id: {{ . | quote }}")
				writeChartFile(t, chartDir, "templates/deployment.yaml", b)
			},
			wantSubstring: "",
		},
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ отрицания вида Б: выборка привязана к
			// ПСЕВДОНИМУ, а не к дереву значений. Она читает вложенную величину,
			// которой чарт уже владеет, — ключом витрины не является.
			//
			// Случай стоит здесь не для полноты: первая редакция распознавателя
			// краснела ровно на нём, приняв вложенный ключ за ключ верхнего
			// уровня.
			name: "выборка по псевдониму — молчание",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "templates/_helpers.tpl")
				b = replaceOnceIn(t, b, wholeAliasDig, `dig "legacyMode" "" $cur`)
				writeChartFile(t, chartDir, "templates/_helpers.tpl", b)
			},
			wantSubstring: "",
		},
	}, auditOperatorKeyPrefixes, "templates/")
}

// TestOperatorKeyPrefixesInjectionRaisesOnlyItsOwn — ТРЕТИЙ ПРОГОН.
//
// Проверяет не «краснеет ли», а «краснеет ли ТОЛЬКО она». Три мира, в каждом
// прогоняются ОБЕ пробы каталога поставки:
//
//	целая копия        обе молчат
//	новый дефект       краснеет новая, существующая молчит
//	существующий       краснеет существующая, новая молчит
//
// Третий мир обязателен: без него молчание существующего контроля неотличимо
// от молчания мёртвого.
func TestOperatorKeyPrefixesInjectionRaisesOnlyItsOwn(t *testing.T) {
	type run struct {
		name       string
		mutate     func(t *testing.T, chartDir string)
		wantNew    bool
		wantExists bool
	}

	for _, r := range []run{
		{
			name:   "контроль — молчат обе",
			mutate: func(*testing.T, string) {},
		},
		{
			name: "новый дефект — краснеет только новая",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "templates/deployment.yaml")
				b = replaceOnceIn(t, b, wholeImageAnnotation,
					foreignDomainAnnotation)
				writeChartFile(t, chartDir, "templates/deployment.yaml", b)
			},
			wantNew: true,
		},
		{
			name: "существующий дефект — краснеет только существующая",
			mutate: func(t *testing.T, chartDir string) {
				b := readChartFile(t, chartDir, "values.yaml")
				b = replaceOnceIn(t, b, "\nimage: \"\"\n", "\nimage: kaname:dev\n")
				writeChartFile(t, chartDir, "values.yaml", b)
			},
			wantExists: true,
		},
	} {
		t.Run(r.name, func(t *testing.T) {
			chartDir := copyChartDeliveryFixture(t)
			r.mutate(t, chartDir)

			newFindings, newCensus, err := auditOperatorKeyPrefixes(chartDir)
			if err != nil {
				t.Fatalf("новая проба: обход не состоялся: %v", err)
			}
			oldFindings, oldCensus, err := auditImageCoordinate(chartDir)
			if err != nil {
				t.Fatalf("существующая проба: обход не состоялся: %v", err)
			}

			t.Logf("новая: находок %d · перепись: %s", len(newFindings), newCensus)
			t.Logf("существующая: находок %d · перепись: %s", len(oldFindings), oldCensus)

			if got := len(newFindings) > 0; got != r.wantNew {
				t.Fatalf("новая проба: ждали красное=%v, получили %v:\n%s",
					r.wantNew, got, strings.Join(newFindings, "\n"))
			}
			if got := len(oldFindings) > 0; got != r.wantExists {
				t.Fatalf("существующая проба: ждали красное=%v, получили %v — инъекция задела "+
					"соседа, и вердикт непрослеживаем:\n%s",
					r.wantExists, got, strings.Join(oldFindings, "\n"))
			}
		})
	}
}

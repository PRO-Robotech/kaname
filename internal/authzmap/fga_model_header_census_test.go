// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// fga_model_header_census_test.go — гейт на ПЕРЕЧЕНЬ ТИПОВ В ШАПКЕ модели прав.
//
// Шапка `fga_model.fga` перечисляет «per-domain object types» — тот список, по
// которому человек читает, из чего вообще состоит модель. Тело файла — то, что
// исполняется. Между ними не было ни одной проверки: соседние гейты этого пакета
// разбирают ТЕЛО (`fga_model_drift_test.go` — `type`-объявления против каталога,
// `fga_model_configmap_identity_test.go` — сгенерированную копию против
// канонического файла), а комментарий не читает никто.
//
// Список, который никто не сверяет, расходится со своим предметом — и разошёлся
// в ОБЕ стороны сразу. Померено на bdafe2c4, а не предположено:
//
//   - `iam_condition` — шапка называет тип, которого в теле НЕТ: на его месте
//     надгробие (строка «TOMBSTONE — `type iam_condition` жил здесь ради
//     тенантского ресурса условия»). Список пережил снятие своего предмета;
//   - `registry_registry`, `registry_repository` — тело объявляет, шапка молчит.
//     Целый домен не виден читателю перечня.
//
// Направление «шапка называет снятое» — не косметика: это ложное утверждение о
// поверхности доступа. Читатель перечня (человек, заводящий новый грант или
// сверяющий охват каталога) видит тип, для которого нельзя написать ни одного
// кортежа, и планирует работу по нему. Обратное направление тише и хуже: домен,
// которого в перечне нет, при таком же чтении просто выпадает из охвата.
//
// # Почему гейт, а не разовая правка
//
// Разовая правка закрывает экземпляр и оставляет класс: следующий тип, заведённый
// в теле, снова не доедет до шапки, и узнать об этом будет неоткуда. Гейт
// превращает шапку в производное от тела — расхождение становится красным на
// обычном `go test ./...`, а не находкой очередного аудита.
//
// # Единый источник исключений
//
// Не-грантуемые типы берутся из `nonGrantableModelTypes` (сосед по пакету), а НЕ
// переписываются здесь: второй, независимый список ровно этих же имён — тот самый
// механизм расхождения, против которого написан файл. Структурные родители
// (`account`/`project`) названы в шапке СВОИМ пунктом, поэтому из перечня
// ресурсных типов исключены — и каждое исключение обязано иметь предмет в теле
// (иначе это просроченное послабление, которое унаследует следующая слепая зона).
package authzmap_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// structuralParentTypes — типы, которые шапка называет ОТДЕЛЬНЫМ пунктом
// («`account` / `project` — STRUCTURAL parents»), поэтому в перечне ресурсных
// типов их быть не должно. Исключение самоистекающее: если тела у типа больше
// нет, запись становится находкой (см. проверку ниже), а не тихо переживает свой
// предмет — ровно то, что случилось с `iam_condition` в самой шапке.
var structuralParentTypes = map[string]string{
	"account": "структурный родитель (cluster ▶ account ▶ project), назван в шапке своим пунктом",
	"project": "структурный родитель (cluster ▶ account ▶ project), назван в шапке своим пунктом",
}

// headerPerDomainBlock — тело пункта «per-domain object types» из шапки.
//
// Границы берутся по СОСЕДНИМ пунктам того же списка, а не по номерам строк:
// перечень растёт, и привязка к позиции протухла бы первой же правкой. Пустой
// результат — ОТКАЗ, а не «расхождений нет»: гейт, потерявший свой вход, обязан
// сказать это вслух, иначе он зеленеет на пустом множестве.
func headerPerDomainBlock(t *testing.T, dsl string) string {
	t.Helper()
	re := regexp.MustCompile(`(?s)#   - per-domain object types —(.*?)\n#   - relations:`)
	m := re.FindStringSubmatch(dsl)
	if m == nil {
		t.Fatalf("в шапке %s не найден пункт «per-domain object types … » до пункта «relations:» — "+
			"гейт потерял свой вход. Это ОТКАЗ, а не «расхождений нет»: сравнение с пустым "+
			"перечнем зелено всегда. Почини разбор или перепиши границы пункта.", canonicalModelRelPath)
	}
	return m[1]
}

// backtickedIdents — идентификаторы в обратных кавычках. Перечень шапки написан
// именно так, и прочая проза (пояснения в скобках, ссылки на тикеты) кавычек не
// несёт, поэтому в множество не попадает.
func backtickedIdents(block string) []string {
	var out []string
	for _, m := range regexp.MustCompile("`([a-z][a-z_0-9]*)`").FindAllStringSubmatch(block, -1) {
		out = append(out, m[1])
	}
	return out
}

// modelBodyTypes — `type`-объявления тела. Это ПРЕДМЕТ, о котором говорит шапка.
func modelBodyTypes(dsl string) []string {
	var out []string
	for _, m := range regexp.MustCompile(`(?m)^type ([a-z][a-z_0-9]*)`).FindAllStringSubmatch(dsl, -1) {
		out = append(out, m[1])
	}
	return out
}

// TestModelHeaderTypeListMatchesBody — перечень типов в шапке равен множеству
// ресурсных типов тела, в ОБЕ стороны.
func TestModelHeaderTypeListMatchesBody(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join(monorepoRoot(t), canonicalModelRelPath))
	require.NoErrorf(t, err, "канонический %s не прочитан — гейту нечего сверять", canonicalModelRelPath)
	dsl := string(raw)

	body := modelBodyTypes(dsl)
	require.NotEmptyf(t, body, "в %s не разобрано НИ ОДНОГО `type` — сломан разбор тела, "+
		"а не «шапка совпадает»", canonicalModelRelPath)

	listed := backtickedIdents(headerPerDomainBlock(t, dsl))
	require.NotEmpty(t, listed, "перечень типов в шапке разобран как ПУСТОЙ — сломан разбор шапки. "+
		"Сравнение с пустым перечнем зелено всегда, поэтому это отказ.")

	inBody := map[string]bool{}
	for _, typ := range body {
		inBody[typ] = true
	}

	// Исключения обязаны иметь предмет: запись, которой больше нечего исключать,
	// — находка. Иначе послабление переживает свой предмет и достаётся в
	// наследство следующему типу с тем же именем.
	for typ, reason := range structuralParentTypes {
		require.Truef(t, inBody[typ], "structuralParentTypes называет %q (%s), но тело модели такой тип "+
			"больше не объявляет — просроченное исключение", typ, reason)
	}
	for typ, reason := range nonGrantableModelTypes {
		require.Truef(t, inBody[typ], "nonGrantableModelTypes называет %q (%s), но тело модели такой тип "+
			"больше не объявляет — просроченное исключение", typ, reason)
	}

	// Ожидаемый перечень — производное от ТЕЛА: все типы минус документированные
	// не-грантуемые (subject/hierarchy/plumbing) минус структурные родители,
	// которые шапка называет своим пунктом.
	want := map[string]bool{}
	for _, typ := range body {
		if nonGrantableModelTypes[typ] != "" || structuralParentTypes[typ] != "" {
			continue
		}
		want[typ] = true
	}
	got := map[string]bool{}
	for _, typ := range listed {
		got[typ] = true
	}

	// ПЕРЕПИСЬ: «ноль расхождений» обязано отличаться от «ноль прочитанного».
	t.Logf("осмотрено: `type` в теле %d, перечислено в шапке %d, ожидалось ресурсных %d "+
		"(исключено: не-грантуемых %d, структурных родителей %d)",
		len(body), len(listed), len(want), len(nonGrantableModelTypes), len(structuralParentTypes))

	var phantom, missing []string
	for typ := range got {
		if !want[typ] {
			phantom = append(phantom, typ)
		}
	}
	for typ := range want {
		if !got[typ] {
			missing = append(missing, typ)
		}
	}
	sort.Strings(phantom)
	sort.Strings(missing)

	// Находки перечисляются ВСЕ. Прерывание на первой скрыло бы радиус: именно
	// так этот гейт в первой редакции назвал `iam_condition` и умолчал про два
	// пропущенных типа registry — то есть сам показал бы класс уже, чем он есть.
	for _, typ := range phantom {
		hint := "тело модели такой тип не объявляет"
		if inBody[typ] {
			hint = "тип объявлен, но документирован как не-грантуемый или структурный — " +
				"в перечне ресурсных типов ему не место"
		}
		t.Errorf("шапка называет тип, которого в перечне быть не должно: `%s` перечислен в шапке %s "+
			"как per-domain object type, но %s.\n\n"+
			"Перечень — то, по чему модель читают глазами. Названный, но снятый тип — "+
			"ложное утверждение о поверхности доступа: для него нельзя написать ни одного "+
			"кортежа, а читатель планирует по нему работу. Убери имя из шапки либо верни "+
			"тип в тело.", typ, canonicalModelRelPath, hint)
	}
	for _, typ := range missing {
		t.Errorf("тело объявляет тип, которого нет в шапке: `%s` объявлен в теле %s и грантуем, "+
			"но в перечне шапки его нет.\n\n"+
			"Это направление тише предыдущего и хуже: домен, которого в перечне нет, "+
			"выпадает из охвата при чтении — его просто не заметят. Внеси имя в пункт "+
			"«per-domain object types».", typ, canonicalModelRelPath)
	}
}

// TestModelHeaderCensusDiscriminatorCutsBothWays — гейт выше проверен инъекцией
// НАСТОЯЩИМ входом той же формы, в обе стороны.
//
// Без этого «расхождений нет» на реальном файле неотличимо от предиката, который
// расхождения не умеет видеть. Фикстура повторяет форму канонического файла: тот
// же пункт шапки, те же соседние пункты, то же надгробие в теле.
//
//   - согласованная пара -> МОЛЧИТ;
//   - шапка называет снятое (надгробие в теле) -> КРАСНОЕ;
//   - тело объявляет, шапка молчит -> КРАСНОЕ;
//   - не-грантуемый и структурный типы в теле, но не в перечне -> МОЛЧИТ
//     (иначе гейт грубее своего предмета и требовал бы `user`/`project` в
//     списке ресурсных типов).
func TestModelHeaderCensusDiscriminatorCutsBothWays(t *testing.T) {
	const shell = `model
  schema 1.1

#   - per-domain object types — %s.
#   - relations: viewer / editor / admin.

type user

type project

%s
`
	cases := []struct {
		name        string
		listed      string
		bodyTypes   []string
		wantPhantom []string
		wantMissing []string
	}{
		{
			name:      "согласованная пара — гейт молчит",
			listed:    "`vpc_network`, `iam_role`",
			bodyTypes: []string{"vpc_network", "iam_role"},
		},
		{
			name:        "шапка называет снятый тип — на его месте надгробие",
			listed:      "`vpc_network`, `iam_condition`",
			bodyTypes:   []string{"vpc_network"},
			wantPhantom: []string{"iam_condition"},
		},
		{
			name:        "тело объявляет домен, шапка молчит",
			listed:      "`vpc_network`",
			bodyTypes:   []string{"vpc_network", "registry_registry", "registry_repository"},
			wantMissing: []string{"registry_registry", "registry_repository"},
		},
		{
			name:        "расхождение сразу в обе стороны",
			listed:      "`vpc_network`, `iam_condition`",
			bodyTypes:   []string{"vpc_network", "registry_registry"},
			wantPhantom: []string{"iam_condition"},
			wantMissing: []string{"registry_registry"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var body strings.Builder
			for _, typ := range tc.bodyTypes {
				body.WriteString("type " + typ + "\n\n")
			}
			// Надгробие: имя снятого типа присутствует в ТЕКСТЕ тела, но
			// объявлением не является. Гейт обязан читать `type`-объявления, а не
			// упоминания, иначе надгробие само себя оправдает.
			body.WriteString("# TOMBSTONE — `type iam_condition` жил здесь.\n")
			dsl := strings.ReplaceAll(shell, "%s", "\x00")
			dsl = strings.Replace(dsl, "\x00", tc.listed, 1)
			dsl = strings.Replace(dsl, "\x00", body.String(), 1)

			gotBody := modelBodyTypes(dsl)
			require.NotEmpty(t, gotBody, "разбор тела фикстуры пуст")
			require.NotContainsf(t, gotBody, "iam_condition",
				"надгробие принято за объявление типа — гейт читает ТЕКСТ, а не `type`-объявления")

			listed := backtickedIdents(headerPerDomainBlock(t, dsl))
			require.NotEmpty(t, listed, "разбор перечня шапки пуст")

			// Те же множества, что в боевом гейте: тело минус документированные
			// исключения.
			want := map[string]bool{}
			for _, typ := range gotBody {
				if nonGrantableModelTypes[typ] != "" || structuralParentTypes[typ] != "" {
					continue
				}
				want[typ] = true
			}
			got := map[string]bool{}
			for _, typ := range listed {
				got[typ] = true
			}

			var phantom, missing []string
			for typ := range got {
				if !want[typ] {
					phantom = append(phantom, typ)
				}
			}
			for typ := range want {
				if !got[typ] {
					missing = append(missing, typ)
				}
			}
			sort.Strings(phantom)
			sort.Strings(missing)

			require.Equal(t, tc.wantPhantom, nilIfEmpty(phantom), "фантомы")
			require.Equal(t, tc.wantMissing, nilIfEmpty(missing), "пропущенные")

			// МОЛЧАЛИВОЕ НАПРАВЛЕНИЕ, явно: `user` (не-грантуемый) и `project`
			// (структурный) лежат в теле КАЖДОЙ фикстуры и не перечислены в шапке
			// ни разу. Ни один случай не вправе объявить их пропущенными — иначе
			// исключения не работают и гейт грубее своего предмета.
			require.NotContains(t, missing, "user", "субъектный тип потребован в перечне ресурсных")
			require.NotContains(t, missing, "project", "структурный родитель потребован в перечне ресурсных")
		})
	}
}

// nilIfEmpty — пустой срез и nil должны сравниваться одинаково, чтобы ожидание
// в таблице писалось без церемоний.
func nilIfEmpty(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return s
}

// modelTypeMention — имя типа модели, упомянутое в прозе. Приставка домена —
// признак структурный: типы модели именуются `<домен>_<ресурс>`, и ни одно
// обычное слово этих приставок не несёт.
var modelTypeMention = regexp.MustCompile(`\b((?:vpc|compute|storage|nlb|iam|registry)_[a-z_0-9]+)\b`)

// TestChartPreambleNamesNoRetiredType — преамбула сгенерированного чарта не
// вправе называть тип, которого модель больше не объявляет.
//
// # Почему это отдельная поверхность
//
// `openfga-model-stub-configmap.yaml` генерируется из канонической модели, но
// генератор переписывает файл ТОЛЬКО начиная с `data:`
// (`gen-openfga-model-configmap.py`: `lines[:data_idx] + data + lines[end_idx:]`).
// Всё, что выше, — рукописная преамбула `{{/* … */}}`, до которой регенерация не
// доходит. Поэтому она пережила и снятие типа, и мою правку шапки: копия
// перечня, лежащая в трёх экранах от оригинала, расходилась с ним молча.
//
// Померено на bdafe2c4: преамбула называла `iam_condition` (снят, надгробие в
// теле) и молчала про `nlb_listener`, `registry_registry`, `registry_repository`.
// Перечень оттуда УБРАН — дублировать список, лежащий ниже в том же файле,
// незачем: независимости это не давало, а вторую поверхность правки создавало.
//
// # Что именно проверяется
//
// Не «списка нет» (это запрет по форме, который обходится переписыванием), а
// «нет ПРОСРОЧЕННОГО имени»: любое упоминание `<домен>_<ресурс>` в преамбуле
// обязано соответствовать живому `type` в модели. Предикат самоистекающий —
// пока имена живые, он молчит; как только тип снимут, преамбула краснеет вместе
// с ним. Живое упоминание остаётся законным: гейт запрещает ложь, а не прозу.
func TestChartPreambleNamesNoRetiredType(t *testing.T) {
	root := monorepoRoot(t)

	dslRaw, err := os.ReadFile(filepath.Join(root, canonicalModelRelPath))
	require.NoErrorf(t, err, "канонический %s не прочитан", canonicalModelRelPath)
	body := map[string]bool{}
	for _, typ := range modelBodyTypes(string(dslRaw)) {
		body[typ] = true
	}
	require.NotEmpty(t, body, "в модели не разобрано ни одного `type` — сломан разбор, а не «преамбула чиста»")

	cmRaw, err := os.ReadFile(filepath.Join(root, configMapRelPath))
	require.NoErrorf(t, err, "чарт %s не прочитан", configMapRelPath)

	// Преамбула — всё, что ДО `data:`: ровно та часть, которую генератор не
	// переписывает и за которой поэтому никто не следит.
	idx := strings.Index(string(cmRaw), "\ndata:")
	require.Positivef(t, idx, "в %s не найден ключ `data:` — граница преамбулы не определяется, "+
		"и «упоминаний нет» значило бы «нечем было искать»", configMapRelPath)
	preamble := string(cmRaw)[:idx]

	mentions := map[string]bool{}
	for _, m := range modelTypeMention.FindAllStringSubmatch(preamble, -1) {
		mentions[m[1]] = true
	}

	var stale []string
	for typ := range mentions {
		if !body[typ] {
			stale = append(stale, typ)
		}
	}
	sort.Strings(stale)

	t.Logf("осмотрено: преамбула чарта %d байт, упомянуто типов модели %d, живых `type` в модели %d",
		len(preamble), len(mentions), len(body))

	for _, typ := range stale {
		t.Errorf("преамбула %s называет `%s`, а модель такой тип не объявляет.\n\n"+
			"Генератор переписывает файл только начиная с `data:`, поэтому преамбула "+
			"переживает и снятие типа, и правку канонической шапки — молча. Убери имя "+
			"либо верни тип в модель.", configMapRelPath, typ)
	}
}

// TestChartPreamblePredicateCutsBothWays — предикат просроченного упоминания
// проверен инъекцией в обе стороны на синтетическом входе.
//
// Без положительного направления «просроченных нет» неотличимо от предиката,
// который просроченное видеть не умеет; без отрицательного — от запрета называть
// типы вообще, который снёс бы законную прозу.
func TestChartPreamblePredicateCutsBothWays(t *testing.T) {
	// Живые типы фикстуры. `iam_user` здесь ОБЯЗАТЕЛЕН: он стоит рядом со снятым
	// в проверке ниже, и без него предикат пометил бы просроченным ещё и его —
	// то есть красное направление доказывалось бы совпадением, а не предметом.
	body := map[string]bool{"vpc_network": true, "nlb_listener": true, "iam_user": true}

	staleOf := func(text string) []string {
		var out []string
		seen := map[string]bool{}
		for _, m := range modelTypeMention.FindAllStringSubmatch(text, -1) {
			if !body[m[1]] && !seen[m[1]] {
				seen[m[1]] = true
				out = append(out, m[1])
			}
		}
		sort.Strings(out)
		return out
	}

	// (а) КРАСНОЕ: снятый тип назван — ровно тот дефект, что был в дереве.
	require.Equal(t, []string{"iam_condition"},
		staleOf("IAM resource-types: iam_user / iam_condition."),
		"просроченное упоминание не поймано")
	require.Equal(t, []string{"iam_condition", "storage_image"},
		staleOf("covers vpc_network / storage_image / iam_condition"),
		"поймано не всё просроченное")

	// (б) МОЛЧАЛИВОЕ: живые типы и обычная проза той же формы.
	require.Empty(t, staleOf("covers vpc_network and nlb_listener"),
		"живое упоминание объявлено просроченным — гейт запрещает прозу, а не ложь")
	require.Empty(t, staleOf("bootstrap job performs idempotent deploy; see model_id secret"),
		"обычные слова приняты за имена типов — приставка домена перестала быть дискриминатором")
}

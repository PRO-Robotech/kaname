// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

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

// Здесь стояли TestChartPreambleNamesNoRetiredType и парная к ней
// TestChartPreamblePredicateCutsBothWays: первая читала РУКОПИСНУЮ преамбулу
// сгенерированной карты чарта — ту часть файла, до которой генератор не доходил,
// — и требовала, чтобы ни одно упомянутое в ней имя типа не пережило снятия
// этого типа из модели; вторая доказывала предикат просроченного упоминания
// инъекцией в обе стороны.
//
// Обе сняты ВМЕСТЕ СО СВОИМ ПРЕДМЕТОМ: ни карты, ни подчарта загрузки движка
// отношений, ни генератора в дереве нет — движок снят целиком (S6). Второй
// поверхности правки, ради которой гейт и заводился, больше не существует: у
// канонической модели осталась одна производная — вшитая копия
// `services/iam/internal/authzmodel/fga_model.fga`, и она порождается ЦЕЛИКОМ,
// рукописной части в ней нет вовсе, а побайтовое равенство пары держит
// `TestEmbeddedModelIsByteIdenticalToCanonical` того пакета.
//
// Проба, доказывающая предикат, снята вместе с ним по той же причине, по какой
// заводилась: без потребителя она утверждала бы свойство функции, которую никто
// не зовёт, — то есть занимала бы слот и отчитывалась зелёным.
//
// Что от урока осталось действующим и живёт выше по файлу: перечень имён,
// лежащий в другом месте того же документа, расходится с оригиналом МОЛЧА, и
// ловить надо не «список есть», а «названо просроченное».

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_parity_test.go — СВОЯ проба стража старта (приёмка
// services/iam/docs/engineering/acceptance/module-withdrawal-is-described.md,
// отрицание Н7 и §3.4; задача продукта #1861).
//
// # Зачем она, если страж уже краснеет в интеграционной пробе
//
// До неё способность `AssertCatalogParity` отказать доказывалась ПОБОЧНО —
// последним утверждением чужой пробы снимка
// (`repo/kacho/pg/catalog_snapshot_integration_test.go`, IAM-MW-1-19). Побочное
// доказательство несёт два дефекта сразу. Первое: оно требует Postgres, поэтому
// исчезает из всякого прогона, где контейнера нет, — и исчезает МОЛЧА, вместе с
// вердиктом о страже. Второе: чужая проба утверждает ОДИН вход (снятая строка
// живого типа) и ничего не говорит ни о лишней строке, ни о перевёрнутом
// признаке словаря, ни о том, называет ли отказ строку по имени. Приёмка это и
// называет: «у стража старта нет своей пробы» (Н7).
//
// # Вход ПРОИЗВОДИТСЯ, а не выписывается
//
// Полное множество берётся у того же производителя, которым страж судит, —
// `LiteralRows()`. Выписанная от руки фикстура разошлась бы с ним молча при
// первой же правке каталога и проверяла бы свою копию вместо предмета. Порча
// описывается ПРЕОБРАЗОВАНИЕМ этого множества, а не готовым набором строк, по
// той же причине.
//
// Отсюда обязанность, которую набор исполняет первым делом: если производитель
// входа отдал пустое множество, набор БЕСПРЕДМЕТЕН и обязан упасть громко.
// «Ноль находок» иначе неотличимо от «ноль прочитанного».
//
// # Инъекция ломает РОВНО ОДНО свойство, и рядом стоит законный близнец
//
// Каждая строка набора снимает у входа одну величину и объявляет, что именно
// отказ обязан назвать. Нетронутое множество идёт первой строкой и обязано
// пройти: без него отрицания зеленели бы на страже, который отвергает всё.
//
// # Что этот набор НЕ утверждает
//
// Он ничего не говорит о том, ОТКУДА берётся опорная сторона: сегодня это
// перечень, порождённый сборкой из манифестов дерева (`authzmap` порождается из
// `services/*/manifest.yaml`). Смени источник — производитель входа этого набора
// сменится вместе с ним (`LiteralRows` заменится на новый), а утверждения
// переживут переезд: они про способность стража отказать, назвать строку и
// отличить снятое от непроехавшего, а не про то, кто написал «что должно
// существовать».
//
// # Что набор УТВЕРЖДАЕТ после #1861
//
// Опорная сторона судит как ВЕРХНЯЯ ГРАНИЦА, а не как равенство: живых строк
// вправе быть МЕНЬШЕ, если о пропавшей есть СНЯТАЯ строка. Поэтому у каждой
// инъекции теперь две половины входа — живая и снятая, — и снятое множество
// подаётся ВСЕГДА, в том числе пустым: строка, о снятии которой свидетельства
// нет, обязана остаться расхождением, иначе послабление накрыло бы и
// непроехавший посев.
package seed_test

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/seed"
	"github.com/PRO-Robotech/kacho-iam/internal/catalog"
)

// stubRowSource — порт чтения живого каталога, отдающий заранее собранное
// множество.
//
// Счётчик обращений — не украшение: страж отдаёт прочитанное наружу
// (`CatalogParityCensus.Live`) именно затем, чтобы снимок наполнялся ТЕМ ЖЕ
// чтением. Второй запрос об одном предмете разошёлся бы с первым молча, поэтому
// «обращений ровно одно» утверждается здесь, где это стоит одной строки.
type stubRowSource struct {
	rows catalog.Rows
	err  error
	// retired — СНЯТОЕ множество. Пустое по умолчанию: строка, о снятии которой
	// свидетельства нет, обязана оставаться расхождением.
	retired      catalog.Rows
	retiredErr   error
	calls        int
	retiredCalls int
}

func (s *stubRowSource) ReadLiveCatalog(_ context.Context) (catalog.Rows, error) {
	s.calls++
	if s.err != nil {
		return catalog.Rows{}, s.err
	}
	return s.rows, nil
}

func (s *stubRowSource) ReadRetiredCatalog(_ context.Context) (catalog.Rows, error) {
	s.retiredCalls++
	if s.retiredErr != nil {
		return catalog.Rows{}, s.retiredErr
	}
	return s.retired, nil
}

// errPortRefused — отказ порта. Собственный вид, чтобы утверждать оборачивание,
// а не совпадение текста.
var errPortRefused = errors.New("порт чтения каталога отказал")

// parityInjection — одно утверждение набора.
type parityInjection struct {
	// name — что испорчено либо что законно; попадает в текст находки.
	name string
	// mutate — порча входа. nil означает ЗАКОННОГО БЛИЗНЕЦА: множество идёт
	// стражу как есть, и страж обязан молчать.
	mutate func(catalog.Rows) catalog.Rows
	// wantErr — страж обязан отказать.
	wantErr bool
	// wantInText — подстроки, которые отказ обязан НАЗВАТЬ. Пустой перечень у
	// отказа запрещён: отказ, не называющий строку, посылает читателя искать не
	// там.
	wantInText []string
	// wantNotInText — то, чего в отказе быть НЕ должно. Нужно там, где два
	// предмета обязаны остаться различимыми: пустой каталог чинится применением
	// миграций, расхождение — повторным посевом.
	wantNotInText []string
	// wantMissing, wantExtra — сколько строк ожидается в каждой половине
	// расхождения. Утверждаются ОБЕ: одностороннее сравнение молчит ровно на
	// той строке, которой в литерале нет, — а она даёт правилу референт.
	wantMissing int
	wantExtra   int
	// retire — СНЯТОЕ множество, собранное из того же производителя входа. nil
	// означает «снятого нет вовсе»: тогда пропавшая живая строка обязана
	// остаться расхождением, а не сойти за снятую.
	retire func(catalog.Rows) catalog.Rows
	// wantWithdrawn — сколько строк литерала ожидается ЗАКОННО снятыми.
	// Утверждается отдельно от расхождения: «страж промолчал» и «страж промолчал
	// и назвал, что именно снято» — разные вещи, и первая зеленеет на страже,
	// который перестал смотреть вовсе.
	wantWithdrawn int
}

// TestCatalogParityGuardRefusesAndNamesTheRow — набор инъекций стража паритета
// каталога (Н7 приёмки module-withdrawal-is-described.md).
func TestCatalogParityGuardRefusesAndNamesTheRow(t *testing.T) {
	full := seed.LiteralRows()

	// ПРЕДПОСЫЛКА НАБОРА. Производитель входа обязан быть непуст: на пустом
	// множестве каждое отрицание ниже выполнялось бы тривиально, а страж
	// отвечал бы «каталог пуст» на любую инъекцию.
	if len(full.Modules) == 0 || len(full.Resources) == 0 || len(full.Verbs) == 0 {
		t.Fatalf("производитель входа пуст: модулей/ресурсов/глаголов %d/%d/%d — "+
			"набор беспредметен, и его молчание неотличимо от исправной работы",
			len(full.Modules), len(full.Resources), len(full.Verbs))
	}
	t.Logf("перепись входа: модулей %d, ресурсов %d, глаголов %d",
		len(full.Modules), len(full.Resources), len(full.Verbs))

	// Строки, которые снимаются, выбираются ДЕТЕРМИНИРОВАННО — первой по
	// сортированному ключу, а не «какая попалась». Порядок перечня литерала
	// свойством контракта не является, и проба, зависящая от него, краснела бы
	// на перестановке, ничего не менявшей.
	dropResource := firstResourceKey(full)
	dropVerb := firstVerbKey(full)
	dropModule := firstModule(full)

	cases := []parityInjection{
		{
			// ЗАКОННЫЙ БЛИЗНЕЦ. Без него всё, что ниже, зеленело бы на страже,
			// который отвергает любой вход.
			name:    "полное множество — страж молчит",
			mutate:  nil,
			wantErr: false,
		},
		{
			name: "нет строки ресурса " + dropResource,
			mutate: func(r catalog.Rows) catalog.Rows {
				r.Resources = dropResourceRow(r.Resources, dropResource)
				return r
			},
			wantErr:     true,
			wantInText:  []string{"ресурс " + dropResource, "нет строкой"},
			wantMissing: 1,
			wantExtra:   0,
		},
		{
			name: "нет строки глагола " + dropVerb.key,
			mutate: func(r catalog.Rows) catalog.Rows {
				r.Verbs = dropVerbRow(r.Verbs, dropVerb)
				return r
			},
			wantErr:     true,
			wantInText:  []string{"глагол " + dropVerb.key},
			wantMissing: 1,
			wantExtra:   0,
		},
		{
			name: "нет строки модуля " + dropModule,
			mutate: func(r catalog.Rows) catalog.Rows {
				r.Modules = dropString(r.Modules, dropModule)
				return r
			},
			wantErr:     true,
			wantInText:  []string{"модуль " + dropModule},
			wantMissing: 1,
			wantExtra:   0,
		},
		{
			// ВТОРАЯ ПОЛОВИНА СРАВНЕНИЯ. Строка, которой в опорном множестве
			// нет, даёт правилу референт, по которому оно резолвится, — а
			// проекция такой строки не производит. Одностороннее сравнение
			// молчит здесь и только здесь.
			name: "лишняя живая строка ресурса вне опорного множества",
			mutate: func(r catalog.Rows) catalog.Rows {
				r.Resources = append(append([]catalog.ResourceRow{}, r.Resources...),
					catalog.ResourceRow{Module: "vpc", Resource: "nonesuch"})
				return r
			},
			wantErr:     true,
			wantInText:  []string{"нет в опоре", "ресурс vpc.nonesuch"},
			wantMissing: 0,
			wantExtra:   1,
		},
		{
			// ПРИЗНАК СЛОВАРЯ ВХОДИТ В КЛЮЧ. Строка с перевёрнутым признаком
			// существует в обоих множествах, и по тройке «модуль.ресурс.глагол»
			// сверка прошла бы молча — разошлись бы ровно те две величины, ради
			// которых словари и разделены.
			name: "признак словаря перевёрнут у " + dropVerb.key,
			mutate: func(r catalog.Rows) catalog.Rows {
				out := append([]catalog.VerbRow{}, r.Verbs...)
				for i := range out {
					if verbTriple(out[i]) == dropVerb.triple && out[i].PerObject == dropVerb.perObject {
						out[i].PerObject = !out[i].PerObject
						break
					}
				}
				r.Verbs = out
				return r
			},
			wantErr: true,
			wantInText: []string{
				"глагол " + dropVerb.key,
				"глагол " + dropVerb.triple + kindSuffix(!dropVerb.perObject),
			},
			wantMissing: 1,
			wantExtra:   1,
		},
		{
			// ДВА ПРЕДМЕТА, А НЕ ОДИН. Пустой каталог чинится применением
			// миграций, расхождение — повторным посевом; схлопнув их в один
			// отказ, оператор чинил бы не то.
			name:          "каталог пуст — отказ называет пустоту, а не расхождение",
			mutate:        func(catalog.Rows) catalog.Rows { return catalog.Rows{} },
			wantErr:       true,
			wantInText:    []string{"каталог модуля пуст", "0/0/0"},
			wantNotInText: []string{"разошлись"},
		},
		{
			// ПРЕДМЕТ #1861. Строка СНЯТА решением — живой её нет, снятая есть.
			// Это не расхождение: снятие и есть та операция, ради которой у
			// каждой из трёх таблиц заведены `retired_at` / `retired_reason` /
			// `live`. Отказ здесь означал бы, что снять строку нельзя иначе как
			// пересборкой образа, — то есть опорой стража остаётся то, что он
			// обязан пережить.
			name: "строка глагола СНЯТА — страж молчит и называет снятое",
			mutate: func(r catalog.Rows) catalog.Rows {
				r.Verbs = dropVerbRow(r.Verbs, dropVerb)
				return r
			},
			retire: func(full catalog.Rows) catalog.Rows {
				return catalog.Rows{Verbs: pickVerbRow(full.Verbs, dropVerb)}
			},
			wantErr:       false,
			wantWithdrawn: 1,
		},
		{
			// ТА ЖЕ ОПЕРАЦИЯ НА РЕСУРСЕ, вместе с его действиями: ключ живости
			// `catalog_verb_resource_live_fk` не допускает живого действия у
			// снятого ресурса, поэтому снятие приходит связкой, и проба обязана
			// подавать его связкой — иначе она утверждала бы о состоянии,
			// которого база не производит.
			name: "строка ресурса СНЯТА вместе со своими действиями — страж молчит",
			mutate: func(r catalog.Rows) catalog.Rows {
				r.Resources = dropResourceRow(r.Resources, dropResource)
				r.Verbs = dropVerbsOfResource(r.Verbs, dropResource)
				return r
			},
			retire: func(full catalog.Rows) catalog.Rows {
				return catalog.Rows{
					Resources: pickResourceRow(full.Resources, dropResource),
					Verbs:     pickVerbsOfResource(full.Verbs, dropResource),
				}
			},
			wantErr:       false,
			wantWithdrawn: 1 + verbsOfResource(full, dropResource),
		},
		{
			// СВИДЕТЕЛЬСТВО ОБЯЗАТЕЛЬНО. Та же пропавшая строка БЕЗ снятой —
			// по-прежнему расхождение: «строка снята решением» и «строка не
			// доехала вовсе» снаружи выглядят одинаково, и различает их ровно
			// наличие снятой строки.
			name: "строка глагола пропала БЕЗ снятой — расхождение остаётся",
			mutate: func(r catalog.Rows) catalog.Rows {
				r.Verbs = dropVerbRow(r.Verbs, dropVerb)
				return r
			},
			retire:      nil,
			wantErr:     true,
			wantInText:  []string{"глагол " + dropVerb.key, "нет строкой"},
			wantMissing: 1,
			wantExtra:   0,
		},
		{
			// СНЯТИЕ НЕ ПРИКРЫВАЕТ ЛИШНЮЮ СТРОКУ. Свидетельство о снятии
			// действует только в ту сторону, где живых строк МЕНЬШЕ. Живая
			// строка вне литерала остаётся отказом при любом снятом множестве:
			// доставка оператора не вправе расширить каталог за пределы того,
			// что знает образ.
			name: "лишняя живая строка при НЕПУСТОМ снятом множестве — отказ",
			mutate: func(r catalog.Rows) catalog.Rows {
				r.Resources = append(append([]catalog.ResourceRow{}, r.Resources...),
					catalog.ResourceRow{Module: "vpc", Resource: "nonesuch"})
				return r
			},
			retire: func(full catalog.Rows) catalog.Rows {
				return catalog.Rows{Verbs: pickVerbRow(full.Verbs, dropVerb)}
			},
			wantErr:    true,
			wantInText: []string{"нет в опоре", "ресурс vpc.nonesuch"},
			wantExtra:  1,
		},
		{
			// ВЕСЬ КАТАЛОГ СНЯТ — тоже отказ, но ДРУГОЙ. Пустое живое множество
			// отвергло бы все правила разом, поэтому старт отказан в обоих
			// случаях; чинятся они противоположно, и текст обязан их различать.
			name:   "весь каталог снят — отказ называет снятие, а не непринятые миграции",
			mutate: func(catalog.Rows) catalog.Rows { return catalog.Rows{} },
			retire: func(full catalog.Rows) catalog.Rows { return full },
			// Снятыми оказываются ВСЕ строки литерала. Число не выписано, а
			// выведено из того же производителя входа: выписанное разошлось бы
			// с ним молча при первой правке каталога.
			wantWithdrawn: len(full.Modules) + len(full.Resources) + len(full.Verbs),
			wantErr:       true,
			wantInText:    []string{"снят"},
			wantNotInText: []string{"миграц"},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows := cloneRows(full)
			if tc.mutate != nil {
				rows = tc.mutate(rows)
			}
			var retired catalog.Rows
			if tc.retire != nil {
				retired = tc.retire(cloneRows(full))
			}
			src := &stubRowSource{rows: rows, retired: retired}
			census, err := seed.AssertCatalogParity(context.Background(), src, seed.ImageAnchor())

			// Обращение к порту РОВНО ОДНО: прочитанное отдаётся наружу, чтобы
			// снимок не заводил своего запроса.
			if src.calls != 1 {
				t.Errorf("обращений к порту %d, ожидалось 1 — второй запрос об одном "+
					"предмете разошёлся бы с первым молча", src.calls)
			}
			// Снятое спрашивается РОВНО ОДИН раз и спрашивается ВСЕГДА: страж,
			// не сходивший за снятым, отличить «снято решением» от «не доехало»
			// не может ничем, а молчит он при этом так же.
			if src.retiredCalls != 1 {
				t.Errorf("обращений за снятым множеством %d, ожидалось 1 — без него "+
					"«снято решением» неотличимо от «строка не доехала»", src.retiredCalls)
			}
			// Перепись печатается ВСЕГДА, независимо от исхода.
			t.Logf("перепись стража: опора %d/%d/%d, строки %d/%d/%d, снятые %d/%d/%d, "+
				"нет строкой %d, снято решением %d, нет в опоре %d",
				census.AnchorModules, census.AnchorResources, census.AnchorVerbs,
				census.RowModules, census.RowResources, census.RowVerbs,
				census.RetiredModules, census.RetiredResources, census.RetiredVerbs,
				len(census.MissingRows), len(census.WithdrawnRows), len(census.ExtraRows))

			if len(census.WithdrawnRows) != tc.wantWithdrawn {
				t.Errorf("снятых строк %d, ожидалось %d: %v — «страж промолчал» и «страж "+
					"промолчал и назвал, ЧТО снято» разные вещи, и первое зеленеет на страже, "+
					"переставшем смотреть вовсе",
					len(census.WithdrawnRows), tc.wantWithdrawn, census.WithdrawnRows)
			}

			if !tc.wantErr {
				if err != nil {
					t.Fatalf("страж отказал на законном входе: %v", err)
				}
				if census.Diverged() {
					t.Fatalf("расхождение на законном входе: нет строкой %v; нет в опоре %v",
						census.MissingRows, census.ExtraRows)
				}
				return
			}

			if err == nil {
				t.Fatalf("страж МОЛЧИТ на испорченном входе — способность отказать не доказана; "+
					"перепись: нет строкой %v; нет в опоре %v", census.MissingRows, census.ExtraRows)
			}
			if len(tc.wantInText) == 0 {
				t.Fatalf("утверждение объявляет отказ и не называет, что отказ обязан сказать — " +
					"такое утверждение зеленеет на любом тексте")
			}
			for _, want := range tc.wantInText {
				if !strings.Contains(err.Error(), want) {
					t.Errorf("отказ не называет %q\nтекст: %s", want, err.Error())
				}
			}
			for _, unwanted := range tc.wantNotInText {
				if strings.Contains(err.Error(), unwanted) {
					t.Errorf("отказ называет %q — два разных предмета схлопнуты в один\nтекст: %s",
						unwanted, err.Error())
				}
			}
			if tc.wantMissing != 0 || tc.wantExtra != 0 {
				if len(census.MissingRows) != tc.wantMissing {
					t.Errorf("нет строкой %d, ожидалось %d: %v",
						len(census.MissingRows), tc.wantMissing, census.MissingRows)
				}
				if len(census.ExtraRows) != tc.wantExtra {
					t.Errorf("нет в опоре %d, ожидалось %d: %v",
						len(census.ExtraRows), tc.wantExtra, census.ExtraRows)
				}
			}
		})
	}
}

// TestCatalogParityGuardReportsCensusWhenThePortRefuses — отказ ПОРТА отличается
// от расхождения и от пустоты: чинится он третьим способом (недоступна база), и
// объём осмотренного обязан быть напечатан и здесь.
func TestCatalogParityGuardReportsCensusWhenThePortRefuses(t *testing.T) {
	src := &stubRowSource{err: errPortRefused}
	census, err := seed.AssertCatalogParity(context.Background(), src, seed.ImageAnchor())
	if err == nil {
		t.Fatalf("страж молчит при отказавшем порте — непрочитанный каталог не есть «каталог сошёлся»")
	}
	if !errors.Is(err, errPortRefused) {
		t.Errorf("отказ порта не обёрнут: %v — вызывающий не отличит недоступную базу от расхождения", err)
	}
	if census.AnchorModules == 0 || census.AnchorResources == 0 || census.AnchorVerbs == 0 {
		t.Errorf("перепись опорной стороны не заполнена (%d/%d/%d) — «ноль расхождений» "+
			"неотличимо от «ноль прочитанного»",
			census.AnchorModules, census.AnchorResources, census.AnchorVerbs)
	}
	if census.RowModules != 0 || census.RowResources != 0 || census.RowVerbs != 0 {
		t.Errorf("перепись живой стороны непуста (%d/%d/%d) при отказавшем порте",
			census.RowModules, census.RowResources, census.RowVerbs)
	}
}

// ── вспомогательное: детерминированный выбор строки и порча множества ─────────

type verbPick struct {
	triple    string
	perObject bool
	key       string
}

func kindSuffix(perObject bool) string {
	if perObject {
		return " (пообъектный)"
	}
	return " (ярусный)"
}

func verbTriple(v catalog.VerbRow) string {
	return v.Module + "." + v.Resource + "." + v.Verb
}

func firstModule(r catalog.Rows) string {
	out := append([]string{}, r.Modules...)
	sort.Strings(out)
	return out[0]
}

func firstResourceKey(r catalog.Rows) string {
	keys := make([]string, 0, len(r.Resources))
	for _, res := range r.Resources {
		keys = append(keys, res.Module+"."+res.Resource)
	}
	sort.Strings(keys)
	return keys[0]
}

func firstVerbKey(r catalog.Rows) verbPick {
	keys := make([]string, 0, len(r.Verbs))
	index := map[string]catalog.VerbRow{}
	for _, v := range r.Verbs {
		k := verbTriple(v) + kindSuffix(v.PerObject)
		keys = append(keys, k)
		index[k] = v
	}
	sort.Strings(keys)
	v := index[keys[0]]
	return verbPick{triple: verbTriple(v), perObject: v.PerObject, key: keys[0]}
}

func cloneRows(r catalog.Rows) catalog.Rows {
	return catalog.Rows{
		Modules:   append([]string{}, r.Modules...),
		Resources: append([]catalog.ResourceRow{}, r.Resources...),
		Verbs:     append([]catalog.VerbRow{}, r.Verbs...),
	}
}

// dropResourceRow снимает ОДНУ строку и падает, если снимать было нечего:
// инъекция, ничего не испортившая, проверяла бы законный вход.
func dropResourceRow(in []catalog.ResourceRow, dotted string) []catalog.ResourceRow {
	out := make([]catalog.ResourceRow, 0, len(in))
	dropped := 0
	for _, r := range in {
		if r.Module+"."+r.Resource == dotted && dropped == 0 {
			dropped++
			continue
		}
		out = append(out, r)
	}
	if dropped != 1 {
		panic(fmt.Sprintf("инъекция не сняла строку ресурса %q (снято %d)", dotted, dropped))
	}
	return out
}

func dropVerbRow(in []catalog.VerbRow, pick verbPick) []catalog.VerbRow {
	out := make([]catalog.VerbRow, 0, len(in))
	dropped := 0
	for _, v := range in {
		if verbTriple(v) == pick.triple && v.PerObject == pick.perObject && dropped == 0 {
			dropped++
			continue
		}
		out = append(out, v)
	}
	if dropped != 1 {
		panic(fmt.Sprintf("инъекция не сняла строку глагола %q (снято %d)", pick.key, dropped))
	}
	return out
}

func dropString(in []string, want string) []string {
	out := make([]string, 0, len(in))
	dropped := 0
	for _, s := range in {
		if s == want && dropped == 0 {
			dropped++
			continue
		}
		out = append(out, s)
	}
	if dropped != 1 {
		panic(fmt.Sprintf("инъекция не сняла модуль %q (снято %d)", want, dropped))
	}
	return out
}

// ── вспомогательное: сборка СНЯТОГО множества из того же производителя ───────
//
// Снятое собирается ВЫБОРКОЙ из полного множества, а не выписывается: выписанная
// строка разошлась бы с производителем молча при первой правке каталога, и проба
// сверяла бы свою копию вместо предмета. Каждая выборка падает на пустом
// результате — инъекция, ничего не выбравшая, подала бы стражу пустое снятое
// множество и утверждала бы совсем другое.

func pickVerbRow(in []catalog.VerbRow, pick verbPick) []catalog.VerbRow {
	for _, v := range in {
		if verbTriple(v) == pick.triple && v.PerObject == pick.perObject {
			return []catalog.VerbRow{v}
		}
	}
	panic(fmt.Sprintf("строка глагола %q в производителе входа не найдена", pick.key))
}

func pickResourceRow(in []catalog.ResourceRow, dotted string) []catalog.ResourceRow {
	for _, r := range in {
		if r.Module+"."+r.Resource == dotted {
			return []catalog.ResourceRow{r}
		}
	}
	panic(fmt.Sprintf("строка ресурса %q в производителе входа не найдена", dotted))
}

func pickVerbsOfResource(in []catalog.VerbRow, dotted string) []catalog.VerbRow {
	out := make([]catalog.VerbRow, 0, 8)
	for _, v := range in {
		if v.Module+"."+v.Resource == dotted {
			out = append(out, v)
		}
	}
	if len(out) == 0 {
		panic(fmt.Sprintf("у ресурса %q в производителе входа ни одного действия", dotted))
	}
	return out
}

func dropVerbsOfResource(in []catalog.VerbRow, dotted string) []catalog.VerbRow {
	out := make([]catalog.VerbRow, 0, len(in))
	dropped := 0
	for _, v := range in {
		if v.Module+"."+v.Resource == dotted {
			dropped++
			continue
		}
		out = append(out, v)
	}
	if dropped == 0 {
		panic(fmt.Sprintf("инъекция не сняла ни одного действия ресурса %q", dotted))
	}
	return out
}

func verbsOfResource(r catalog.Rows, dotted string) int {
	return len(pickVerbsOfResource(r.Verbs, dotted))
}

// TestCatalogParityGuardRefusesWhenTheRetiredSideCannotBeRead — НЕПРОЧИТАННОЕ
// снятое множество не есть «ничего не снято».
//
// Порт снятого отказал — значит вопрос «строка снята решением или не доехала
// вовсе?» остался без ответа, и пропускать старт на этом основании нельзя:
// отсутствие ответа не есть «да». Fail-closed здесь тот же, что у самого стража,
// и живая половина сверки его не заменяет: она при отказавшем снятом порте
// по-прежнему выглядит расхождением, то есть отказ был бы ВЕРНЫМ ПО ИСХОДУ и
// ложным по предмету — оператор пошёл бы чинить каталог вместо базы.
func TestCatalogParityGuardRefusesWhenTheRetiredSideCannotBeRead(t *testing.T) {
	full := seed.LiteralRows()
	if len(full.Resources) == 0 {
		t.Fatalf("производитель входа пуст — проба беспредметна")
	}

	src := &stubRowSource{rows: cloneRows(full), retiredErr: errPortRefused}
	census, err := seed.AssertCatalogParity(context.Background(), src, seed.ImageAnchor())
	if err == nil {
		t.Fatalf("страж молчит при отказавшем порте СНЯТОГО — непрочитанное снятое "+
			"множество принято за «ничего не снято»; перепись снятого %d/%d/%d",
			census.RetiredModules, census.RetiredResources, census.RetiredVerbs)
	}
	if !errors.Is(err, errPortRefused) {
		t.Errorf("отказ порта снятого не обёрнут: %v — вызывающий не отличит недоступную "+
			"базу от расхождения каталога", err)
	}
	if census.AnchorModules == 0 || census.AnchorResources == 0 || census.AnchorVerbs == 0 {
		t.Errorf("перепись опорной стороны не заполнена (%d/%d/%d) — «ноль расхождений» "+
			"неотличимо от «ноль прочитанного»",
			census.AnchorModules, census.AnchorResources, census.AnchorVerbs)
	}
}

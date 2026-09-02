// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

package seed

// catalog_parity.go — страж расхождения литерала и строк каталога.
//
// # Зачем это на СТАРТЕ, а не гейтом дерева
//
// Гейт дерева сверяет литерал с ТЕКСТОМ миграции и потому не знает ничего о
// базе, к которой служба подключилась. Между правкой литерала и повторным
// посевом существует состояние, в котором они расходятся, — и снаружи оно
// выглядит не как поломка, а как «прав не выдали»: правило, называющее тип,
// которого нет в таблице, отвергается ключом, а тип, которого нет в литерале, не
// получает пар. Мягкий проход здесь означал бы контроль, который не отказал ни
// разу за свою жизнь.
//
// # Почему ОТКАЗ СТАРТА, а не предупреждение
//
// Пустой каталог отверг бы ВСЕ правила разом, и это читалось бы как «продукт
// сломан», а не «условие не создано» (миграции не применены). Отказ старта
// называет предмет прямо и приходит ДО приёма запросов — то есть арендатор не
// видит ни одного ложного отказа.
//
// # Перепись печатается ВСЕГДА
//
// Обе величины — сколько прочитано из литерала и сколько из таблицы — выводятся
// независимо от исхода: «ноль расхождений» обязано быть отличимо от «ноль
// прочитанного».

import (
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kacho/services/iam/internal/authzmap"
	"github.com/PRO-Robotech/kacho/services/iam/internal/catalog"
	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// CatalogParityCensus — объём осмотренного и найденное расхождение.
type CatalogParityCensus struct {
	LiteralModules   int
	LiteralResources int
	LiteralVerbs     int
	RowModules       int
	RowResources     int
	RowVerbs         int
	// MissingRows — есть в литерале, нет живой строкой.
	MissingRows []string
	// ExtraRows — есть живой строкой, нет в литерале.
	ExtraRows []string
	// Live — ЖИВОЕ множество, прочитанное этой сверкой.
	//
	// Оно отдаётся наружу затем, чтобы снимок каталога наполнялся ТЕМ ЖЕ
	// чтением, а не своим: второй запрос об одном предмете — два места, и
	// разойдутся они молча. Величина, которую утверждает проба `-01`, —
	// РАВЕНСТВО операторов: за время старта со снимком их уходит ровно столько,
	// сколько шлёт сам страж.
	Live catalog.Rows
}

// Diverged — расхождение найдено хотя бы в одну сторону.
func (c CatalogParityCensus) Diverged() bool {
	return len(c.MissingRows) > 0 || len(c.ExtraRows) > 0
}

// Empty — таблиц каталога не прочитано ни строки. Отдельно от расхождения,
// потому что предмет другой: расхождение чинится повторным посевом, пустой
// каталог — применением миграций.
func (c CatalogParityCensus) Empty() bool {
	return c.RowModules == 0 && c.RowResources == 0 && c.RowVerbs == 0
}

// AssertCatalogParity сверяет ЖИВЫЕ строки каталога с литералом-источником и
// возвращает перепись вместе с исходом. Ошибка означает отказ старта.
//
// Строки приходят через ПОРТ, а не читаются здесь своим запросом. Причина — не
// слоистость: этим же чтением наполняется снимок каталога (`internal/catalog`),
// и завести ради него второй запрос об одном предмете значило бы получить два
// места, которые разойдутся молча. Порт читает ПУЛ, а не реплику: та отстаёт, а
// страж исполняется на старте, когда отставание наиболее вероятно, — прочитанный
// оттуда пустой каталог дал бы отказ старта на исправной службе.
func AssertCatalogParity(ctx context.Context, src catalog.RowSource) (CatalogParityCensus, error) {
	var c CatalogParityCensus

	want := LiteralRows()
	wantMod := setOf(want.Modules)
	wantRes := map[string]bool{}
	for _, r := range want.Resources {
		wantRes[r.Module+"."+r.Resource] = true
	}
	wantVerb := map[string]bool{}
	for _, v := range want.Verbs {
		wantVerb[verbKey(v)] = true
	}
	c.LiteralModules, c.LiteralResources, c.LiteralVerbs = len(wantMod), len(wantRes), len(wantVerb)

	live, err := src.ReadLiveCatalog(ctx)
	if err != nil {
		return c, fmt.Errorf("прочитать каталог модуля: %w", err)
	}
	c.Live = live

	gotMod := setOf(live.Modules)
	gotRes := map[string]bool{}
	for _, r := range live.Resources {
		gotRes[r.Module+"."+r.Resource] = true
	}
	gotVerb := map[string]bool{}
	for _, v := range live.Verbs {
		gotVerb[verbKey(v)] = true
	}
	c.RowModules, c.RowResources, c.RowVerbs = len(gotMod), len(gotRes), len(gotVerb)

	diffInto(&c.MissingRows, &c.ExtraRows, "модуль", wantMod, gotMod)
	diffInto(&c.MissingRows, &c.ExtraRows, "ресурс", wantRes, gotRes)
	diffInto(&c.MissingRows, &c.ExtraRows, "глагол", wantVerb, gotVerb)
	sort.Strings(c.MissingRows)
	sort.Strings(c.ExtraRows)

	switch {
	case c.Empty():
		return c, fmt.Errorf("каталог модуля пуст: строк catalog_module/catalog_resource/catalog_verb "+
			"прочитано 0/0/0 при %d/%d/%d в литерале — пустой каталог отверг бы ВСЕ правила разом, "+
			"и это читалось бы как поломка продукта, а не как непринятые миграции (kacho#1030, IAM-CT-1-16)",
			c.LiteralModules, c.LiteralResources, c.LiteralVerbs)
	case c.Diverged():
		return c, fmt.Errorf("литерал и строки каталога разошлись: нет строкой [%s]; нет в литерале [%s]. "+
			"Прочитано из литерала %d/%d/%d, строками %d/%d/%d. Расхождение снаружи выглядит как "+
			"«прав не выдали», поэтому старт отказан, а не продолжен (kacho#1030, IAM-CT-1-15)",
			strings.Join(c.MissingRows, ", "), strings.Join(c.ExtraRows, ", "),
			c.LiteralModules, c.LiteralResources, c.LiteralVerbs,
			c.RowModules, c.RowResources, c.RowVerbs)
	}
	return c, nil
}

// LiteralRows — каталог, каким его объявляет ЛИТЕРАЛ: тот же перечень, которым
// миграция посеяла строки и с которым их сверяет страж выше.
//
// Производитель перечня ОДИН (`authzmap.CatalogSeed*` + `domain.KnownModules`), и
// зовут его отсюда трое: посев миграции, гейт паритета дерева и этот страж.
// Второй производитель разошёлся бы с первым молча — ровно в тот момент, когда
// расхождение и опасно.
//
// Форма — та же `catalog.Rows`, что у живого множества, и это не совпадение: обе
// стороны сверки обязаны быть выражены одинаково, иначе сравнение начинает
// зависеть от того, кто как разложил свою сторону.
func LiteralRows() catalog.Rows {
	rows := catalog.Rows{Modules: domain.KnownModules()}
	for _, r := range authzmap.CatalogSeedResources() {
		rows.Resources = append(rows.Resources, catalog.ResourceRow{Module: r.Module, Resource: r.Resource})
	}
	for _, v := range authzmap.CatalogSeedVerbs() {
		rows.Verbs = append(rows.Verbs, catalog.VerbRow{
			Module: v.Module, Resource: v.Resource, Verb: v.Verb, PerObject: v.PerObject,
		})
	}
	return rows
}

// verbKey — ключ сверки строки глагола, несущий ПРИЗНАК СЛОВАРЯ.
//
// Признак входит в ключ намеренно: строка, посеянная с неверным признаком,
// существует в обоих множествах и по тройке (модуль, ресурс, глагол) сверку
// прошла бы молча — а разошлись бы при этом ровно те две величины, ради которых
// словари и разделены: что ключ пропускает и что материализуется. Так
// расхождение видно с ОБЕИХ сторон — «нет строкой» и «нет в литерале» разом.
func verbKey(v catalog.VerbRow) string {
	kind := " (ярусный)"
	if v.PerObject {
		kind = " (пообъектный)"
	}
	return v.Module + "." + v.Resource + "." + v.Verb + kind
}

func setOf(values []string) map[string]bool {
	out := make(map[string]bool, len(values))
	for _, v := range values {
		out[v] = true
	}
	return out
}

// diffInto — расхождение в ОБЕ стороны. Одностороннее сравнение (включение)
// молчало бы на строке, которой в литерале нет: она даёт правилу референт, по
// которому оно резолвится, а проекция — нет.
func diffInto(missing, extra *[]string, kind string, want, got map[string]bool) {
	for k := range want {
		if !got[k] {
			*missing = append(*missing, kind+" "+k)
		}
	}
	for k := range got {
		if !want[k] {
			*extra = append(*extra, kind+" "+k)
		}
	}
}

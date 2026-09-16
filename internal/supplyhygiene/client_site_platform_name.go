// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// client_site_platform_name.go — судья оси «клиентский сайт»: сайт
// документации называет продукт СВОИМ именем (kacho#2076, решение Р3 — «бренд в
// прозе»).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Сайт — единственное, что читает оператор, ставящий службу в чужом облаке, не
// открывая наш исходный код. Заголовок сайта и имя проекта были переименованы,
// а проза страниц — нет: 17 вхождений диакритической формы имени платформы на 13
// страницах из 29 (`6e9b94ab`), и в каждом страница называла СЕБЯ чужим именем —
// «tenant-контейнер платформы Kachō», «как Kachō решает, можно ли действие»,
// заглавие собственного сайта продукта.
//
// ─────────────────────────────────────────────────────────────────────────────
// КРИТЕРИЙ — САМОНАЗВАНИЕ ПРОТИВ ССЫЛКИ НА СОСЕДА
//
// Норма владельца: продукт наследует от платформы КОД, но не ИМЯ. На странице
// это различается вопросом «чьё свойство названо этим именем»:
//
//	свойство ЭТОГО продукта (его модель, его API, его ресурс, его репозиторий)
//	    — самоназвание; имя платформы здесь чужое, и страница правится;
//	предмет, у которого есть СВОЙ владелец вне продукта (документация соседнего
//	сервиса, ручка края, ряд общего измерителя, метка секрета, которую чеканит
//	фундамент, провайдер инфраструктуры, адрес задачи трекера, прежнее имя
//	схемы, которым страж старта объясняет оператору, что искать)
//	    — ссылка; правка сделала бы страницу ложной.
//
// Критерий отвечает человек, а не форма: одно и то же слово бывает и тем, и
// другим. Поэтому оставшееся имя не прощается признаком формы, а называется
// ПОИМЁННО — страница, токен, точное число, причина. Признак вида «токен
// начинается с приставки» освободил бы и те вхождения, ради которых ось заведена.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ТОКЕН, А НЕ СТРОКА ИЛИ СТРАНИЦА
//
// Запись по странице целиком простила бы новое самоназвание на странице, где уже
// есть законная ссылка; запись по номеру строки ломалась бы от любой правки выше
// неё. Токен различает `kacho-vpc` и отдельное слово прозы, а точное число
// краснеет на втором самоназвании той же формы.
package supplyhygiene

import (
	"fmt"
	"sort"
	"strings"
)

// ClientSiteStay — имя платформы, которое сайт вправе нести.
type ClientSiteStay struct {
	// Page — путь страницы относительно корня дерева.
	Page string
	// Token — токен целиком, как его возвращает PlatformNameHits.
	Token string
	// Count — точное число вхождений этого токена на странице.
	Count int
	// Why — чья это ссылка и почему правка сделала бы страницу ложной.
	Why string
}

// ClientSiteCensus — объём осмотренного.
type ClientSiteCensus struct {
	// Pages — файлов сайта прочитано.
	Pages int
	// PagesWithName — из них несущих имя платформы в любой форме.
	PagesWithName int
	// Hits и HitsDiacritic — вхождений всего и из них диакритической формой.
	Hits          int
	HitsDiacritic int
	// Stayed — вхождений, названных ведомостью поимённо.
	Stayed int
}

// InClientSite — принадлежит ли путь сайту: приставка каталога либо файл.
func InClientSite(rel string, surface []string) bool {
	return underAny(rel, surface)
}

// JudgeClientSitePlatformName судит сайт.
//
// corpus — путь → текст файлов сайта; stay — ведомость; surface — из чего сайт
// состоит (запись ведомости вне сайта — находка, а не прощение). Всё приходит
// параметрами: инъекция подаёт того же судью на синтетике.
func JudgeClientSitePlatformName(
	corpus map[string]string,
	stay []ClientSiteStay,
	surface []string,
) (ClientSiteCensus, []string) {
	type key struct{ page, token string }
	var (
		census   ClientSiteCensus
		findings []string
		counts   = map[key]int{}
		lines    = map[key][]int{}
	)

	pages := make([]string, 0, len(corpus))
	for rel := range corpus {
		pages = append(pages, rel)
	}
	sort.Strings(pages)
	for _, rel := range pages {
		census.Pages++
		hits := PlatformNameHits(corpus[rel])
		if len(hits) > 0 {
			census.PagesWithName++
		}
		for _, h := range hits {
			census.Hits++
			if h.Diacritic {
				census.HitsDiacritic++
			}
			k := key{rel, h.Token}
			counts[k]++
			lines[k] = append(lines[k], h.Line)
		}
	}

	entries := map[key]ClientSiteStay{}
	for _, e := range stay {
		k := key{e.Page, e.Token}
		switch {
		case !InClientSite(e.Page, surface):
			findings = append(findings, fmt.Sprintf("ведомость называет %s — это не страница "+
				"сайта, и прощать там нечего", e.Page))
			continue
		case e.Count <= 0 || strings.TrimSpace(e.Why) == "":
			findings = append(findings, fmt.Sprintf("запись ведомости %s «%s»: число обязано быть "+
				"положительным, а причина — названа (число %d)", e.Page, e.Token, e.Count))
			continue
		}
		if _, dup := entries[k]; dup {
			findings = append(findings, fmt.Sprintf("запись ведомости %s «%s» названа дважды",
				e.Page, e.Token))
			continue
		}
		entries[k] = e
	}

	keys := make([]key, 0, len(counts))
	for k := range counts {
		keys = append(keys, k)
	}
	sort.Slice(keys, func(i, j int) bool {
		if keys[i].page != keys[j].page {
			return keys[i].page < keys[j].page
		}
		return keys[i].token < keys[j].token
	})
	for _, k := range keys {
		n := counts[k]
		e, ok := entries[k]
		if !ok {
			for _, ln := range lines[k] {
				findings = append(findings, fmt.Sprintf("%s:%d: «%s» — страница называет имя "+
					"платформы, и ведомость его не называет: самоназвание правится на имя "+
					"продукта, ссылка на соседа вносится в ведомость с причиной", k.page, ln, k.token))
			}
			continue
		}
		if n != e.Count {
			findings = append(findings, fmt.Sprintf("%s «%s»: на странице %d вхождений, ведомость "+
				"называет %d (строки %v) — число держится точно: рост означает новое "+
				"самоназвание той же формы, спад — что ведомость отстала от страницы",
				k.page, k.token, n, e.Count, lines[k]))
			continue
		}
		census.Stayed += n
	}

	stale := make([]string, 0)
	for k, e := range entries {
		if counts[k] == 0 {
			stale = append(stale, fmt.Sprintf("записи ведомости нечего прощать: %s «%s» на "+
				"странице больше нет — снимите запись, иначе она молча простит СЛЕДУЮЩЕЕ "+
				"вхождение этой формы (причина записи: %s)", e.Page, e.Token, e.Why))
		}
	}
	sort.Strings(stale)
	findings = append(findings, stale...)
	return census, findings
}

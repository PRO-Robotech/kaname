// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migrator_showcase_name.go — извлечение для гейта «накатчик, названный на
// витрине Kaname, есть накатчик Kaname» (задача #17, порт семейства
// `kanamemigratorshowcase` с монорепо
// `internal/repohygiene/kanamemigratorshowcase.go`, снятого выносом службы —
// `kacho#2597`).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ — ВИТРИНА, а не дерево
//
// Критерий сформулирован со стороны клиента: «увидит ли это оператор чужого
// облака, НЕ ОТКРЫВАЯ наш исходный код». По полосе накатчика ответ был «да»
// сразу в пяти местах: спецификация пода (`kubectl describe`), клиентский
// документ установки, раздел «с чего начать» на сайте документации, перечень
// сторонних лицензий и текст отказа службы. То есть имя ЧУЖОЙ платформы
// доезжало до арендатора ИНСТРУКЦИЕЙ, которую он обязан выполнить.
//
// Судится ПОСТАВКА Kaname — дерево модуля, уезжающее арендатору целиком. Внутри
// поставки витрина — подмножество (документы, чарты, тексты, которые печатает
// служба), а остальное имя ПРОИЗВОДИТ либо о нём УТВЕРЖДАЕТ. Разойтись им
// нельзя: производитель и употребитель, назвавшие разное, дают под, чей
// init-контейнер зовёт несуществующий путь, а записка, назвавшая снятое имя, —
// утверждение, пережившее свой предмет.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО РАЗРЕЗ ЗАБРАЛ — НАЗВАНО ЧИСЛОМ
//
// Витрин у предка было ДВЕ: дерево модуля (`services/iam`) и подчарт зонта
// (`deploy/helm/umbrella/charts/kaname`). Здесь корень модуля И ЕСТЬ корень
// репозитория, а зонта нет: `git ls-files deploy/helm/umbrella | wc -l` → 0.
// Ушедшая половина была меньшей — и она не «не судится», а НЕ СУЩЕСТВУЕТ в этом
// дереве: её предмет уехал вместе с витриной платформы и судится там.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАКОННОЕ ИМЯ ВЫВОДИТСЯ У ПРОИЗВОДИТЕЛЯ, А НЕ ВЫПИСАНО
//
// Имя берётся разбором `cmd/migrator/main.go` — поля `Use` корневой команды, то
// есть ровно той строки, которую оператор набирает. Литерал здесь был бы вторым
// местом об одном предмете: он пережил бы следующее переименование молча, и
// гейт продолжал бы требовать имя, которого нет.
//
// Словарь ИМЁН ПРОДУКТОВ тоже выводится — `contractnaming.KnownOwners()`. Имя
// накатчика ОДНО НА ПРОДУКТ, а не на службу: у шести служб платформы он общий,
// у Kaname свой, поэтому различаются продукты, а не службы.
//
// ─────────────────────────────────────────────────────────────────────────────
// РАСПОЗНАВАТЕЛЬ СУДИТ ТОКЕН, А НЕ ПОДСТРОКУ
//
// Судится токен, оканчивающийся на `migrator`, и судится он ТОЛЬКО когда среди
// его сегментов, разделённых дефисом, стоит имя продукта. Иначе гейт краснел бы
// на `build-migrator` — цели сборки, которая имени платформы не несёт и
// предметом критерия не является. Замер этого дерева: таких токенов 15.
//
// СЕГМЕНТОМ, а не приставкой: `kacho-nlb-migrator` несёт имя платформы ВТОРЫМ
// словом от конца, и распознаватель, читающий только приставку, такую запись не
// отверг бы, а НЕ УВИДЕЛ — то есть дал бы молчание вместо находки.
//
// Форма ТОКЕНА, а не подстроки, закрывает три написания разом: голое имя
// (`kacho-migrator up`), путь установки (`/usr/local/bin/kacho-migrator`) и путь
// сборки (`bin/kacho-migrator`) — во всех трёх токен один и тот же.
//
// ОБЕ латинские формы имени платформы: обычная и диакритическая. Предикат,
// знающий одну, недобирает МОЛЧА (`printf 'Kachō\n' | grep -ci kacho` → 0).
// Диакритической формы рядом с накатчиком в дереве сегодня НОЛЬ — и это сказано
// числом переписи, а не умолчанием.
package supplyhygiene

import (
	"fmt"
	"regexp"
	"sort"
	"strings"
)

// MigratorTokenSuffix — чем оканчивается судимый токен.
const MigratorTokenSuffix = "migrator"

// migratorTokenRe — токен формы `…migrator`.
//
// В класс входят латиница, цифры, `_`, `.` и дефис плюс `ō` обеих регистров:
// диакритическая форма имени платформы — законное написание, и предикат,
// знающий одну форму, недобирает молча.
var migratorTokenRe = regexp.MustCompile(`[A-Za-z0-9_.\x{014d}\x{014c}-]*migrator\b`)

// MigratorShowcaseFinding — одно место витрины, назвавшее ЧУЖОЙ накатчик.
type MigratorShowcaseFinding struct {
	File  string
	Line  int
	Token string
	Own   string
}

func (f MigratorShowcaseFinding) String() string {
	return fmt.Sprintf("%s:%d — витрина называет накатчик %q, а накатчик этого продукта — %q. "+
		"Имя чужой платформы доезжает до арендатора инструкцией, которую он обязан выполнить: "+
		"под, чей init-контейнер зовёт несуществующий путь, либо документ, велящий набрать "+
		"команду, которой нет.",
		f.File, f.Line, f.Token, f.Own)
}

// MigratorShowcaseCensus — объём осмотренного.
type MigratorShowcaseCensus struct {
	FilesTracked int
	FilesExempt  int
	FilesRead    int
	// TokensSeen — токенов формы `…migrator` встречено ВСЕГО.
	TokensSeen int
	// TokensJudged — из них признано именем накатчика ПРОДУКТА.
	TokensJudged int
	// TokensOwn — из судимых названо своё.
	//
	// Печатается рядом с TokensJudged: одна величина скрывает ровно тот случай,
	// ради которого гейт заведён.
	TokensOwn int
	// TokensDiacritic — из судимых записано диакритической формой имени.
	TokensDiacritic int
	// ExemptReasons — причина изъятия → сколько файлов.
	ExemptReasons map[string]int
}

// MigratorShowcaseScan судит витрину.
//
// `files` — координата → содержимое; `products` — имена продуктов дерева;
// `own` — имя накатчика ЭТОГО продукта, прочитанное у производителя.
//
// Вызывающий отдаёт корпус сам: гейт берёт его из индекса git, инъекция — из
// синтетики, и разводить два источника внутри значило бы завести здесь вторую
// посадку.
func MigratorShowcaseScan(
	files map[string]string, products []string, own string,
) ([]MigratorShowcaseFinding, MigratorShowcaseCensus) {
	census := MigratorShowcaseCensus{ExemptReasons: map[string]int{}}

	product := make(map[string]bool, len(products)*2)
	for _, p := range products {
		product[strings.ToLower(p)] = true
	}
	// Диакритическая форма имени платформы — законное написание того же
	// продукта, и словарь обязан знать обе.
	for _, p := range products {
		product[diacriticFormOf(strings.ToLower(p))] = true
	}

	var findings []MigratorShowcaseFinding
	for _, rel := range sortedFileKeys(files) {
		census.FilesRead++
		body := files[rel]
		for _, m := range migratorTokenRe.FindAllStringIndex(body, -1) {
			token := body[m[0]:m[1]]
			census.TokensSeen++
			if !tokenNamesAProduct(token, product) {
				continue
			}
			census.TokensJudged++
			if strings.ContainsAny(token, "ōŌ") {
				census.TokensDiacritic++
			}
			if token == own {
				census.TokensOwn++
				continue
			}
			findings = append(findings, MigratorShowcaseFinding{
				File:  rel,
				Line:  strings.Count(body[:m[0]], "\n") + 1,
				Token: token,
				Own:   own,
			})
		}
	}
	return findings, census
}

// tokenNamesAProduct — стоит ли среди сегментов токена имя продукта.
//
// Сегмент приводится к части после последней точки: путь установки приезжает
// в токен вместе с приставкой (`bin.kacho-migrator` в конфигурации сборки), и
// сравнение целого сегмента такую запись НЕ УВИДЕЛО БЫ.
func tokenNamesAProduct(token string, product map[string]bool) bool {
	for _, seg := range strings.Split(strings.ToLower(token), "-") {
		if i := strings.LastIndexByte(seg, '.'); i >= 0 {
			seg = seg[i+1:]
		}
		if product[seg] {
			return true
		}
	}
	return false
}

// diacriticFormOf — диакритическая форма имени продукта.
//
// Правило одно и оно про ЭТО имя: долгая `o` на конце пишется `ō`. Общей
// транслитерации здесь не заводится — она порождала бы формы, которых в дереве
// нет, и словарь перестал бы быть перечнем написаний.
func diacriticFormOf(name string) string {
	if strings.HasSuffix(name, "o") {
		return strings.TrimSuffix(name, "o") + "ō"
	}
	return name
}

func sortedFileKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

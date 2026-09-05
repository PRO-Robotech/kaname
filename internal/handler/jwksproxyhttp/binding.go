// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package jwksproxyhttp

import (
	"fmt"
	"net/http"
	"sort"
	"strings"
	"time"
)

const (
	// keySetReadTimeout — свой предел времени на чтение источника нашей записи.
	keySetReadTimeout = 5 * time.Second

	// keySetCacheControl — срок годности НАШЕГО ответа. Величина ВЫБРАНА и
	// объявлена числом: это второе слагаемое арифметики отсрочки снятия ключа,
	// только со стороны публикатора. Она не превышает потолка, который
	// потребителю разрешено удерживать.
	keySetCacheControl = "public, max-age=300"

	// Опознавательные слова исходов нашей записи. Их два, и они РАЗНЫЕ, потому
	// что чинятся по-разному: источник не ответил — повтор осмыслен; ключей
	// нет вовсе — повтор не поможет, нужен ключ.
	reasonKeySetUnavailable = "jwks_keyset_unavailable"
	reasonKeySetEmpty       = "jwks_keyset_empty"
)

// Record — одна запись привязки «издатель → источник набора».
//
// Записей больше одной, и это следствие решения принимать двух издателей: у
// КАЖДОГО принимаемого издателя своя запись. Объединение наборов рассмотрено и
// отвергнуто — оно уничтожает ровно ту защиту, ради которой развязка и
// заводится: ключ одного издателя проверял бы токен, объявляющий другого.
type Record struct {
	// Issuer — принимаемый издатель. Ключ поиска, и ТОЛЬКО ключ поиска.
	Issuer string
	// Path — путь записи. ОБЪЯВЛЯЕТСЯ здесь, а не выводится из издателя.
	//
	// Производная конструкция «взять базовый адрес и приклеить издателя»
	// короче и запрещена по двум причинам сразу. Первая — про безопасность:
	// издатель приходит от предъявителя, то есть это недоверенный вход, и
	// значению от предъявителя не место в построении пути. Вторая — про
	// проверяемость: производный путь получается У ВСЯКОГО издателя, поэтому
	// состояние «записи источника нет» не наступает никогда, и страж старта
	// становится тождественно истинным — проверка остаётся в тексте, не имея
	// возможности упасть.
	Path string
	// Handler — обработчик записи: проекция ключницы для нашей, зеркало для
	// прежнего издателя.
	Handler http.Handler
}

// Binding — объявленная привязка «издатель → путь → обработчик».
type Binding struct {
	records  []Record
	byIssuer map[string]Record
}

// NewBinding строит привязку, ОТКАЗЫВАЯ в вырожденной.
//
// Это и есть страж старта записи источника: издатель, объявленный
// принимаемым, но не имеющий записи, — отказ в старте, а не молчаливый перебор
// записей подряд. Отказ здесь — третий экземпляр класса «пустое значение
// означает „не сужаем“», который дерево уже закрывает на двух других перечнях.
func NewBinding(records []Record) (Binding, error) {
	if len(records) == 0 {
		return Binding{}, fmt.Errorf("jwks binding: no key-set records declared — " +
			"a publisher with no records answers nobody, and every token of every issuer would be refused")
	}
	byIssuer := make(map[string]Record, len(records))
	byPath := make(map[string]string, len(records))
	for _, rec := range records {
		issuer := strings.TrimSpace(rec.Issuer)
		if issuer == "" {
			return Binding{}, fmt.Errorf("jwks binding: a record declares no issuer")
		}
		// Путь считается ПО СОДЕРЖАНИЮ, а не по длине строки: разделители без
		// сегментов дают непустую строку и пустой путь.
		if !usablePath(rec.Path) {
			return Binding{}, fmt.Errorf(
				"jwks binding: issuer %s is accepted but declares no usable key-set path (got %q) — "+
					"refusing to start rather than resolving it to a derived address", issuer, rec.Path)
		}
		if rec.Handler == nil {
			return Binding{}, fmt.Errorf("jwks binding: issuer %s declares a path with no handler behind it", issuer)
		}
		if _, dup := byIssuer[issuer]; dup {
			return Binding{}, fmt.Errorf("jwks binding: issuer %s is declared twice", issuer)
		}
		if other, dup := byPath[rec.Path]; dup {
			return Binding{}, fmt.Errorf(
				"jwks binding: path %s is claimed by both %s and %s — one path, one record",
				rec.Path, other, issuer)
		}
		byIssuer[issuer] = Record{Issuer: issuer, Path: rec.Path, Handler: rec.Handler}
		byPath[rec.Path] = issuer
	}
	out := Binding{byIssuer: byIssuer}
	for _, rec := range byIssuer {
		out.records = append(out.records, rec)
	}
	sort.Slice(out.records, func(i, j int) bool { return out.records[i].Path < out.records[j].Path })
	return out, nil
}

// usablePath отвечает, несёт ли объявленный путь хотя бы один сегмент.
func usablePath(path string) bool {
	if !strings.HasPrefix(path, "/") {
		return false
	}
	for _, seg := range strings.Split(path, "/") {
		if strings.TrimSpace(seg) != "" {
			return true
		}
	}
	return false
}

// Paths возвращает пути привязки.
//
// Всякий, кому нужен перечень путей публикации — проба замка «только внутри»,
// композиционный корень, страница развёртывания, — ВЫВОДИТ его отсюда.
// Выписанный перечень разошёлся бы с привязкой молча при появлении третьей
// записи, и утверждение о единственном маршруте осталось бы зелёным, уедь
// второй на внешнюю поверхность.
func (b Binding) Paths() []string {
	out := make([]string, 0, len(b.records))
	for _, rec := range b.records {
		out = append(out, rec.Path)
	}
	return out
}

// Records возвращает записи привязки.
func (b Binding) Records() []Record { return append([]Record(nil), b.records...) }

// PathOf резолвит объявленного издателя в путь его записи.
//
// Издатель употребляется ТОЛЬКО как ключ поиска в объявленной таблице: не
// резолвится — отказ. Ни одна часть пути, имени файла, ключа кэша или
// исходящего адреса из него не строится.
func (b Binding) PathOf(issuer string) (string, bool) {
	rec, ok := b.byIssuer[issuer]
	if !ok {
		return "", false
	}
	return rec.Path, true
}

// NewMux монтирует КАЖДУЮ запись привязки на свой путь.
//
// Возвращённый mux выставляется вызывающим на cluster-ВНУТРЕННЕМ слушателе —
// никогда на внешнем, и это относится к каждому пути, а не к первому из них.
func NewMux(b Binding) (*http.ServeMux, error) {
	if len(b.records) == 0 {
		return nil, fmt.Errorf("jwks mux: binding carries no records")
	}
	mux := http.NewServeMux()
	for _, rec := range b.records {
		mux.Handle(rec.Path, rec.Handler)
	}
	return mux, nil
}

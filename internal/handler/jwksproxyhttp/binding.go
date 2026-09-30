// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package jwksproxyhttp

import (
	"fmt"
	"net/http"
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

// Record — запись привязки «издатель → источник набора».
//
// Запись у публикатора ОДНА — наша. Вторая существовала ради прежнего
// издателя и ушла вместе с ним (kaname#361); объединять наборы разных
// издателей в один документ запрещено по той же причине, по которой их прежде
// разводили: ключ одного издателя проверял бы токен, объявляющий другого.
type Record struct {
	// Issuer — издатель записи. Ключ поиска, и ТОЛЬКО ключ поиска.
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
	// Handler — обработчик записи: проекция ключницы.
	Handler http.Handler
}

// Binding — объявленная привязка «издатель → путь → обработчик».
type Binding struct {
	record Record
}

// NewBinding строит привязку, ОТКАЗЫВАЯ в вырожденной.
//
// Это и есть страж старта записи источника: издатель, объявленный
// публикуемым, но не имеющий записи, — отказ в старте, а не молчаливый
// перебор записей подряд. Отказ на пустом перечне — третий экземпляр класса
// «пустое значение означает „не сужаем“», который дерево уже закрывает на двух
// других перечнях.
//
// ВТОРАЯ ЗАПИСЬ — ТОЖЕ ОТКАЗ, и отказывает мощность, а не форма: каждая запись
// по отдельности законна, и потому вернувшееся зеркало чужого набора прошло бы
// все остальные проверки молча.
func NewBinding(records []Record) (Binding, error) {
	switch {
	case len(records) == 0:
		return Binding{}, fmt.Errorf("jwks binding: no key-set record declared — " +
			"a publisher with no record answers nobody, and every token would be refused")
	case len(records) > 1:
		extra := make([]string, 0, len(records)-1)
		for _, rec := range records[1:] {
			extra = append(extra, strings.TrimSpace(rec.Issuer))
		}
		return Binding{}, fmt.Errorf(
			"jwks binding: %d key-set records declared, and the publisher carries exactly one — "+
				"its own key set (issuer %s); a record of another issuer (%s) would put that issuer's "+
				"keys next to ours on the same listener",
			len(records), strings.TrimSpace(records[0].Issuer), strings.Join(extra, ", "))
	}
	rec := records[0]
	issuer := strings.TrimSpace(rec.Issuer)
	if issuer == "" {
		return Binding{}, fmt.Errorf("jwks binding: the record declares no issuer")
	}
	// Путь считается ПО СОДЕРЖАНИЮ, а не по длине строки: разделители без
	// сегментов дают непустую строку и пустой путь.
	if !usablePath(rec.Path) {
		return Binding{}, fmt.Errorf(
			"jwks binding: issuer %s is published but declares no usable key-set path (got %q) — "+
				"refusing to start rather than resolving it to a derived address", issuer, rec.Path)
	}
	if rec.Handler == nil {
		return Binding{}, fmt.Errorf("jwks binding: issuer %s declares a path with no handler behind it", issuer)
	}
	return Binding{record: Record{Issuer: issuer, Path: rec.Path, Handler: rec.Handler}}, nil
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
// композиционный корень, страница развёртывания, — ВЫВОДИТ его отсюда, а не
// выписывает: выписанный перечень разошёлся бы с привязкой молча.
func (b Binding) Paths() []string {
	if b.record.Handler == nil {
		return nil
	}
	return []string{b.record.Path}
}

// PathOf резолвит объявленного издателя в путь его записи.
//
// Издатель употребляется ТОЛЬКО как ключ поиска: не совпал с объявленным —
// отказ. Ни одна часть пути, имени файла, ключа кэша или исходящего адреса из
// него не строится.
func (b Binding) PathOf(issuer string) (string, bool) {
	if b.record.Handler == nil || issuer != b.record.Issuer {
		return "", false
	}
	return b.record.Path, true
}

// NewMux монтирует запись привязки на её путь.
//
// Возвращённый mux выставляется вызывающим на cluster-ВНУТРЕННЕМ слушателе —
// никогда на внешнем.
func NewMux(b Binding) (*http.ServeMux, error) {
	if b.record.Handler == nil {
		return nil, fmt.Errorf("jwks mux: binding carries no record")
	}
	mux := http.NewServeMux()
	mux.Handle(b.record.Path, b.record.Handler)
	return mux, nil
}

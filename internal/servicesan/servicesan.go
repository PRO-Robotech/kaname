// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package servicesan — ФОРМА ИМЕНИ СЛУЖБЫ в учётке SPIFFE-идентификатора
// рабочей нагрузки (kaname#308): как установка складывает имя учётки модуля из
// короткого имени службы и как читает его обратно.
//
// # Предмет: форму объявляет установка, а не код
//
// Идентификатор модуля имеет вид `spiffe://<домен>/ns/<пространство>/sa/<учётка>`,
// и короткое имя службы (`vpc`, `api-gateway`) выводится из учётки. Как учётка
// складывается из имени службы — решение того, кто ставит: одна установка
// называет учётки `acme-vpc`, другая — `team.a-vpc`. Прежде форма стояла в
// страже прав литералом, и это была приставка имени ДРУГОГО продукта: установка,
// называвшая учётки иначе, поднималась зелёной — взаимный TLS сходился, стражи
// старта молчали, — а полоса входа отказывала каждому запросу до маршрута и до
// тела, не называя ни ручки, ни причины.
//
// Домен доверия был переведён в величину установки раньше и по той же причине
// (corelib `grpcsrv.TrustDomain`); форма имени — вторая половина того же
// идентификатора и устроена тем же порядком: умолчания нет, нулевое значение —
// «не объявлена», и по необъявленной форме не узнаётся НИКТО.
//
// # Запись формы
//
// Форма — строка с ровно одним заполнителем [Placeholder] и НЕПУСТОЙ
// приставкой перед ним: `acme-{service}`, `acme-{service}-sa`. Всё, что стоит
// вокруг заполнителя, — приставка и окончание учётки; знаки — те, из которых
// складывается имя учётки в кластере (строчные латинские, цифры, `-` и `.`), и
// на краях имени стоит буква или цифра. Иное — не форма, и страж старта её
// отвергает ([Form.Require]): по ней не разбирается ни одно имя, а установка
// выглядела бы настроенной.
//
// Формы без приставки (`{service}`, `{service}-sa`) нет: при ней модулем
// становится всякая учётка домена, чьё имя совпало с именем службы, и пол
// «проверенный модуль» сужает не больше, чем имя учётки.
//
// # Почему здесь нет разбора идентификатора
//
// Разбор SPIFFE-идентификатора один на все пути признания вызывающего и живёт у
// перечня личностей модулей (`moduleidentity.ParseSAN`, kaname#984): модулем
// признаётся только пара (пространство, учётка), которую объявила установка.
// Форма — величина, которой перечень читает учётки своих записей
// ([Form.Service]); второй разбор идентификатора здесь разошёлся бы с первым
// молча — правка одного не доезжает до другого.
package servicesan

import (
	"fmt"
	"strings"

	"github.com/PRO-Robotech/corelib/grpcsrv"
)

// Placeholder — место имени службы в форме учётки.
const Placeholder = "{service}"

// Sample — образец записи формы для справки и текстов отказа.
//
// Приставка в образце нейтральная: конкретную выбирает установка, и написанная
// здесь читалась бы как выбор, сделанный за неё.
const Sample = "acme-" + Placeholder

// Form — объявленная форма имени учётки модуля.
//
// Значение неизменяемо после сборки: поля неэкспортируемые. Нулевое значение —
// «форма не объявлена», и по нему не разбирается ни один идентификатор.
type Form struct {
	// raw — запись формы, как её объявила установка, без пробелов по краям.
	raw string
	// prefix и suffix — то, что стоит до и после заполнителя.
	prefix, suffix string
	// problem — почему записанное формой не является; пусто у законной формы.
	problem string
}

// NewForm собирает форму из того, что объявила установка.
//
// Пробелы по краям срезаются по той же причине, что у домена доверия: значение,
// написанное с пробелом, дало бы не отказ старта, а молчаливый отказ каждому
// законному модулю. Пустая строка даёт канонический ноль — «не объявлена».
func NewForm(raw string) Form {
	s := strings.TrimSpace(raw)
	if s == "" {
		return Form{}
	}
	f := Form{raw: s}
	switch n := strings.Count(s, Placeholder); {
	case n == 0:
		f.problem = "carries no " + Placeholder + " placeholder, so no service name can be read from an account by it"
		return f
	case n > 1:
		f.problem = "carries the " + Placeholder + " placeholder more than once, so an account name would not determine the service name"
		return f
	}
	f.prefix, f.suffix, _ = strings.Cut(s, Placeholder)
	if bad := firstForeignRune(f.prefix + f.suffix); bad != "" {
		f.problem = fmt.Sprintf("carries %q around the placeholder, and a cluster account name is made of "+
			"lower-case latin letters, digits, '-' and '.' only", bad)
		return f
	}
	// Приставка обязательна (F1 ревью сборки k1). Без неё модульность учётки
	// решает одно совпадение её имени с коротким именем службы: учётка `vpc` в
	// любом пространстве домена становится модулем `vpc`, учётка `api-gateway` —
	// краем, и пол «проверенный модуль» на обоих слушателях, ярус соседей и
	// допуск края на полосе входа сужают не больше, чем имя учётки. Приставка —
	// то, чем установка отделяет учётки своих модулей от прочих учёток домена.
	if f.prefix == "" {
		f.problem = "carries nothing before the " + Placeholder + " placeholder: without a prefix an account " +
			"is a module merely because its name equals a service name, so the module floor, the peer tier " +
			"and the edge admission narrow nothing beyond the account name; begin the form with the prefix " +
			"the installation gives the accounts of its modules"
		return f
	}
	// Приставка и окончание стоят на краях имени учётки, а имя учётки кластера
	// начинается и кончается буквой или цифрой. Форма, нарушающая это, не
	// называет ни одной возможной учётки: по ней не узнаётся никто, а установка
	// выглядела бы настроенной.
	if !isAlnum(f.prefix[0]) || (f.suffix != "" && !isAlnum(f.suffix[len(f.suffix)-1])) {
		f.problem = "begins or ends with a separator, and a cluster account name begins and ends with " +
			"a lower-case latin letter or a digit, so no account of this form can exist"
	}
	return f
}

// isAlnum — строчная латинская буква или цифра. Остальные знаки формы проверены
// раньше ([firstForeignRune]), поэтому байта достаточно.
func isAlnum(b byte) bool {
	return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9')
}

// firstForeignRune — первый знак, которого в имени учётки кластера быть не
// может; пусто — таких нет.
func firstForeignRune(s string) string {
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= '0' && r <= '9', r == '-', r == '.':
			continue
		}
		return string(r)
	}
	return ""
}

// IsDeclared — объявила ли установка форму вообще. Законность записи —
// отдельный вопрос ([Form.Valid]).
func (f Form) IsDeclared() bool { return f.raw != "" }

// Valid — форма объявлена и записана законно: по ней разбирается имя службы.
func (f Form) Valid() bool { return f.IsDeclared() && f.problem == "" }

// String — запись формы для журнала и самоотчёта. Форма не секрет: она
// написана в каждом выпущенном сертификате.
func (f Form) String() string {
	if !f.IsDeclared() {
		return "<not declared>"
	}
	return f.raw
}

// Account — имя учётки, которым форма называет службу service. Пусто — форма
// не годна либо имя службы пусто: собрать по ней учётку нельзя.
func (f Form) Account(service string) string {
	if !f.Valid() || service == "" {
		return ""
	}
	return f.prefix + service + f.suffix
}

// Service — короткое имя службы, которое форма читает в учётке account.
//
// Ложь — учётка этой формы не имеет либо имя службы в ней пусто. Учётка с
// косой чертой формы не имеет никогда: имя учётки кластера её не несёт, и
// принять такую значило бы признать модулем хвост чужого пути.
func (f Form) Service(account string) (string, bool) {
	if !f.Valid() || strings.Contains(account, "/") {
		return "", false
	}
	rest, ok := strings.CutPrefix(account, f.prefix)
	if !ok {
		return "", false
	}
	svc, ok := strings.CutSuffix(rest, f.suffix)
	if !ok || svc == "" {
		return "", false
	}
	return svc, true
}

// Gate — вход стража формы: имя ручки, которой форма задаётся, для текста
// отказа. Отказ читает оператор, и отказ, не называющий ручку, оставляет
// установку неподнятой и непонятной.
type Gate struct {
	Knob string
}

// Require — страж формы: отказ старта, когда форма не объявлена либо записана
// незаконно.
//
// Срабатывает на ЛЮБОМ старте, как страж домена доверия: у необъявленной формы
// нет посадки, в которой она работает — ни одна учётка не узнаётся модульной, и
// процесс отверг бы каждого соседа молча, отказом, неотличимым от вызова без
// личности.
func (f Form) Require(g Gate) error {
	if !f.IsDeclared() {
		return fmt.Errorf("%s is empty: the installation has not named the form of its service "+
			"account names, so no client certificate is recognized as a module — every module call "+
			"is refused, the edge included, and the sign-in lane answers a bare refusal to every "+
			"request; set it to the form the installation names its service accounts by, with %s "+
			"in place of the service name (example %s; the SAN shape is %s)",
			g.Knob, Placeholder, Sample, grpcsrv.SANShape)
	}
	if f.problem != "" {
		return fmt.Errorf("%s %q %s; write the account name with %s in place of the service name "+
			"(example %s)", g.Knob, f.raw, f.problem, Placeholder, Sample)
	}
	return nil
}

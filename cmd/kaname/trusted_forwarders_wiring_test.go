// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// trusted_forwarders_wiring_test.go — страж РАЗМЕЩЕНИЯ: доверенную пару со
// списком отправителей обязаны получать ОБА листенера, список — приходить из
// конфигурации, а пер-RPC политика вызывающего — стоять на публичном листенере
// так же, как она давно стоит на внутреннем.
//
// Поведенческие замки (кого цепочка принимает, а кого отвергает) живут в
// trusted_forwarders_test.go и утверждают на ОДНОЙ цепочке. Что эту цепочку
// получает каждый из двух листенеров — предмет этого файла. Разрыв между
// «проверено» и «смонтировано» и есть та «форма без содержания», из-за которой
// дыра прожила до сих пор: доверенная пара стояла на обоих листенерах, выглядела
// как сужение и не сужала ничего, потому что список был пуст.

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// unconditionalExtract — безусловный извлекатель заголовков личности. Его godoc
// прямо запрещает монтировать его туда, куда дозванивается неконтролируемый пир;
// до iam дозванивается любой под пространства имён: оба gRPC-порта — обычные
// Service, а единственная сетевая политика, выбирающая под iam, покрывает
// внутренний порт и вне боевого профиля выключена.
var unconditionalExtract = regexp.MustCompile(`grpcsrv\.(Unary|Stream)PrincipalExtract\(`)

// identityBuilderCall — вызов боевого сборщика цепочки личности. Пробелы не
// фиксируем: перенос строки при форматировании не должен превращать стража в
// ложное падение.
var identityBuilderCall = regexp.MustCompile(`(?s)\bidentity(Unary|Stream)\(\s*cfg\s*\)`)

// forwardersArg — то, ЧТО уезжает в общий конструктор пары как круг отправителей.
// Ищем все вхождения, а не первое: одного вызова с литералом достаточно, чтобы
// круг снова не сужался. Аргумент сам содержит скобки
// (`cfg.AuthN.TrustedForwarders()`), поэтому класс «что угодно, кроме скобки»
// здесь не годится — берём нежадное совпадение до закрывающей скобки строки.
var forwardersArg = regexp.MustCompile(`(?m)grpcsrv\.PrincipalExtract(?:Unary|Stream)\(\s*(.*?)\s*\)\s*$`)

// chainAssign — ЛЮБОЕ присваивание переменной, которая уезжает в листенер.
// Оператор захватывается отдельной группой: `:=` — заведение, `=` — дополнение,
// и требования к ним РАЗНЫЕ. Без этого различения `internalUnary =
// append(publicUnary, …)` читалось бы как заведение и проходило бы, хотя это
// подмена одной цепочки другой.
var chainAssign = regexp.MustCompile(`(?m)^\s*(publicUnary|publicStream|internalUnary|internalStream)\s*(:?=)\s*(.+?)\s*$`)

func serveSrc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("serve.go")
	if err != nil {
		t.Fatalf("read composition root: %v", err)
	}
	return string(b)
}

// TestServe_NoUnconditionalPrincipalExtract — нижний слой инварианта: ни один
// листенер не читает x-kacho-principal-* без взгляда на транспорт и личность
// сертификата пира.
func TestServe_NoUnconditionalPrincipalExtract(t *testing.T) {
	if hits := unconditionalExtract.FindAllString(serveSrc(t), -1); len(hits) > 0 {
		t.Fatalf("serve.go монтирует безусловный извлекатель личности: %v. Он читает "+
			"x-kacho-principal-* не глядя ни на транспорт, ни на личность сертификата пира — любой "+
			"под кластера присылает заголовки жертвы, и решение о правах принимается от её имени", hits)
	}
}

// TestServe_BothListenersGetTheTrustAwareChain — измерение нельзя закрыть на
// одном листенере: публичный (:9090) несёт весь тенантский CRUD и чеканку
// носителей прав, внутренний (:9091) — административные и служебные RPC. Оба
// обязаны собирать цепочку одним и тем же боевым сборщиком.
//
// RED до правки: сборщика нет, каждый листенер перечисляет извлекатели у себя, и
// список отправителей не уезжает ни в один из них.
func TestServe_BothListenersGetTheTrustAwareChain(t *testing.T) {
	src := serveSrc(t)

	var unary, stream int
	for _, m := range identityBuilderCall.FindAllStringSubmatch(src, -1) {
		if m[1] == "Unary" {
			unary++
		} else {
			stream++
		}
	}
	if unary != 2 {
		t.Fatalf("identityUnary(cfg) встречается %d раз(а), ожидается 2 "+
			"(публичный :9090 и внутренний :9091)", unary)
	}
	if stream != 2 {
		t.Fatalf("identityStream(cfg) встречается %d раз(а), ожидается 2", stream)
	}
}

// TestServe_ForwarderAllowListComesFromConfig — список обязан выводиться из
// конфигурации. Пустой литерал означает «принимаем переданную личность от ЛЮБОГО
// пира с сертификатом» (corelib сужает круг только на непустом списке) — и
// настроить это было бы невозможно ни одним способом.
func TestServe_ForwarderAllowListComesFromConfig(t *testing.T) {
	src := serveSrc(t)

	all := forwardersArg.FindAllStringSubmatch(src, -1)
	if len(all) == 0 {
		t.Fatal("serve.go: пара извлечения личности не собирается общим конструктором " +
			"grpcsrv.PrincipalExtract* — круг отправителей чужой личности ничем не сужается " +
			"(либо страж перестал читать проводку и его надо обновить вместе с ней)")
	}
	for _, m := range all {
		arg := strings.TrimSpace(m[1])
		if !strings.Contains(arg, "cfg.") {
			t.Fatalf("serve.go: allow-list передаётся как `%s` — литералом, а не конфигурацией", arg)
		}
	}
}

// TestServe_IdentityChainComesFromTheSharedConstructor — пара извлечения личности
// обязана приезжать у ОБЩЕГО конструктора, а не пересобираться здесь.
//
// Раньше на этом месте стоял контракт порядка («сначала личность сертификата,
// потом переданная»), проверяемый по позициям строк в исходнике. Порядок теперь
// держит сам конструктор, и он заперт исходом в pkg/grpcsrv
// (TestPrincipalExtractPairOrderIsLoadBearing: перевёрнутая пара доказательно
// теряет личность). Текстовая проверка позиций на его месте была бы вторым местом
// об одном предмете — и именно она устарела бы молча, когда конструктор поменяют.
// Здесь остаётся то, что конструктор гарантировать не может: что его позвали.
func TestServe_IdentityChainComesFromTheSharedConstructor(t *testing.T) {
	src := serveSrc(t)
	for _, want := range []string{"grpcsrv.PrincipalExtractUnary(", "grpcsrv.PrincipalExtractStream("} {
		if !strings.Contains(src, want) {
			t.Errorf("serve.go: %q отсутствует — пара извлечения личности собирается мимо общего конструктора", want)
		}
	}
	for _, manual := range []string{"grpcsrv.UnaryTrustedPrincipalExtract(", "grpcsrv.StreamTrustedPrincipalExtract("} {
		if strings.Contains(src, manual) {
			t.Errorf("serve.go: пара пересобирается вручную (%s) — её полнота и порядок снова "+
				"держатся текстом, а не конструкцией", manual)
		}
	}
}

// TestServe_EachListenerChainIsSeededFromTheIdentityBuilder — КАЖДАЯ из четырёх
// переменных, уезжающих в листенеры, обязана быть ЗАВЕДЕНА вызовом боевого
// сборщика, а всякое последующее присваивание — дополнением ЕЁ ЖЕ.
//
// Почему обе половины. Считать одни лишь вызовы сборщика недостаточно: вызов мог
// бы стоять в стороне, а в листенер уехала бы другая цепочка. Считать одни лишь
// присваивания тоже недостаточно: `publicUnary = append(someOtherChain, …)` —
// формально дополнение, фактически подмена. Разрыв между «вызвано рядом» и
// «смонтировано» и есть та форма без содержания, ради которой этот файл написан.
func TestServe_EachListenerChainIsSeededFromTheIdentityBuilder(t *testing.T) {
	src := serveSrc(t)

	seeded := map[string]bool{}
	for _, m := range chainAssign.FindAllStringSubmatch(src, -1) {
		name, op, rhs := m[1], m[2], strings.TrimSpace(m[3])
		want := seedingBuilderFor(name)
		if op == ":=" {
			// Заведение. Обязано втягивать цепочку личности из сборщика: смотрим
			// на ВЕСЬ оператор, а не на первую строку — он многострочный.
			stmt := balancedFrom(t, src, strings.Index(src, name+" := append("))
			if !strings.Contains(stmt, want) {
				t.Fatalf("serve.go: %s заводится без %s — в листенер уехала бы цепочка, которая "+
					"не сужает круг отправителей чужой личности:\n%s", name, want, stmt)
			}
			seeded[name] = true
			continue
		}
		// Дополнение — только самой себя (метрики, recovery, политики). Любая
		// другая правая часть означает, что в листенер уедет ЧУЖАЯ цепочка, а все
		// прочие проверки останутся зелёными.
		if !strings.HasPrefix(rhs, "append("+name+",") {
			t.Fatalf("serve.go: %s присваивается как `%s` — это не дополнение её же. Переданная "+
				"личность принимается тем, что реально попало в листенер, а не тем, что рядом "+
				"вызвано", name, rhs)
		}
		if !seeded[name] {
			t.Fatalf("serve.go: %s дополняется до того, как заведена сборщиком", name)
		}
	}
	for _, name := range []string{"publicUnary", "publicStream", "internalUnary", "internalStream"} {
		if !seeded[name] {
			t.Fatalf("serve.go: цепочка %s нигде не заводится боевым сборщиком — "+
				"страж потерял цель, обнови его вместе с проводкой", name)
		}
	}
}

// seedingBuilderFor — боевой сборщик, которым заводится названная цепочка.
//
// У слушателей сборщики РАЗНЫЕ, и это решение, а не дрейф: публичный принимает
// арендатора, которому в чужом облаке нечем назваться, кроме предъявленного
// удостоверения, — внутренний принимает соседний модуль по mTLS, и читатель
// предъявленного там был бы лишним способом назваться. Публичный сборщик при
// этом ДОПОЛНЯЕТ общую пару, а не заменяет её, и это утверждает своим разбором
// TestServe_PublicIdentityBuilderStillSeedsFromTheSharedOne: без него страж
// принял бы публичную цепочку, собранную с нуля и не сужающую круг
// разрешённых отправителей.
func seedingBuilderFor(chain string) string {
	switch chain {
	case "publicUnary":
		return "publicIdentityUnary(cfg,"
	case "publicStream":
		return "publicIdentityStream(cfg,"
	case "internalStream":
		return "identityStream(cfg)"
	default:
		return "identityUnary(cfg)"
	}
}

// balancedFrom возвращает текст оператора, начинающегося с позиции from, до
// закрытия первой открытой круглой скобки — так многострочный append читается
// целиком.
func balancedFrom(t *testing.T, src string, from int) string {
	t.Helper()
	if from < 0 {
		t.Fatal("serve.go: не найдено начало оператора (страж разошёлся с проводкой)")
	}
	depth := 0
	for i := from; i < len(src); i++ {
		switch src[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				return src[from : i+1]
			}
		}
	}
	t.Fatal("serve.go: несбалансированные скобки в присваивании цепочки")
	return ""
}

// TestServe_PublicListenerCarriesItsCallerPolicy — второй слой сужения: пер-RPC
// политика вызывающего обязана стоять на ПУБЛИЧНОМ листенере, а не только на
// внутреннем. Без неё сосед из списка отправителей всё ещё чеканил бы токены и
// раздавал права от чужого имени — список сужает «кто вправе говорить за
// пользователя», но не «на каком RPC».
//
// RED до правки: публичной политики нет ни как типа, ни как звена цепочки.
func TestServe_PublicListenerCarriesItsCallerPolicy(t *testing.T) {
	src := serveSrc(t)

	if !strings.Contains(src, "authzguard.NewPublicCallerPolicy(") {
		t.Fatal("serve.go: публичная политика вызывающего не создаётся — на :9090 любой " +
			"верифицированный сосед доходит до чеканки токенов и выдачи прав")
	}
	for _, want := range []string{"publicCallerPolicy.Unary()", "publicCallerPolicy.Stream()"} {
		if !strings.Contains(src, want) {
			t.Fatalf("serve.go: %s не смонтирован — политика существует, но ничего не решает "+
				"(форма без содержания)", want)
		}
	}
}

// TestServe_PublicCallerPolicyIsProductionGated — политика обязана читать РЕЖИМ
// процесса, а не быть включённой константой: dev-стенд без mTLS не имеет
// проверенного сертификата вовсе, и жёсткое включение положило бы его целиком.
func TestServe_PublicCallerPolicyIsProductionGated(t *testing.T) {
	src := serveSrc(t)
	m := regexp.MustCompile(`authzguard\.NewPublicCallerPolicy\(\s*([A-Za-z0-9_.]+)\s*,`).FindStringSubmatch(src)
	if m == nil {
		t.Fatal("serve.go: не удалось прочитать первый аргумент NewPublicCallerPolicy")
	}
	if m[1] != "productionMode" {
		t.Fatalf("serve.go: политика построена с prodMode=`%s`, ожидается productionMode "+
			"(тот же режим, которым гейтится внутренняя политика)", m[1])
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_road_address_single_reader.go — разбор мест, ЧИТАЮЩИХ резолвер
// адреса административной дороги к внешнему поставщику личности
// (задачи `kacho#2573`, `kaname#21`).
//
// # ПРЕДМЕТ — РЕЗОЛВЕР, КОТОРЫЙ НЕ ВОЗВРАЩАЕТ ПУСТОГО
//
// `AuthNConfig.ResolveHydraAdminURL` пустого не возвращает НИКОГДА: при
// незаданной ручке он ВЫВОДИТ адрес из доменного имени. Это сказано в его
// собственной шапке и в шапке безопасного близнеца `DeclaredHydraAdminURL`,
// который пуст ровно тогда, когда оператор ничего не писал.
//
// Следствие несущее: «объявлен» и «выведен» на месте вызова НЕРАЗЛИЧИМЫ. Поэтому
// всякое чтение резолвера вне строителя дороги даёт значение, о котором нельзя
// сказать, назвал ли его кто-нибудь, — и посадка, у которой внешнего поставщика
// нет вовсе, получает непустой адрес, читающийся как настроенный.
//
// # ЧТО ЗДЕСЬ НАХОДКА, А ЧТО НЕТ
//
//	cfg.AuthN.ResolveHydraAdminURL()   вне строителя дороги   ← НАХОДКА
//	cfg.AuthN.ResolveHydraAdminURL()   внутри строителя       ← владелец, молчим
//	cfg.AuthN.DeclaredHydraAdminURL()  где угодно             ← безопасный близнец
//
// Близнец находкой не является и считается ОТДЕЛЬНО: страж посадки читает
// именно его, и «находок ноль» обязано быть отличимо от «распознаватель не видит
// в этом дереве ничего про адрес поставщика».
//
// # ПОЧЕМУ УЗЕЛ ВЫЗОВА, А НЕ ПОИСК ПО СЛОВУ
//
// Имя резолвера встречается в прозе — в шапке самого резолвера, в шапке близнеца
// и в шапке стража посадки, который объясняет, почему читает не его. Поиск по
// подстроке краснел бы на собственном объяснении проверяемого: проверка обязана
// судить ИСПОЛНЯЕМУЮ часть, отличая код от комментария и строкового литерала.
//
// # ЧЕГО РАЗБОР НЕ ВИДИТ — НАЗВАНО, А НЕ СПРЯТАНО
//
//  1. чтение через значение-функцию (`f := cfg.AuthN.ResolveHydraAdminURL; f()`);
//  2. чтение, добравшееся сюда через промежуточное поле или обёртку;
//  3. чтение из чужого модуля — обход ограничен деревом этой службы.
package check

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"sort"
)

// ProviderAddressRead — одно место, прочитавшее резолвер адреса дороги.
type ProviderAddressRead struct {
	File   string
	Line   int
	Func   string
	Callee string
}

// ProviderAddressCensus — объём осмотренного одним файлом.
//
// Три величины, а не одна: «вызовов осмотрено» отличает пустой обход от обхода
// без предмета, а «чтений близнеца» — предметное молчание от слепоты
// распознавателя.
type ProviderAddressCensus struct {
	Calls         int
	ResolverReads int
	TwinReads     int
}

// ScanProviderAddressReads разбирает ОДИН файл и собирает чтения резолвера.
//
// resolver — имя резолвера, который пустого не возвращает; twin — имя
// безопасного близнеца, чьи чтения считаются, но находкой не являются.
func ScanProviderAddressReads(path string, src []byte, resolver, twin string) (
	[]ProviderAddressRead, ProviderAddressCensus, error,
) {
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, 0)
	if err != nil {
		return nil, ProviderAddressCensus{}, err
	}
	var (
		out    []ProviderAddressRead
		census ProviderAddressCensus
	)
	for _, decl := range f.Decls {
		fn, _ := decl.(*ast.FuncDecl)
		enclosing := "уровень пакета"
		if fn != nil {
			enclosing = claimFuncQualifiedName(fn)
		}
		ast.Inspect(decl, func(n ast.Node) bool {
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			census.Calls++
			sel, ok := call.Fun.(*ast.SelectorExpr)
			if !ok {
				return true
			}
			switch sel.Sel.Name {
			case twin:
				census.TwinReads++
			case resolver:
				census.ResolverReads++
				out = append(out, ProviderAddressRead{
					File: path, Line: fset.Position(call.Pos()).Line,
					Func: enclosing, Callee: sel.Sel.Name,
				})
			}
			return true
		})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Line < out[j].Line })
	return out, census, nil
}

// SplitProviderAddressReads делит чтения на владельца и посторонних.
//
// Отдельная функция, а не ветка в теле пробы: разделение и есть вердикт, и оно
// обязано быть вызываемым с синтетическим входом.
func SplitProviderAddressReads(reads []ProviderAddressRead, owner string) (atOwner, outside []ProviderAddressRead) {
	for _, r := range reads {
		if r.Func == owner {
			atOwner = append(atOwner, r)
			continue
		}
		outside = append(outside, r)
	}
	return atOwner, outside
}

// ProviderAddressPremise — ГОДЕН ЛИ ВЕРДИКТ ВООБЩЕ, четырьмя отдельными
// условиями.
//
// # ПОЧЕМУ ФУНКЦИЯ, А НЕ ЧЕТЫРЕ `t.Fatalf` В ТЕЛЕ ПРОБЫ
//
// Премиса, живущая в теле пробы, читается глазами и НЕ ИСПОЛНЯЕТСЯ НИ РАЗУ:
// подать ей пустое дерево нечем, потому что обход строится там же. Ровно тот
// класс, ради которого заведён `tree_corpus.go`. Здесь вход приходит значением,
// поэтому каждая из четырёх ветвей доказывается исполнением.
//
// Условия РАЗДЕЛЬНЫЕ, а не одно: «прочитано мало», «вызовов не осмотрено»,
// «близнец исчез» и «владелец перестал читать» требуют разных действий, и
// схлопывание их в один отказ послало бы читателя не туда.
func ProviderAddressPremise(parsed, floor int, census ProviderAddressCensus, atOwner, total int,
	resolver, twin, owner string,
) error {
	if parsed < floor {
		return fmt.Errorf("перепись обвалилась: разобрано %d прод-файлов при пороге %d — "+
			"о дереве не прочитано почти ничего, и вердикт беспредметен", parsed, floor)
	}
	if census.Calls == 0 {
		return fmt.Errorf("на %d файлах не осмотрено НИ ОДНОГО вызова: распознаватель "+
			"молчит не потому, что находок нет", parsed)
	}
	if census.TwinReads == 0 {
		return fmt.Errorf("чтений безопасного близнеца %s — НОЛЬ: страж посадки читает "+
			"именно его, и его исчезновение означает, что предмет гейта переехал, а гейт "+
			"стережёт координату, которой больше нет", twin)
	}
	if atOwner == 0 {
		return fmt.Errorf("строитель %s резолвер %s НЕ читает (всего чтений в дереве %d): "+
			"адрес дороги строится не там, где спрашивается полоса, — гейт стережёт "+
			"координату, которой больше не существует", owner, resolver, total)
	}
	return nil
}

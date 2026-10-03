// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_claim_retired_provider.go — ГЕЙТ КЛАССА: имя утверждения в составе
// выданного токена не называет прежнего поставщика (kaname#375).
//
// # Предмет
//
// Состав утверждений нашего подписанта нёс утверждение, названное по
// поставщику, на КАЖДОЙ полосе выдачи, в том числе на посадке без поставщика.
// Имя утверждения — часть контракта токена: читатель, увидевший его, строит на
// нём решение о том, кто выдал токен. Экземпляр снят; этот гейт держит класс —
// всякое место сборки состава в дереве, чей ключ называет поставщика, находка.
//
// # Что судится
//
// Места сборки находит тот же разбор, что держит единственность состава
// (`ScanClaimAssemblies`): составной литерал `map[string]…` с ключами префикса
// утверждений. Судится КЛЮЧ, а не значение и не проза: значение выводится из
// настройки во время исполнения и дереву не видно — его держат пробы полос
// (`TestNoIssuanceLaneNamesTheRetiredProvider`). Имя поставщика берётся из
// одного источника с гейтом прозы (`RetiredIssuerName`).
//
// # Чего гейт НЕ видит — названо, а не спрятано
//
// Те же слепые зоны, что у разбора сборок: ключ, присвоенный по одному
// (`claims["…"] = v`), ключ, собранный из частей или взятый переменной, ключ
// без префикса утверждений.
package check

import (
	"fmt"
	"sort"
	"strings"
)

// ClaimNamingRetiredIssuer — ключ сборки состава, называющий прежнего
// поставщика.
type ClaimNamingRetiredIssuer struct {
	File string
	Line int
	Func string
	Key  string
}

func (f ClaimNamingRetiredIssuer) String() string {
	return fmt.Sprintf("%s:%d %s — утверждение %s называет прежнего поставщика (%q): имя утверждения — "+
		"контракт токена, и читатель построит на нём решение о том, кто выдал токен. Снимите "+
		"утверждение либо назовите его в терминах нашего издателя",
		f.File, f.Line, f.Func, f.Key, RetiredIssuerName)
}

// ClaimNamingRetiredIssuerCensus — объём осмотренного. Печатается всегда:
// «ноль находок» обязано быть отличимо от «ноль прочитанного».
type ClaimNamingRetiredIssuerCensus struct {
	Assemblies int
	Keys       int
	Findings   int
}

func (c ClaimNamingRetiredIssuerCensus) String() string {
	return fmt.Sprintf("перепись: сборок состава %d · ключей %d · называют прежнего поставщика %d",
		c.Assemblies, c.Keys, c.Findings)
}

// JudgeClaimNamesNamingRetiredIssuer — тело гейта над найденными сборками.
// Вынесено, чтобы инъекция звала ТО ЖЕ, что исполняется на дереве.
//
// Пустой перечень сборок — отказ, а не «находок нет»: разбор, не нашедший ни
// одной сборки, ничего не осмотрел.
func JudgeClaimNamesNamingRetiredIssuer(assemblies []ClaimAssembly) (
	[]ClaimNamingRetiredIssuer, ClaimNamingRetiredIssuerCensus, error,
) {
	census := ClaimNamingRetiredIssuerCensus{Assemblies: len(assemblies)}
	if len(assemblies) == 0 {
		return nil, census, fmt.Errorf("%w: сборок состава не найдено — судить нечего", ErrEmptyTraversal)
	}
	var out []ClaimNamingRetiredIssuer
	for _, a := range assemblies {
		for _, k := range a.Keys {
			census.Keys++
			if !strings.Contains(strings.ToLower(k), RetiredIssuerName) {
				continue
			}
			out = append(out, ClaimNamingRetiredIssuer{File: a.File, Line: a.Line, Func: a.Func, Key: k})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		if out[i].Line != out[j].Line {
			return out[i].Line < out[j].Line
		}
		return out[i].Key < out[j].Key
	})
	census.Findings = len(out)
	return out, census, nil
}

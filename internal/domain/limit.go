// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// limit.go — СЛОВАРЬ ВИДОВ, и только он. Авторитета величин здесь больше нет.
//
// Задача продукта `PRO-Robotech/kacho#2117`, приёмка `KAN-QUOTA-1`, стадия S4,
// сценарий `KAN-Q4-14`, условие готовности `DoD S4` пп. 13-14.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ОТСЮДА УШЛО И ПОЧЕМУ ЭТО НАЗВАНО, А НЕ СТЁРТО МОЛЧА
//
// Файл держал авторитет величин целиком: идентичность потолка (`LimitID`), его
// область (`LimitScope` с тремя рукавами и старшинством), носителя
// (`LimitCarrier`), ЗАКРЫТЫЙ КАТАЛОГ двадцати четырёх видов (`countableKinds`,
// `CountableKind`) и разрешение действующей величины между областями
// (`Limit`, `LimitFilter`, `EffectiveLimit`, `ResolveEffective`).
//
// Всё это — предмет ДРУГОГО продукта: служба доступа отвечает на вопрос «кому
// что разрешено», а не «сколько чего можно завести». Оператор, ставящий её в
// своём облаке, получал вместе с ней авторитет величин, которого не просил и
// которым не управлял.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ОСТАЛОСЬ — И ПОЧЕМУ СНЯТЬ ЕГО ЗАОДНО БЫЛО БЫ РАСШИРЕНИЕМ ПОВЕРХНОСТИ
//
// Остался СЛОВАРЬ: имя вида и разбор его частей. Служба по-прежнему СЧИТАЕТ три
// собственных вида (`iam.account`, `iam.user.credential`,
// `iam.serviceAccount.credential`) и по-прежнему отвечает арендатору, каков его
// потолок. Сменился ИСТОЧНИК величины: её объявляет посадка
// (`limit_posture_stated.go`, `П25`), а не внешний авторитет, которого в
// самостоятельной установке нет by construction.
//
// Снять словарь вместе с авторитетом значило бы оставить установку без
// ограничения на число аккаунтов и путей входа — расширение поверхности, не
// названное ни в одном артефакте.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЗАКРЫТОГО КАТАЛОГА ЗДЕСЬ БОЛЬШЕ НЕТ, И ЭТО ПРОВЕРЯЕТСЯ, А НЕ ОБЕЩАЕТСЯ
//
// `internal/check` `TestLimitAuthorityIsGoneFromTheTree` судит узлы-имена
// прод-дерева и объявление `countableKinds` отдельной осью: возврат каталога —
// находка с координатой, а не тихое отрастание. Куда каталог уезжает, решает
// развилка платформы `kacho#2190`, и служба доступа её за владельца не решает.
package domain

import "strings"

// LimitKind — a dotted token naming what is being counted. Two forms, and only
// two:
//
//	`<domain>.<resource>`            — a resource counted in its carrier
//	`<domain>.<parent>.<child>`      — how many <child> fit in ONE <parent>
//
// Both forms name REAL types of the authorization model, and the three-part form
// names two of them. That is a gate rather than a convention: a ceiling stated on
// a name the platform does not know is a ceiling nobody can check and nobody can
// show the tenant (§7 п.9 of the acceptance).
type LimitKind string

// Service — the owner service this kind belongs to (`vpc.network` → `vpc`,
// `vpc.network.subnet` → `vpc`).
//
// Derived from the token rather than stored beside it: two fields naming one
// thing drift, and the dot is the same separator the platform's reference types
// already use.
func (k LimitKind) Service() string {
	if i := strings.IndexByte(string(k), '.'); i > 0 {
		return string(k)[:i]
	}
	return ""
}

// Parts splits the kind into its dotted segments.
func (k LimitKind) Parts() []string { return strings.Split(string(k), ".") }

// Nested reports whether this kind bounds children within ONE parent
// (`vpc.network.subnet`) rather than within the carrier as a whole.
func (k LimitKind) Nested() bool { return len(k.Parts()) == 3 }

// ParentKind — the two-part token of the parent a nested kind counts within;
// empty for a flat kind. `vpc.network.subnet` → `vpc.network`.
//
// This is the token that must resolve against the closed table, and it is
// returned rather than re-derived at each call site so the two halves of the
// three-part gate cannot disagree about where the split is.
func (k LimitKind) ParentKind() LimitKind {
	p := k.Parts()
	if len(p) != 3 {
		return ""
	}
	return LimitKind(p[0] + "." + p[1])
}

// ChildKind — the two-part token of the child a nested kind counts; empty for a
// flat kind. `vpc.network.subnet` → `vpc.subnet`.
//
// The child's domain is the kind's domain: a nested kind never crosses a service
// boundary, because the parent and the child are rows of one database and the
// count is an invariant of one schema (data-integrity §within-service).
func (k LimitKind) ChildKind() LimitKind {
	p := k.Parts()
	if len(p) != 3 {
		return ""
	}
	return LimitKind(p[0] + "." + p[2])
}

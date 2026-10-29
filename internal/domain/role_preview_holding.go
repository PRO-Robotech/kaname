// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// role_preview_holding.go — признак превью роли: какие из её объявленных
// сегментов проекция выдач ДЕРЖИТ (kaname#76, приёмка
// `catalog-consequence-reaches-role-readers.md` §2.3, §3.2).
//
// # Откуда признак и почему не из снимка каталога
//
// Признак — тот же вопрос, которым уже считается целость роли
// (`UnresolvedSegments`): у роли нет строки `role_verb` этого типа и этого
// глагола, у якоря — никакой строки этого типа. Задаётся он в той транзакции,
// что читает саму роль. Снимок каталога в памяти реплики отстаёт от транзакции
// применения на период петли обновления, а оживление ресурса выдачу арендатору
// не возвращает; признак, взятый из снимка, обещал бы отобранное в обоих
// состояниях. Проекцию выдач меняет ТА ЖЕ транзакция, что кладёт событие роли,
// поэтому оба состояния закрываются построением, а не периодом петли.
//
// # Нулевое значение — «не прочитано», и судит его ПЕРЕВОД, а не домен
//
// Как у `Role.TypeVerbs`: показ без признака неотличим от честного превью,
// поэтому «нечем ответить» — отказ перевода роли в ответ
// (`internal/dto/toproto/role.go`). Домен непрочитанный признак не судит и
// считает превью по букве правил: так его зовут чистые пробы формы превью, а
// дойти до арендатора без признака роль не может — её не переведут.
//
// # Перечень ярусных классов приходит от ВЛАДЕЛЬЦА набора
//
// Глагол ЯРУСНОЙ пары проекция выдач не держит никогда — строки `role_verb` у
// такой пары не бывает, — а право выдаётся ярусным кортежем. Какие классы
// действуют ярусом, объявляет одно место (`authzmap.TierOnlyVerbClasses`), и
// домен его не переписывает: второй перечень разошёлся бы с первым молча.
// Признак несёт перечень вместе с ответом проекции — один вход, а не два.

// PreviewHolding — ответ проекции выдач о сегментах роли плюс перечень
// ярусных классов глаголов.
type PreviewHolding struct {
	// read — признак прочитан. Ложь у нулевого значения: «не прочитано».
	read bool
	// unheld — сегменты, которых проекция НЕ держит, ключом
	// `тип + "\x00" + глагол` (пустой глагол — якорь).
	unheld map[string]bool
	// tierOnly — классы глаголов, действующие ярусом.
	tierOnly map[string]bool
}

// PreviewHoldingOf собирает признак из ответа `UnresolvedSegments` по одной
// роли и перечня ярусных классов, объявленного владельцем набора.
//
// Пустой ответ законен и значит «держится всё»: признак при этом ПРОЧИТАН, чем
// и отличается от нулевого значения.
func PreviewHoldingOf(unresolved []RoleSegment, tierOnlyClasses []string) PreviewHolding {
	h := PreviewHolding{
		read:     true,
		unheld:   make(map[string]bool, len(unresolved)),
		tierOnly: make(map[string]bool, len(tierOnlyClasses)),
	}
	for _, s := range unresolved {
		h.unheld[segmentKey(s.ObjectType, s.Verb)] = true
	}
	for _, c := range tierOnlyClasses {
		h.tierOnly[NormalizeVerb(c)] = true
	}
	return h
}

// Read — признак прочитан (не нулевое значение).
func (h PreviewHolding) Read() bool { return h.read }

// holds — проекция выдач держит сегмент «тип + глагол» (пустой глагол — якорь).
func (h PreviewHolding) holds(objectType, verb string) bool {
	return !h.unheld[segmentKey(objectType, verb)]
}

// tierOnlyClass — глагол принадлежит классу, действующему ярусом.
func (h PreviewHolding) tierOnlyClass(verb string) bool { return h.tierOnly[verb] }

// segmentKey — ключ сегмента. Разделитель вне алфавита имён типа и глагола:
// склейка без него свела бы разные пары в один ключ.
func segmentKey(objectType, verb string) string { return objectType + "\x00" + verb }

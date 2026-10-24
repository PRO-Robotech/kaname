// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package reconcile

// catalog_lag.go — «тип ещё не дошёл до снимка каталога» против «тип снят»
// (kaname#937).
//
// # Предмет
//
// Кортежи члена собираются по имени типа МОДЕЛИ, а его даёт снимок каталога
// процесса (catalog.Snapshot). Снимок обновляется периодом, поэтому после
// применения манифеста, заведшего тип, реплика с необновлённым снимком этого типа
// не знает. До kaname#937 такая реплика считала члена ВЫПАВШИМ и снимала его
// кортежи по реестру выдачи: доступ, который только что выдала соседняя реплика,
// пропадал на окно до обновления снимка (до 60 с). Отказ закрытый, но доступ
// теряется — и теряется молча.
//
// # Что решает и чем
//
// Снимок отвечает «не знаю», а не «снят»: эти два состояния различает только
// строка каталога в базе. Поэтому член, чей тип снимок не знает, спрашивается у
// базы (ReconcileStore.LiveCatalogTypes):
//
//   - строка ЖИВА — тип ещё не дошёл до снимка. Член УДЕРЖИВАЕТСЯ как есть: его
//     строка, реестр и прямой факт не трогаются, новый член не заводится (кортежи
//     собрать нечем). Проход по этому типу повторит реплика, чей снимок его знает:
//     сведение по периоду и событие объекта;
//   - строки нет либо она снята — тип снят. Член выпадает из желаемого и снимается
//     обычным путём выпавшего: по реестру своей координаты (kaname#933).
//
// Удерживается ровно тот член, которого правило выдачи СЕЙЧАС сопоставило объекту
// в её области: выпадение по другой причине (правило снято, метка сменилась,
// объект ушёл из зеркала, объект вне области) решается без каталога и снимает
// член, как и прежде. Исключение одно — член `public_reader` удерживаемой
// координаты: его ключ выводится из каталожного факта контейнера
// (publicReaderMember), и снимок, не знающий типа, не может ни подтвердить его,
// ни опровергнуть. Его удерживает тот же признак, и снимает тот же следующий
// проход реплики со свежим снимком.
//
// # Чего здесь нет
//
// Обратного отставания — снимок ещё знает тип, а строка уже снята — этот путь не
// судит: спрашивать базу о КАЖДОМ типе прохода значило бы платить обращением в
// обычном проходе. Там окно прежнее — до обновления снимка, и снимает член
// следующий проход.
//
// Строки каталога транзакция сверки не запирает: удержание живёт один проход, а
// замок связал бы сверку с применителем каталога лишним ребром ожидания.

import (
	"context"
	"fmt"
	"log/slog"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// heldMembers — члены, которые проход удерживает как есть: ключи членов, не
// входящих в желаемое (`public_reader` удерживаемой координаты), и строки реестра
// удерживаемых координат — на них претендует удержанный член.
type heldMembers struct {
	keys   map[string]struct{}
	ledger map[MemberCoord][]domain.MembershipTuple
}

// holds — удерживается ли текущий член с ключом key, которого нет в желаемом.
func (h *heldMembers) holds(key string) bool {
	if h == nil {
		return false
	}
	_, ok := h.keys[key]
	return ok
}

// claim дописывает в претензии выживших строки реестра удерживаемых координат:
// уходящий член той же координаты (тот же объект под снятым правилом) не забывает
// и не снимает кортежей, которые удержанный член уже выпустил.
func (h *heldMembers) claim(c *memberClaims) {
	if h == nil {
		return
	}
	for coord, tuples := range h.ledger {
		at := c.byCoord[coord]
		if at == nil {
			at = make(map[domain.MembershipTuple]struct{}, len(tuples))
			c.byCoord[coord] = at
		}
		for _, t := range tuples {
			c.all[t] = struct{}{}
			at[t] = struct{}{}
		}
	}
}

// settleUnresolved решает членов с типом, неизвестным снимку (typeUnresolved), по
// строке каталога в базе. Возвращает желаемое без членов снятых типов и набор
// удерживаемых. Ни одного такого члена — ни одного обращения к базе.
func (r *Reconciler) settleUnresolved(ctx context.Context, s ReconcileStore, bs BindingScope,
	desired []DesiredMember, current map[string]domain.TargetMember) ([]DesiredMember, *heldMembers, error) {
	var types []string
	seen := map[string]struct{}{}
	for _, d := range desired {
		if !d.typeUnresolved {
			continue
		}
		if _, dup := seen[d.ObjectType]; dup {
			continue
		}
		seen[d.ObjectType] = struct{}{}
		types = append(types, d.ObjectType)
	}
	if len(types) == 0 {
		return desired, nil, nil
	}
	sort.Strings(types)
	liveTypes, err := s.LiveCatalogTypes(ctx, types)
	if err != nil {
		return nil, nil, fmt.Errorf("live catalog types %v of binding %s: %w", types, bs.BindingID, err)
	}
	live := make(map[string]struct{}, len(liveTypes))
	for _, t := range liveTypes {
		live[t] = struct{}{}
	}

	out := make([]DesiredMember, 0, len(desired))
	heldCoords := map[MemberCoord]struct{}{}
	for _, d := range desired {
		if !d.typeUnresolved {
			out = append(out, d)
			continue
		}
		if _, ok := live[d.ObjectType]; !ok {
			// Тип снят: член выпадает и снимается по реестру своей координаты.
			continue
		}
		out = append(out, d)
		if _, existed := current[memberRuleKey(d.RuleFP, d.ObjectType, d.ObjectID)]; existed {
			heldCoords[desiredCoord(d)] = struct{}{}
		}
	}

	h := &heldMembers{keys: map[string]struct{}{}, ledger: map[MemberCoord][]domain.MembershipTuple{}}
	for key, m := range current {
		if !strings.HasPrefix(m.RuleFP, publicReaderRuleFPPrefix) {
			continue
		}
		if _, ok := heldCoords[coordOf(m)]; ok {
			h.keys[key] = struct{}{}
		}
	}
	coords := make([]MemberCoord, 0, len(heldCoords))
	for c := range heldCoords {
		coords = append(coords, c)
	}
	sort.Slice(coords, func(i, j int) bool {
		if coords[i].ObjectType != coords[j].ObjectType {
			return coords[i].ObjectType < coords[j].ObjectType
		}
		return coords[i].ObjectID < coords[j].ObjectID
	})
	for _, c := range coords {
		tuples, err := s.LedgerTuplesForMember(ctx, bs.BindingID, c)
		if err != nil {
			return nil, nil, fmt.Errorf("ledger of held member %s:%s of binding %s: %w", c.ObjectType, c.ObjectID, bs.BindingID, err)
		}
		h.ledger[c] = tuples
	}
	if len(coords) > 0 {
		r.logger.WarnContext(ctx, "reconcile: members held — their type is live in the catalog but not yet in this replica's snapshot",
			slog.String("binding_id", string(bs.BindingID)), slog.Any("types", types), slog.Int("held_objects", len(coords)))
	}
	return out, h, nil
}

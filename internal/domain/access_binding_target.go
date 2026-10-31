// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package domain

// access_binding_target.go — цель выдачи AccessBinding.target (redesign-2026 F8,
// хребет наименьших привилегий). Цель выбирает, НА КАКИЕ объекты под якорем
// области действует выдача:
//
//   - AllInScope — ВСЕ объекты под якорем, включая будущие (самая широкая
//     выдача, достижимая ТОЛЬКО явным выбором — никогда по умолчанию);
//   - Resources  — закрытый перечень пообъектных ResourceRef{type,id} (без имени;
//     `type` — точечное имя типа, живого в каталоге платформы, например
//     `compute.instance`; судит его ЖИВОЙ каталог, а не перечень в коде —
//     `ValidTargetType`; `id` — по грамматике объекта, `validObjectID`).
//
// Ветви взаимоисключающие. Нулевое значение (обе пусты) читается как выдача на
// весь якорь — для прежних и внутренних строк, заведённых до F8 (так вела себя
// выдача без цели); публичный Create отвергает отсутствующую цель синхронно
// (наименьшие привилегии на границе).

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"go.uber.org/multierr"
)

// ResourceRef — пообъектный указатель {type,id} (redesign-2026 F8 / B1). В
// отличие от общего Referrer имени НЕ несёт: цель iam — строгая форма {type,id}.
// `Type` — точечный ключ `<module>.<resource>`.
type ResourceRef struct {
	Type string
	ID   string
}

// AccessTarget — выбор объектов выдачи (F8). Значима ровно одна ветвь; нулевое
// значение — выдача на весь якорь (смысл AllInScope).
type AccessTarget struct {
	AllInScope bool          // whole-anchor grant (incl. future objects)
	Resources  []ResourceRef // per-object grant (mutually exclusive with AllInScope)
}

// MaxTargetResourcesPerBinding — жёсткий потолок target.resources[]. Защита от
// отказа в обслуживании и посильная пообъектная материализация: реконсайлер
// пересекает каждый подошедший по правилам объект с целью через ЛИНЕЙНЫЙ
// AccessTarget.Contains внутри ОДНОЙ синхронной транзакции записи под
// рекомендательной блокировкой выдачи и повторяет это на каждый объект,
// созданный в кластере (forwardObjectForBinding). Неограниченный перечень стоил
// бы |подошедших|×|цели| сравнений на горячем пути и неограниченной строки JSONB.
// 0 < n ≤ 256 судится синхронно (INVALID_ARGUMENT), как MaxSubjectsPerBinding.
const MaxTargetResourcesPerBinding = 256

// IsEmpty сообщает, что не задана ни одна ветвь (явного выбора нет). Пустая цель
// хранится и сверяется как AllInScope, но публичный Create её отвергает (цель
// ОБЯЗАТЕЛЬНА).
func (t AccessTarget) IsEmpty() bool {
	return !t.AllInScope && len(t.Resources) == 0
}

// Validate судит форму цели: ветви взаимоисключающие, у каждого пообъектного
// ResourceRef непустой тип, а идентификатор непуст и подчиняется грамматике
// объекта (`validObjectID`). AllInScope и пустая цель всегда годны.
//
// Отказы копятся по всем элементам; у элемента с пустым идентификатором отказ
// один — «(empty)», проверка формы его не дублирует.
//
// Членство типа в каталоге здесь НЕ судится: домен чист и каталога не видит.
// Годность типа — вопрос живого каталога на момент записи (`ValidTargetType`,
// `FirstNonLiveType`); его задаёт use-case создания выдачи синхронно по снимку
// и повторно в транзакции записи (kaname#904).
func (t AccessTarget) Validate() error {
	if t.AllInScope && len(t.Resources) > 0 {
		return fmt.Errorf("Illegal argument target (allInScope and resources are mutually exclusive)")
	}
	if len(t.Resources) > MaxTargetResourcesPerBinding {
		return fmt.Errorf("Illegal argument target.resources (must be 1..%d)", MaxTargetResourcesPerBinding)
	}
	var errs error
	for i, r := range t.Resources {
		if r.Type == "" {
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument target.resources[%d].type (empty)", i))
		}
		switch {
		case r.ID == "":
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument target.resources[%d].id (empty)", i))
		case !validObjectID(r.ID):
			errs = multierr.Append(errs, fmt.Errorf(
				"Illegal argument target.resources[%d].id (not a valid object id: "+
					"space, tab, newline, '#' and ':' are not allowed)", i))
		}
	}
	return errs
}

// objectIDForbidden — знаки, которых грамматика объекта не допускает в
// идентификаторе: те же, по которым регистрация объекта судит часть после
// двоеточия (`validateRelationString` в
// `internal/apps/kaname/api/internal_iam/register_resource.go`): пробел,
// табуляция, перевод строки, `#` — разделитель набора субъектов, второе `:`.
// Объект с таким идентификатором зарегистрирован быть не может, поэтому отказ
// цели не отнимает ни одной законной выдачи.
const objectIDForbidden = " \t\n#:"

// validObjectID сообщает, годен ли идентификатор объекта цели по грамматике
// объекта: непуст и не несёт ни одного знака `objectIDForbidden`.
//
// Зачем это цели. Состав пообъектной цели сверяется по его записи —
// отсортированные «тип:id», склеенные переводом строки. Идентификатор с
// переводом строки и вторым «тип:id» дал бы цели из ОДНОГО объекта ту же запись,
// что у цели из двух, и выдача на неё отвергалась бы как повтор чужой выдачи.
// Грамматика объекта такой идентификатор исключает, и запись состава остаётся
// однозначной без смены её способа (kaname#1004). `/` законен и разбирается
// дословно: служба идентификатор не режет и не нормализует.
func validObjectID(id string) bool {
	return id != "" && !strings.ContainsAny(id, objectIDForbidden)
}

// Contains сообщает, перечисляет ли закрытый пообъектный перечень цели объект
// (dottedType, id). Это проверка членства наименьших привилегий: совпадение по
// role.rules материализует ТОЛЬКО объект, который цель тоже перечисляет. Цель
// AllInScope или пустая явных объектов здесь не перечисляет (её ширина — весь
// якорь, его материализует ветвь «вся область» реконсайлера, а не эта проверка),
// поэтому Contains для неё ложен; вызывающий судит IsEmpty()/AllInScope до неё.
func (t AccessTarget) Contains(dottedType, id string) bool {
	for _, r := range t.Resources {
		if r.Type == dottedType && r.ID == id {
			return true
		}
	}
	return false
}

// ResourceIDsForTypes возвращает идентификаторы пообъектных элементов цели,
// чей точечный тип входит в `types` (порядок сохранён, повторы сняты). По ним
// реконсайлер находит кандидатов ARM_ANCHOR пообъектной цели по идентификатору
// (MatchByIDs), а не обходом всей области (MatchAllInScope) — путь
// материализации наименьших привилегий (IAM-1-21). Пусто, если ни один элемент
// не подходит по типу.
func (t AccessTarget) ResourceIDsForTypes(types []string) []string {
	if len(t.Resources) == 0 || len(types) == 0 {
		return nil
	}
	want := make(map[string]struct{}, len(types))
	for _, ty := range types {
		want[ty] = struct{}{}
	}
	seen := make(map[string]struct{}, len(t.Resources))
	var out []string
	for _, r := range t.Resources {
		if _, ok := want[r.Type]; !ok {
			continue
		}
		if _, dup := seen[r.ID]; dup {
			continue
		}
		seen[r.ID] = struct{}{}
		out = append(out, r.ID)
	}
	return out
}

// Digest returns a deterministic, set-based canonicalization of the target for the
// active-grant partial UNIQUE. AllInScope / empty → "all"; a resource set → a hash
// of its SORTED "type:id" members (order-independent — the same set in any order
// collides, IAM-1-29).
func (t AccessTarget) Digest() string {
	if t.AllInScope || len(t.Resources) == 0 {
		return "all"
	}
	members := make([]string, 0, len(t.Resources))
	for _, r := range t.Resources {
		members = append(members, r.Type+":"+r.ID)
	}
	sort.Strings(members)
	sum := sha256.Sum256([]byte(strings.Join(members, "\n")))
	return "obj:" + hex.EncodeToString(sum[:])
}

// splitDottedType делит точечный тип `<module>.<resource>` на части по первой
// точке. ok=false, когда форма не `<непусто>.<непусто>`.
func splitDottedType(dotted string) (module, resource string, ok bool) {
	i := strings.IndexByte(dotted, '.')
	if i <= 0 || i >= len(dotted)-1 {
		return "", "", false
	}
	return dotted[:i], dotted[i+1:], true
}

// CoversType сообщает, дают ли авторские правила роли глаголы на точечный тип
// `<module>.<resource>` (redesign-2026 F9, ворота 3 / IAM-1-24). Правило
// покрывает тип, когда совпадает Module, а Resources перечисляет ресурс (или "*").
// Пустые правила не покрывают ничего.
func (rs Rules) CoversType(dottedType string) bool {
	module, resource, ok := splitDottedType(dottedType)
	if !ok {
		return false
	}
	for _, r := range rs {
		if r.Module != module {
			continue
		}
		for _, res := range r.Resources {
			if res == "*" || res == resource {
				return true
			}
		}
	}
	return false
}

// TargetTypeCatalog — ПОРТ живого каталога типов, каким его видит проверка цели
// выдачи: есть ли у платформы ЖИВАЯ строка каталога с таким точечным именем.
// Объявлен здесь, у потребителя; реализация — `catalog.Facts` (снимок живых
// строк). Порт узкий намеренно: цели нужен ровно один факт — есть ли строка.
type TargetTypeCatalog interface {
	// FGAObjectType — имя типа модели для точечного имени каталога; ok=false у
	// ресурса, чья строка снята либо которого в каталоге нет вовсе.
	FGAObjectType(dotted string) (string, bool)
}

// ValidTargetType сообщает, может ли точечный `<module>.<resource>` быть назван
// типом пообъектной цели выдачи: тогда и только тогда, когда у типа есть ЖИВАЯ
// строка каталога платформы (Р1 приёмки
// `access-target-names-live-catalog-types.md`, kaname#904).
//
// Почему источник — каталог. Цель чтится в одном месте: реконсайлер сравнивает
// её с типом объекта из зеркала точным совпадением строк
// (`AccessTarget.Contains`), а зеркало принимает объект лишь живого типа
// (`resource_mirror/emitter.go`, отказ «is not a live entry of the platform
// resource catalog»). Множество типов, которые лента МОЖЕТ произвести, и есть
// живой каталог — включая типы, заведённые манифестами модулей. Закрытый
// перечень в коде (`materializableTypes`) отвечал на этот вопрос второй,
// отдельно сопровождаемой копией и ошибался в обе стороны: тип модуля, живой в
// каталоге, отвергался — и выдача на объект модуля выражалась только всей
// областью, то есть ШИРЕ запрошенного; а тип, которого лента не производит,
// принимался бы и не давал ничего.
//
// Подстановочный `*`, не-точечное имя, другое написание и снятая строка дают
// false: ни у одного из них живой строки нет. Пустой каталог (nil) — false на
// всё: отсутствие источника не превращается во всеразрешение.
func ValidTargetType(cat TargetTypeCatalog, dotted string) bool {
	if cat == nil {
		return false
	}
	_, ok := cat.FGAObjectType(dotted)
	return ok
}

// FirstNonLiveType — первый в порядке перечня тип пообъектной цели, у которого
// нет живой строки каталога; ok=false, когда таких нет (в том числе у цели
// «вся область», у которой типов нет вовсе). Отказ называет ПЕРВЫЙ неживой тип
// (Р3): перечень отвергается целиком, и вызывающему нужен один исправимый адрес.
func (t AccessTarget) FirstNonLiveType(cat TargetTypeCatalog) (string, bool) {
	for _, r := range t.Resources {
		if !ValidTargetType(cat, r.Type) {
			return r.Type, true
		}
	}
	return "", false
}

// DistinctTypes — различные типы пообъектной цели в порядке первого появления.
// Им транзакция записи выдачи спрашивает каталог одним оператором.
func (t AccessTarget) DistinctTypes() []string {
	if len(t.Resources) == 0 {
		return nil
	}
	seen := make(map[string]struct{}, len(t.Resources))
	out := make([]string, 0, len(t.Resources))
	for _, r := range t.Resources {
		if _, dup := seen[r.Type]; dup {
			continue
		}
		seen[r.Type] = struct{}{}
		out = append(out, r.Type)
	}
	return out
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: BUSL-1.1

// Package shared — updatemask.go: UpdateMask validation + predicate.
//
// Заменяет повторяющиеся ~16 LOC (validation loop + apply closure) в каждом
// из 5 Update use-case'ов: account/project/service_account/group/role.
//
// Per-resource maps `<resource>MutableFields` + `<resource>ImmutableFields`
// остаются package-level в каждом ресурсе (контекстные error-messages типа
// `"owner_user_id is immutable after Account.Create"`)
// — они конфигурация, не дубликат.
package shared

import (
	"fmt"

	"github.com/PRO-Robotech/kacho/services/iam/internal/domain"
)

// ValidateUpdateMask проверяет, что каждое поле в mask:
//   - НЕ присутствует в `immutable` map (если присутствует → InvalidArg
//     с per-field error message — по контракту error-format Kachō), И
//   - присутствует в `mutable` set (если нет — Illegal-argument
//     update_mask field — по контракту error-format Kachō).
//
// Пустая mask проходит без ошибок (full-PATCH semantics).
//
// `immutable` value-string — сообщение для конкретного field
// (`"<field> is immutable after <Resource>.Create"` — см. per-resource maps).
func ValidateUpdateMask(mask []string, mutable map[string]struct{}, immutable map[string]string) error {
	for _, f := range mask {
		if msg, isImmut := immutable[f]; isImmut {
			return InvalidArg(f, msg)
		}
		if _, ok := mutable[f]; !ok {
			return InvalidArg(f, fmt.Sprintf("Illegal argument update_mask field %q", f))
		}
	}
	return nil
}

// MaskAllows возвращает true, если поле `field` присутствует в mask, ИЛИ
// если mask пустой (full-PATCH semantics — все поля применяются).
//
// Заменяет inlined-closure pattern:
//
//	apply := func(field string) bool {
//	    if len(mask) == 0 { return true }
//	    for _, m := range mask { if m == field { return true } }
//	    return false
//	}
func MaskAllows(mask []string, field string) bool {
	if len(mask) == 0 {
		return true
	}
	for _, m := range mask {
		if m == field {
			return true
		}
	}
	return false
}

// maskContains — поле ЯВНО указано в mask. В отличие от MaskAllows пустой mask
// здесь дает false (full-PATCH «разрешает все», но не «упоминает» поле явно).
func maskContains(mask []string, field string) bool {
	for _, m := range mask {
		if m == field {
			return true
		}
	}
	return false
}

// ResolveLabelsUpdate решает, нужно ли применить labels в Update, и возвращает
// целевое значение метки.
//
// proto3-map не несет presence: пустой `labels:{}` и отсутствующий labels в теле
// приходят в use-case как nil domain.Labels — неотличимо. Поэтому единственный
// надежный сигнал «очистить labels» — присутствие "labels" в update_mask:
//   - mask содержит "labels"  → apply, значение = тело (nil/пусто → очистка);
//   - mask пустой (full-PATCH) и labels переданы в теле → apply, значение = тело;
//   - иначе                    → labels не трогаем.
//
// При apply=true newLabels всегда non-nil (пустой набор = очистка), чтобы writer
// записал labels='{}' и LabelsEqual корректно сравнил с текущим значением.
func ResolveLabelsUpdate(mask []string, body domain.Labels) (newLabels domain.Labels, apply bool) {
	if maskContains(mask, "labels") {
		if body == nil {
			return domain.Labels{}, true
		}
		return body, true
	}
	if len(mask) == 0 && body != nil {
		return body, true
	}
	return nil, false
}

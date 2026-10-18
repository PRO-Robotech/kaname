// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package accesstarget — ЕДИНСТВЕННОЕ прочтение формы цели привязки
// (`access_bindings.target`, задача kaname#863).
//
// # Почему у прочтения один дом
//
// Цель читают двое: ветвь выдач решения о доступе (SQL в `relverdict`) и
// материализатор (Go, загрузка выдачи в `access_binding_repo.go`). Прежде
// каждый держал своё прочтение, и на формах вне контракта они расходились:
// `{"resources": null}` решение о доступе читало как «ничего», а
// материализатор — как «вся область». Здесь оба прочтения стоят рядом и
// говорят одно и то же правило:
//
//   - «вся область» — корень-объект без ключа `resources` либо пустой перечень;
//   - «названные объекты» — непустой перечень пар «тип, идентификатор»;
//   - всё прочее — не цель: решение о доступе не находит по ней ничего,
//     загрузка возвращает ошибку. Ни одно прочтение не толкует незнакомую форму
//     как «вся область».
//
// Форму целиком держит база — ограничение `access_bindings_target_form_ck`
// (миграция `20261018090644_access_binding_target_form_is_held_by_the_base.sql`),
// поэтому третья ветвь у живых строк недостижима; прочтения держат её закрытой
// на случай строки, пришедшей мимо ограничения. Совпадение двух прочтений
// судит табличная проба `forms_integration_test.go`: одна таблица форм на обе
// стороны.
package accesstarget

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// ConstraintName — имя ограничения базы, держащего форму цели.
const ConstraintName = "access_bindings_target_form_ck"

// Ключи формы, дословно.
const (
	keyAllInScope = "allInScope"
	keyResources  = "resources"
	keyType       = "type"
	keyID         = "id"
)

// ErrForm — содержимое колонки не есть цель привязки.
var ErrForm = errors.New("accesstarget: форма цели вне контракта")

// persisted — форма записи.
type persisted struct {
	AllInScope bool          `json:"allInScope,omitempty"`
	Resources  []resourceRef `json:"resources,omitempty"`
}

type resourceRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// Encode — форма записи цели: перечень пар при непустом наборе, иначе
// `{"allInScope":true}` (явная «вся область» и пустое значение домена).
func Encode(t domain.AccessTarget) ([]byte, error) {
	p := persisted{}
	if len(t.Resources) > 0 {
		p.Resources = make([]resourceRef, 0, len(t.Resources))
		for _, r := range t.Resources {
			p.Resources = append(p.Resources, resourceRef{Type: r.Type, ID: r.ID})
		}
	} else {
		p.AllInScope = true
	}
	return json.Marshal(p)
}

// Decode — прочтение цели материализатором. Классы те же, что у
// [WholeScopeSQL] и [NamedSQL]; форма вне контракта — ошибка [ErrForm], а не
// «вся область».
func Decode(b []byte) (domain.AccessTarget, error) {
	var root map[string]json.RawMessage
	if !isKind(b, '{') {
		return domain.AccessTarget{}, fmt.Errorf("%w: корень — не объект", ErrForm)
	}
	if err := json.Unmarshal(b, &root); err != nil {
		return domain.AccessTarget{}, fmt.Errorf("%w: %w", ErrForm, err)
	}
	if raw, ok := root[keyAllInScope]; ok {
		var v bool
		if !isBool(raw) || json.Unmarshal(raw, &v) != nil {
			return domain.AccessTarget{}, fmt.Errorf("%w: %s — не логическое значение", ErrForm, keyAllInScope)
		}
	}
	raw, ok := root[keyResources]
	if !ok {
		return domain.AccessTarget{AllInScope: true}, nil
	}
	if !isKind(raw, '[') {
		return domain.AccessTarget{}, fmt.Errorf("%w: %s — не перечень", ErrForm, keyResources)
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		return domain.AccessTarget{}, fmt.Errorf("%w: %w", ErrForm, err)
	}
	if len(elems) == 0 {
		return domain.AccessTarget{AllInScope: true}, nil
	}
	out := make([]domain.ResourceRef, 0, len(elems))
	for i, e := range elems {
		ref, err := decodeRef(e)
		if err != nil {
			return domain.AccessTarget{}, fmt.Errorf("%w: %s[%d]: %w", ErrForm, keyResources, i, err)
		}
		out = append(out, ref)
	}
	return domain.AccessTarget{Resources: out}, nil
}

// decodeRef — элемент перечня: объект со строковыми `type` и `id`.
func decodeRef(e json.RawMessage) (domain.ResourceRef, error) {
	if !isKind(e, '{') {
		return domain.ResourceRef{}, errors.New("элемент — не объект")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(e, &obj); err != nil {
		return domain.ResourceRef{}, err
	}
	var ref domain.ResourceRef
	for key, dst := range map[string]*string{keyType: &ref.Type, keyID: &ref.ID} {
		raw, ok := obj[key]
		if !ok || !isKind(raw, '"') {
			return domain.ResourceRef{}, fmt.Errorf("%s — не строка", key)
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			return domain.ResourceRef{}, err
		}
	}
	return ref, nil
}

// isKind — первый значащий знак значения JSON.
func isKind(raw []byte, first byte) bool {
	t := bytes.TrimLeft(raw, " \t\r\n")
	return len(t) > 0 && t[0] == first
}

// isBool — значение JSON есть true либо false.
func isBool(raw []byte) bool {
	t := bytes.TrimSpace(raw)
	return bytes.Equal(t, []byte("true")) || bytes.Equal(t, []byte("false"))
}

// WholeScopeSQL — прочтение решения о доступе: цель в колонке col — «вся
// область». Тот же класс, что `Decode` → AllInScope.
func WholeScopeSQL(col string) string {
	return `(jsonb_typeof(` + col + `) = 'object' AND NOT (` + col + ` ? '` + keyResources + `'))
          OR ` + col + ` -> '` + keyResources + `' = '[]'::jsonb`
}

// NamedSQL — прочтение решения о доступе: цель в колонке col называет пару
// «тип, идентификатор». Тот же класс, что `Decode` → Resources и
// `domain.AccessTarget.Contains`.
func NamedSQL(col, typeExpr, idExpr string) string {
	return col + ` -> '` + keyResources + `' @> jsonb_build_array(jsonb_build_object(
                 '` + keyType + `', ` + typeExpr + `, '` + keyID + `', ` + idExpr + `))`
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package relverdict

// target.go — ЕДИНСТВЕННОЕ прочтение формы цели привязки
// (`access_bindings.target`, задача kaname#863).
//
// # Почему у прочтения один дом
//
// Цель читают двое: ветвь выдач решения о доступе (SQL этого пакета,
// `grantArmPredicate`) и материализатор (Go, загрузка выдачи в
// `access_binding_repo.go` через [DecodeTarget]). Прежде
// каждый держал своё прочтение, и на формах вне контракта они расходились:
// `{"resources": null}` решение о доступе читало как «ничего», а
// материализатор — как «вся область». Здесь оба прочтения стоят рядом и
// говорят одно и то же правило:
//
//   - «вся область» — корень-объект без ключа `resources` либо пустой перечень;
//   - «названные объекты» — непустой перечень пар «тип, идентификатор»;
//   - всё прочее — не цель, и такой строки нет: форму целиком держит база,
//     ограничение `access_bindings_target_form_ck` (миграция
//     `20261018090644_access_binding_target_form_is_held_by_the_base.sql`).
//
// [DecodeTarget] принимает РОВНО то, что принимает ограничение, и на прочем
// возвращает [ErrTargetForm], а не «вся область». SQL-прочтение на формах, где
// прочтения расходились до kaname#863 (корень не объект, `resources` не
// перечень), не находит ничего; его класс на прочих формах вне контракта не
// обещается — их не пропускает база. Совпадение двух прочтений на каждой
// законной форме и совпадение законного у [DecodeTarget] и у базы судит
// табличная проба `target_forms_integration_test.go`: одна таблица форм на обе
// стороны.
//
// Дом — этот пакет, а не отдельный: SQL-прочтение цели есть часть запроса
// вердикта, и его текст обязан лежать под отпечатком предмета замера
// (`scalegrid.FingerprintPredicate` — не-тестовые .go каталога `relverdict`),
// иначе правка прочтения не обесценила бы отчёты R7.

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// TargetFormConstraint — имя ограничения базы, держащего форму цели.
const TargetFormConstraint = "access_bindings_target_form_ck"

// Ключи формы, дословно.
const (
	targetKeyAllInScope = "allInScope"
	targetKeyResources  = "resources"
	targetKeyType       = "type"
	targetKeyID         = "id"
)

// ErrTargetForm — содержимое колонки не есть цель привязки.
var ErrTargetForm = errors.New("relverdict: форма цели вне контракта")

// targetPersisted — форма записи.
type targetPersisted struct {
	AllInScope bool                `json:"allInScope,omitempty"`
	Resources  []targetResourceRef `json:"resources,omitempty"`
}

type targetResourceRef struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

// EncodeTarget — форма записи цели: перечень пар при непустом наборе, иначе
// `{"allInScope":true}` (явная «вся область» и пустое значение домена).
func EncodeTarget(t domain.AccessTarget) ([]byte, error) {
	p := targetPersisted{}
	if len(t.Resources) > 0 {
		p.Resources = make([]targetResourceRef, 0, len(t.Resources))
		for _, r := range t.Resources {
			p.Resources = append(p.Resources, targetResourceRef{Type: r.Type, ID: r.ID})
		}
	} else {
		p.AllInScope = true
	}
	return json.Marshal(p)
}

// DecodeTarget — прочтение цели материализатором. Классы те же, что у
// wholeScopeTarget и namedInTarget; форма вне контракта — ошибка [ErrTargetForm], а не
// «вся область».
func DecodeTarget(b []byte) (domain.AccessTarget, error) {
	var root map[string]json.RawMessage
	if !jsonKind(b, '{') {
		return domain.AccessTarget{}, fmt.Errorf("%w: корень — не объект", ErrTargetForm)
	}
	if err := json.Unmarshal(b, &root); err != nil {
		return domain.AccessTarget{}, fmt.Errorf("%w: %w", ErrTargetForm, err)
	}
	if raw, ok := root[targetKeyAllInScope]; ok {
		var v bool
		if !jsonBool(raw) || json.Unmarshal(raw, &v) != nil {
			return domain.AccessTarget{}, fmt.Errorf("%w: %s — не логическое значение", ErrTargetForm, targetKeyAllInScope)
		}
	}
	raw, ok := root[targetKeyResources]
	if !ok {
		return domain.AccessTarget{AllInScope: true}, nil
	}
	if !jsonKind(raw, '[') {
		return domain.AccessTarget{}, fmt.Errorf("%w: %s — не перечень", ErrTargetForm, targetKeyResources)
	}
	var elems []json.RawMessage
	if err := json.Unmarshal(raw, &elems); err != nil {
		return domain.AccessTarget{}, fmt.Errorf("%w: %w", ErrTargetForm, err)
	}
	if len(elems) == 0 {
		return domain.AccessTarget{AllInScope: true}, nil
	}
	out := make([]domain.ResourceRef, 0, len(elems))
	for i, e := range elems {
		ref, err := decodeTargetRef(e)
		if err != nil {
			return domain.AccessTarget{}, fmt.Errorf("%w: %s[%d]: %w", ErrTargetForm, targetKeyResources, i, err)
		}
		out = append(out, ref)
	}
	return domain.AccessTarget{Resources: out}, nil
}

// decodeTargetRef — элемент перечня: объект со строковыми `type` и `id`.
func decodeTargetRef(e json.RawMessage) (domain.ResourceRef, error) {
	if !jsonKind(e, '{') {
		return domain.ResourceRef{}, errors.New("элемент — не объект")
	}
	var obj map[string]json.RawMessage
	if err := json.Unmarshal(e, &obj); err != nil {
		return domain.ResourceRef{}, err
	}
	var ref domain.ResourceRef
	for key, dst := range map[string]*string{targetKeyType: &ref.Type, targetKeyID: &ref.ID} {
		raw, ok := obj[key]
		if !ok || !jsonKind(raw, '"') {
			return domain.ResourceRef{}, fmt.Errorf("%s — не строка", key)
		}
		if err := json.Unmarshal(raw, dst); err != nil {
			return domain.ResourceRef{}, err
		}
	}
	return ref, nil
}

// jsonKind — первый значащий знак значения JSON.
func jsonKind(raw []byte, first byte) bool {
	t := bytes.TrimLeft(raw, " \t\r\n")
	return len(t) > 0 && t[0] == first
}

// jsonBool — значение JSON есть true либо false.
func jsonBool(raw []byte) bool {
	t := bytes.TrimSpace(raw)
	return bytes.Equal(t, []byte("true")) || bytes.Equal(t, []byte("false"))
}

// wholeScopeTarget — прочтение решения о доступе: цель привязки `b.target` —
// «вся область». Тот же класс, что [DecodeTarget] → AllInScope. Проверять
// ОТСУТСТВИЕ ключа через «-> 'resources' IS NULL» нельзя: у корня-не-объекта
// NULL даёт и это выражение (довод — в шапке `grantArmPredicate`).
const wholeScopeTarget = `(jsonb_typeof(b.target) = 'object' AND NOT (b.target ? '` + targetKeyResources + `'))
          OR b.target -> '` + targetKeyResources + `' = '[]'::jsonb`

// namedInTarget — прочтение решения о доступе: цель привязки называет пару
// «тип, id» (тип — в словаре каталога). Тот же класс, что [DecodeTarget] →
// Resources и `domain.AccessTarget.Contains`.
func namedInTarget(typeExpr, idExpr string) string {
	return `b.target -> '` + targetKeyResources + `' @> jsonb_build_array(jsonb_build_object(
                 '` + targetKeyType + `', ` + typeExpr + `, '` + targetKeyID + `', ` + idExpr + `))`
}

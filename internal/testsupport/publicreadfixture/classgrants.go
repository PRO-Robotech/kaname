// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicreadfixture

// classgrants.go — посевы стадии S7 (kaname#950): модуль решает публичность
// своих объектов сам.
//
// Приёмка docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md,
// редакция 17 (отпечаток d44a9bbbdfef42e5f33d0ded13754ff103a4ae33f7ad6d7695be3865b65f9ae7),
// «Как строится «Дано»», П7:
//   - П7 — документ П6 ([NewEditionFile]) со строкой ключа оболочки
//     `classGrantsOnlyOnContainers: true` сразу после `module: registry`
//     ([WithClassGrantsKey]); «П7 без ключа» — сам документ П6;
//   - П7 с ролями И — тот же документ с двумя ролями модуля, дописанными в конец
//     раздела `roles` ([WithNamedRoles]); «П7 без ключа» с ролями И — документ
//     П6 с теми же ролями.
//
// Каждый близнец строится правкой основы, и дельту сверяет [Delta]: ключ — одна
// добавленная строка, роли — двадцать три добавленные строки, удалённых ноль.
//
// Роли И сужают объекты МЕТКАМИ (`matchLabels`), а не именами: манифест модуля
// не называет конкретных объектов (kaname#965 — ссылка, снятая снятием
// регистрации, вернулась бы на следующем старте), и загрузка отвергает
// `resourceNames` в правиле роли модуля. Ворот S7 это не меняет: вид селектора
// они не судят (Р11 п. 2 (б) приёмки) — роль модуля, сужающая его тип метками,
// открывает тот же обход, что и сужающая именами. Метки реестра X
// ([RegistryXLabels]) кладёт его регистрация в мире SC-81.

import (
	"bytes"
	"fmt"
)

// ClassGrantsKey — ключ оболочки манифеста стадии S7 (Р11 п. 1).
const ClassGrantsKey = "classGrantsOnlyOnContainers"

// envelopeModuleLine — строка оболочки, за которой П7 ставит ключ. Перевод
// строки ПЕРЕД ней обязателен: `module: registry` стоит и в каждом правиле роли
// (`      - module: registry`), и без начала строки вхождений было бы шесть.
const envelopeModuleLine = "\nmodule: registry\n"

// Роли И и И2 (SC-81): имена и id по формуле 'rol' || substr(md5(имя), 1, 17).
// Id выписаны, а не вычислены, — их называет приёмка; согласие с формулой
// сверяет проба ([NamedRoleIID] против `domain.SystemRoleID`).
const (
	NamedRoleIName  = "registry.repo_reader_named"
	NamedRoleIID    = "rol753025eda7953ac9c"
	NamedRoleI2Name = "registry.reg_reader_named"
	NamedRoleI2ID   = "rola8923748827353a58"
	// ReaderRoleName / ReaderRoleID — пробная роль П6 `registry.reader`:
	// правило-якорь над `registry.registries` с вложенным правилом над
	// `registry.repositories` (SC-81 «И (якорь и вложенное правило)»).
	ReaderRoleName = "registry.reader"
	ReaderRoleID   = "rolb812261cfaa239694"
)

// namedRolesBlock — две роли модуля, дописываемые в конец раздела `roles`,
// ярус — кластер: роль И — 13 строк (пустая строка и 12 строк роли), роль И2 —
// 10 строк (пустая и 9). Тип репозиториев ленты ресурса не несёт и метками не
// выбирается (загрузка отвергает `matchLabels` над ним), поэтому роль И сужает
// метками реестры, а тип репозиториев покрывает её вложенное правило — то
// самое покрытие необъявленного типа, которое судят ворота S7 (Р11 п. 2 (б)).
const namedRolesBlock = `
  - id: registry.repo_reader_named
    description: >
      Пробная роль S7: чтение репозиториев реестров, суженных метками.
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: registry
        resources: [registries]
        classes: [get]
        matchLabels: {s7: x}
        children:
          - resources: [repositories]
            classes: [get, list]

  - id: registry.reg_reader_named
    description: >
      Пробная роль S7: чтение реестра X, сужено метками.
    tier: {tierType: iam.cluster, tierId: cluster_root}
    rules:
      - module: registry
        resources: [registries]
        classes: [get]
        matchLabels: {s7: x}
`

// WithClassGrantsKey — документ с ключом S7, равным true: строка ключа встаёт
// сразу после `module: registry`. Дельта — одна добавленная строка.
func WithClassGrantsKey(doc []byte) ([]byte, error) {
	return WithClassGrantsKeyValue(doc, "true")
}

// WithClassGrantsKeyValue — документ с ключом S7 и названным значением
// (SC-80 (б): `false`). Дельта — одна добавленная строка.
func WithClassGrantsKeyValue(doc []byte, value string) ([]byte, error) {
	line := ClassGrantsKey + ": " + value
	twin, err := replaceOnce(doc, envelopeModuleLine, envelopeModuleLine+line+"\n", "вставить ключ S7")
	if err != nil {
		return nil, err
	}
	return twin, requireDelta(doc, twin, nil, []string{line})
}

// WithNamedRoles — документ с ролями И и И2 в конце раздела `roles`. Основа
// обязана кончаться разделом `roles` (иначе роли встали бы в чужой раздел) и
// переводом строки. Дельта — двадцать три добавленные строки.
func WithNamedRoles(doc []byte) ([]byte, error) {
	if !bytes.HasSuffix(doc, []byte("\n")) {
		return nil, fmt.Errorf("publicreadfixture: документ не кончается переводом строки — роли И слились бы с последней строкой")
	}
	if _, err := OnlyPublicReadRole(doc); err != nil {
		return nil, fmt.Errorf("publicreadfixture: основа ролей И: %w", err)
	}
	twin := append(append([]byte(nil), doc...), namedRolesBlock...)
	r, a := Delta(doc, twin)
	if len(r) != 0 || len(a) != 23 {
		return nil, fmt.Errorf("publicreadfixture: роли И: удалено %d (объявлено 0), добавлено %d (объявлено 23)", len(r), len(a))
	}
	return twin, nil
}

// RegistryXLabels — метки, которыми регистрация реестра X в мире SC-81
// отвечает селектору правила роли И2 (`matchLabels: {s7: x}`): роль сужает тип
// реестров до реестра X метками, как прежде — именем (kaname#965).
func RegistryXLabels() map[string]string { return map[string]string{"s7": "x"} }

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
//   - П7 с ролями И — тот же документ, РАЗОБРАННЫЙ загрузчиком, с двумя ролями
//     модуля, дописанными в его раздел `roles` и положенными применителем
//     напрямую, минуя загрузчик; «П7 без ключа» с ролями И — документ П6 с
//     теми же ролями тем же путём.
//
// Роли И сужены именами (`resourceNames`), а манифест модуля конкретных
// объектов не называет (kaname#965): загрузчик такую роль отвергает, и текстом
// её в документ больше не дописать. Строка такой роли остаётся возможной как
// доставленная до запрета, и ворота S7 судят её по-прежнему — тот же приём, что
// у ND-05 (б) ствола (`seedNamedReader`). Роли собирает проба мира SC-81
// структурой манифеста; здесь — их имена и id.
//
// Близнец по ключу строится правкой основы, и дельту сверяет [Delta]: ключ —
// одна добавленная строка, удалённых ноль.

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

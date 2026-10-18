// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelrender

import (
	"crypto/sha256"
	"encoding/hex"
)

// priorEditions — ПЕРЕХОДНЫЙ приём прежней редакции блоков (Р10 приёмки
// anonymous-and-authenticated-are-subject-classes.md, решение диспетчера,
// вариант (а)): тип → sha256 его блока в прежней редакции.
//
// # Почему исключение из «канон неприкосновенен» вообще есть
//
// Публичное чтение контейнера (kaname#856) меняет блоки registry в каноне, а
// манифест registry доставляет kacho. Выкатка идёт сначала kaname, затем kacho:
// kaname новой версии обязана стартовать с манифестом ПРЕЖНЕЙ kacho (ствол
// @a95248464). Поэтому для этих двух типов и только для них рендер доставленного
// манифеста равен либо канону, либо прежней редакции; третья форма — отказ, как
// всегда. Действует при этом канон: прежняя редакция в модель не попадает.
//
// # Что такое «прежняя редакция» — побайтово
//
// Ровно два блока канона kaname @a7a726802: `registry_registry` — строки
// 1303–1332, `registry_repository` — строки 1334–1355 файла
// proto/kaname/cloud/iam/v1/fga_model.fga. Предикат —
// `git show a7a726802:proto/kaname/cloud/iam/v1/fga_model.fga | sed -n 1303,1332p | sha256sum`
// и то же с `1334,1355p`.
//
// # Чем кончается
//
// Приём снимает задача PRO-Robotech/kaname#858 после выкатки kacho с манифестом
// новой редакции; её предикат — `go test ./internal/modelcompose/ -run
// '^TestCompose_SC72_' -count=1` — `ok`. Тем же изменением снимается проба
// приёма прежней редакции (SC-70 (а)).
var priorEditions = map[string]string{
	"registry_registry":   "b115c3c18f6ffdda0c22c1c742da50fbecd1a1f888d28810663429a97b240359",
	"registry_repository": "d2aafdbdba912a2680d636230bf6e046f7434b057ec77f3070968b35de7aaa69",
}

// IsPriorEdition — блок типа равен его прежней редакции побайтово.
//
// Объявлено ОДИН раз, здесь, и зовётся обоими судьями совпадения канона с
// манифестом: сборкой модели на старте (`modelcompose.Compose`) и сверкой
// дерева (`Sweep`, `tools` TestModelCanonCheck…). Разойдясь, они дали бы старт,
// принимающий прежнюю редакцию, при красной сверке дерева — либо наоборот.
func IsPriorEdition(typ string, blk []byte) bool {
	want, ok := priorEditions[typ]
	if !ok {
		return false
	}
	// Блок мог уже пройти [TranslateNoteProse]: закреплены байты с прежней
	// прозой, поэтому проза приводится к ней, а закрепление не пересчитывается.
	sum := sha256.Sum256(mapBlockLines(blk, newNoteProse))
	return hex.EncodeToString(sum[:]) == want
}

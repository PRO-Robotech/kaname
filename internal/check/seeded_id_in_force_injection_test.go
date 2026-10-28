// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/ids"

	"github.com/PRO-Robotech/kaname/internal/domain"
)

// Гейт формы посева судит идентификатор, который корпус миграций оставляет В
// СИЛЕ, и судит его формой фундамента (приёмка system-roles-carry-canonical-ids.md,
// kaname#543, DoD п.3; §0.1 — форма судится `ids.HasKnownPrefix`).
//
// # ЗАЧЕМ ДВЕ ОСИ
//
// Ось «в силе». Применённая миграция не правится (ban #5), поэтому вставка с
// негодным id остаётся в корпусе навсегда, а годным id делает её ПОЗДНЯЯ миграция,
// переводящая строку. Гейт, читающий только текст вставки, краснеет на
// исправленном посеве — и тогда единственный выход из красного у него один:
// перечень прощённого, то есть снова послабление.
//
// Ось «алфавит». Проверка пути запроса судит префикс и длину, но не алфавит тела.
// Идентификатор длины 20 с буквой вне алфавита ею принимается, а судьёй
// фундамента — нет; гейт, судящий только ею, молчит ровно на классе дефекта
// системной роли admin.
//
// У каждой оси — дефект и законный близнец, отличающиеся ОДНИМ фактом.

const (
	// inForceBadLenID — дефект длины: 21 знак, алфавит годный.
	inForceBadLenID = "rolqqqqqqqqqqqqqqqqqq"
	// inForceGoodID — годный id: 20 знаков, тело — алфавит фундамента.
	inForceGoodID = "rolqqqqqqqqqqqqqqqqq"
	// inForceBadAlphabetID — дефект алфавита: 20 знаков, последняя буква вне алфавита.
	inForceBadAlphabetID = "rolqqqqqqqqqqqqqqqqi"
)

func inForceRoleSeed(id string) string {
	return "INSERT INTO kaname.roles (id, name, permissions) VALUES ('" + id + "', 'system.synthetic', '[]');\n"
}

// inForceRename — поздняя миграция, переводящая строку роли на годный id.
// Нижняя половина возвращает прежний id: судить обязана верхняя.
func inForceRename(from, to string) string {
	return "-- +goose Up\n" +
		"UPDATE kaname.roles SET id = '" + to + "' WHERE id = '" + from + "';\n" +
		"-- +goose Down\n" +
		"UPDATE kaname.roles SET id = '" + from + "' WHERE id = '" + to + "';\n"
}

// TestSeededIDInForcePremise — предпосылка: синтетика вне перечня посеянного, а
// оси различимы судьёй фундамента ровно так, как объявлено.
func TestSeededIDInForcePremise(t *testing.T) {
	for _, id := range []string{inForceBadLenID, inForceGoodID, inForceBadAlphabetID} {
		require.Falsef(t, domain.IsSeededResourceID(id), "синтетика %q названа перечнем посеянного — инъекция вакуумна", id)
	}
	require.True(t, ids.HasKnownPrefix(inForceGoodID), "годный id не годен судье фундамента")
	require.False(t, ids.HasKnownPrefix(inForceBadLenID), "дефект длины годен судье фундамента")
	require.False(t, ids.HasKnownPrefix(inForceBadAlphabetID), "дефект алфавита годен судье фундамента")
	require.Len(t, inForceBadAlphabetID, len(inForceGoodID), "оси алфавита и длины обязаны не пересекаться")
}

// TestSeededIDGate_InForce_UnrenamedMalformedSeedIsFound — дефект оси «в силе»:
// негодная вставка без поздней миграции. Близнец ниже отличается одним фактом.
func TestSeededIDGate_InForce_UnrenamedMalformedSeedIsFound(t *testing.T) {
	corpus := map[string]string{
		"0001_initial.sql":                   inForceRoleSeed(inForceBadLenID),
		"20991231000000_unrelated_later.sql": "-- +goose Up\nSELECT 1;\n-- +goose Down\nSELECT 1;\n",
	}
	findings, _ := auditSeededIDs(corpus, nil)
	require.Len(t, findings, 1, "негодный посев без перевода оставил гейт зелёным")
	require.Contains(t, findings[0], inForceBadLenID)
}

// TestSeededIDGate_InForce_SeedRenamedLaterIsSilent — законный близнец: та же
// вставка, а поздняя миграция переводит строку на годный id. В силе — годный.
func TestSeededIDGate_InForce_SeedRenamedLaterIsSilent(t *testing.T) {
	corpus := map[string]string{
		"0001_initial.sql":                   inForceRoleSeed(inForceBadLenID),
		"20991231000000_rename_to_canon.sql": inForceRename(inForceBadLenID, inForceGoodID),
	}
	findings, c := auditSeededIDs(corpus, nil)
	require.Emptyf(t, findings, "гейт судит текст вставки, а не id, оставшийся в силе: %v", findings)
	require.Positive(t, c.judged, "id в силе не был судим — молчание вакуумно")
}

// TestSeededIDGate_Alphabet_OutsideLetterIsFound — дефект оси «алфавит»: длина
// верна, буква тела вне алфавита фундамента.
func TestSeededIDGate_Alphabet_OutsideLetterIsFound(t *testing.T) {
	corpus := map[string]string{"0001_initial.sql": inForceRoleSeed(inForceBadAlphabetID)}
	findings, _ := auditSeededIDs(corpus, nil)
	require.Len(t, findings, 1, "id с буквой вне алфавита прошёл гейт — судья не знает алфавита")
	require.Contains(t, findings[0], inForceBadAlphabetID)
}

// TestSeededIDGate_Alphabet_CanonicalBodyIsSilent — законный близнец оси
// «алфавит»: та же длина, тело в алфавите.
func TestSeededIDGate_Alphabet_CanonicalBodyIsSilent(t *testing.T) {
	corpus := map[string]string{"0001_initial.sql": inForceRoleSeed(inForceGoodID)}
	findings, c := auditSeededIDs(corpus, nil)
	require.Empty(t, findings, "гейт краснеет на годном id — отрицания выше ничего не докажут")
	require.Equal(t, 1, c.judged)
}

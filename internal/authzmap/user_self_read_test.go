// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzmap_test

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// TestUserSelfRead_VGetConsumesTheSelfTuple — читающий глагол записи пользователя
// принимает `subject`, то есть самого пользователя.
//
// Почему это отдельная проба, а не строка в гейте дрейфа. Дрейф-гейт сверяет, какие
// отношения СУЩЕСТВУЮТ; здесь предмет — из чего складывается ОДНО отношение. Кортеж
// `iam_user:<usr> # subject @ user:<usr>` эмитируется на заведении пользователя
// (см. bootstrapTuples в .../api/user/internal_upsert.go), и его назначение —
// «чтобы пользователь мог получить сам себя». Разводка тиров и глаголов оставила
// `subject` только в `viewer`, тогда как гейт чтения — `v_get`: кортеж писался,
// проверкой не читался, самочтение не работало НИ У КОГО. Со стороны это выглядело
// как «пользователя нет» — скрытие существования отвечает тем же текстом, что и
// настоящее отсутствие, поэтому дефект был тихим и прожил долго.
//
// Проба утверждает ОБЕ стороны. Без второй половины она зеленела бы на модели, где
// `subject` дописан всем четырём глаголам разом, — то есть где право читать себя
// незаметно стало правомménять и удалять себя.
func TestUserSelfRead_VGetConsumesTheSelfTuple(t *testing.T) {
	data, err := os.ReadFile(canonicalModelPath(t))
	require.NoError(t, err)

	defs := relationDefs(t, string(data), "iam_user")
	require.NotEmpty(t, defs, "тип iam_user не разобран — предпосылка пробы не выполнена, "+
		"а молчаливый зелёный означал бы «проверено»")

	vget, ok := defs["v_get"]
	require.True(t, ok, "у iam_user нет глагола v_get — читать нечем")
	require.Contains(t, vget, "subject",
		"читающий глагол обязан принимать самого пользователя: кортеж `subject` "+
			"эмитируется на заведении пользователя именно ради самочтения, и глагол, "+
			"который его не читает, оставляет этот кортеж без потребителя")

	// Положительный контроль: НИ ОДИН распоряжающийся глагол себя `subject` не даёт.
	//
	// Набор берётся ИЗ МОДЕЛИ, а не выписывается: `v_update` был снят с этого типа
	// (#1128), и литеральный перечень покраснел бы на его отсутствии — то есть
	// контроль ломался бы от правки, которой он не про что. Невырожденность
	// перечня утверждается отдельно, иначе «ни один» было бы истинно на пустоте.
	var others []string
	for verb := range defs {
		if strings.HasPrefix(verb, "v_") && verb != "v_get" {
			others = append(others, verb)
		}
	}
	sort.Strings(others)
	require.NotEmpty(t, others,
		"кроме `v_get`, у iam_user не объявлено ни одного глагола — положительный контроль "+
			"ниже был бы истинным даром")
	for _, verb := range others {
		require.NotContains(t, defs[verb], "subject",
			"%s не должен выводиться из факта «я — это я»: право читать свою запись и "+
				"право её менять — разные вопросы с разными источниками", verb)
	}
	t.Logf("перепись: глаголов у iam_user %d, из них проверено на `subject` %d",
		len(others)+1, len(others))
}

var reRelationDef = regexp.MustCompile(`^\s*define\s+([a-z_0-9]+)\s*:\s*(.+?)\s*$`)

// relationDefs — определения отношений одного типа: имя → тело определения.
//
// Гейт дрейфа рядом разбирает лишь ИМЕНА отношений, поэтому «из чего складывается
// отношение» им не проверить; этот разбор добирает недостающее и намеренно живёт
// рядом с ним, а не заводит вторую копию модели.
func relationDefs(t *testing.T, dsl, typeName string) map[string]string {
	t.Helper()
	out := map[string]string{}
	inType := false
	for _, line := range strings.Split(dsl, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "type ") {
			inType = strings.TrimSpace(strings.TrimPrefix(trimmed, "type ")) == typeName
			continue
		}
		if !inType || strings.HasPrefix(trimmed, "#") {
			continue
		}
		if m := reRelationDef.FindStringSubmatch(line); m != nil {
			out[m[1]] = m[2]
		}
	}
	return out
}

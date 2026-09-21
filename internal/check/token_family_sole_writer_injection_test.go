// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// token_family_sole_writer_injection_test.go — ДОКАЗАТЕЛЬСТВО, что гейт
// способен упасть, и что он молчит на законном близнеце.
//
// Гейт, не проверенный инъекцией, утверждает «находок ноль» одинаково и когда
// дерево чисто, и когда разбор не видит предмета.
package check_test

import (
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const guardedWriterSrc = `package pg

const insertFamilyOnLiveSessionSQL = ` + "`" + `
WITH s AS (
    SELECT ended_at, expires_at FROM kaname.human_sessions WHERE id = $4
), ins AS (
    INSERT INTO kaname.token_families (id, client_id, user_id, session_id, scope)
    SELECT $1, $2, $3, $4, $5 FROM s
     WHERE s.ended_at IS NULL AND s.expires_at > now()
    RETURNING 1
)
SELECT (SELECT count(*) FROM s)::int, (SELECT count(*) FROM ins)::int` + "`" + `
`

const bareWriterSrc = `package pg

const sneakySQL = ` + "`" + `
INSERT INTO kaname.token_families (id, client_id, user_id, session_id, scope)
VALUES ($1,$2,$3,$4,$5)` + "`" + `
`

// mentionOnlySrc — ЗАКОННЫЙ БЛИЗНЕЦ: таблица названа в комментарии и в строке,
// которая ничего не вставляет. Гейт обязан смолчать — иначе он запрещает о
// предмете писать.
const mentionOnlySrc = `package pg

// Семейство живёт в kaname.token_families; INSERT INTO упомянут здесь текстом.
const readFamilySQL = ` + "`" + `SELECT id FROM kaname.token_families WHERE id = $1` + "`" + `
`

// TestTokenFamilyGateFindsASecondWriter — планта: вставка без условия живости.
func TestTokenFamilyGateFindsASecondWriter(t *testing.T) {
	t.Parallel()

	census, err := check.TokenFamilyWriters(map[string]string{
		"guarded.go": guardedWriterSrc,
		"sneaky.go":  bareWriterSrc,
	})
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if census.GuardedCount != 1 {
		t.Fatalf("охраняемых обязан найти ровно одного, нашёл %d", census.GuardedCount)
	}
	if census.BareCount != 1 {
		t.Fatalf("второй писатель ОБЯЗАН быть находкой: найдено без условия живости %d", census.BareCount)
	}
	var sawSneaky bool
	for _, w := range census.Writers {
		if w.File == "sneaky.go" && w.Kind == check.TokenFamilyWriterBare {
			sawSneaky = true
		}
	}
	if !sawSneaky {
		t.Fatal("находка обязана нести КООРДИНАТУ плантированного писателя")
	}
}

// TestTokenFamilyGateIsSilentOnAMention — законный близнец: упоминание таблицы
// и чтение из неё находкой не являются.
func TestTokenFamilyGateIsSilentOnAMention(t *testing.T) {
	t.Parallel()

	census, err := check.TokenFamilyWriters(map[string]string{
		"guarded.go": guardedWriterSrc,
		"mention.go": mentionOnlySrc,
	})
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if census.BareCount != 0 {
		t.Fatalf("упоминание и чтение находкой быть не могут: найдено %d", census.BareCount)
	}
	if census.GuardedCount != 1 {
		t.Fatalf("охраняемый обязан остаться найденным: %d", census.GuardedCount)
	}
}

// TestTokenFamilyGateRedOnAnEmptyTraversal — предпосылка: на дереве без единого
// писателя перепись обязана дать НОЛЬ охраняемых, а не смолчать «чисто».
// Решение о красном принимает проба на дереве; здесь утверждается число.
func TestTokenFamilyGateRedOnAnEmptyTraversal(t *testing.T) {
	t.Parallel()

	census, err := check.TokenFamilyWriters(map[string]string{
		"nothing.go": "package pg\n\nconst x = `SELECT 1`\n",
	})
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	if census.GuardedCount != 0 || census.BareCount != 0 {
		t.Fatalf("на дереве без писателей обе величины обязаны быть нулём: %d и %d",
			census.GuardedCount, census.BareCount)
	}
	if census.FilesParsed != 1 {
		t.Fatalf("объём осмотренного обязан быть напечатан честно: файлов %d", census.FilesParsed)
	}
}

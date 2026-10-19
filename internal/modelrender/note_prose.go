// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelrender

import (
	"strings"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// priorNoteProse — прежняя проза примечаний публичного чтения → её запись после
// перевода на класс субъекта: строка блока целиком (с отступом блока), ключ —
// прежняя, значение — новая.
//
// Манифесты registry и nlb ствола kacho описывали публичное чтение словом
// `user:*`, а канон после классов субъектов (kaname#829) называет класс
// `system_class` (kaname#855). Канон переносит примечания манифеста побайтово, а
// kacho закрепляет kaname пином, поэтому проза переходит парой «канон + манифест»
// (kacho#3272), и перевод разрывает взаимную блокировку так же, как
// [subjectWords] для записи субъекта: манифест прежней прозы и манифест новой
// порождают при сверке один и тот же блок канона.
//
// Переводится строка, равная прежней ЦЕЛИКОМ; всякая иная форма строки
// воспроизводится дословно. Допуск переводом не ослабляется: канон несёт только
// новую прозу, и сверка судит перевод, а не прежнюю запись.
//
// Условие снятия: манифесты registry и nlb kacho несут новую прозу и kacho
// поднял пин kaname (PRO-Robotech/kacho#3272). Снятие — задача
// PRO-Robotech/kaname#836 вместе со снятием перевода слова записи субъекта; её
// предикат — вывод `git grep -nE
// 'priorNoteProse|newNoteProse|translateNoteProse|RenderForCanon' -- internal`
// пуст, и сборка модели со сверкой дерева зовут [RenderWithKeyTerms] и [Render].
var priorNoteProse = map[string]string{
	"    # RG-1 D-7: `user:*` public-read wildcard — anonymous pull of a PUBLIC repo.": "    # RG-1 D-7: `system_class:anonymous` public-read subject — anonymous pull of a PUBLIC repo.",
	"    # The wildcard grants v_get ONLY on repos that ALSO carry an explicit":        "    # The class grants v_get ONLY on repos that ALSO carry an explicit",
	"    # `user:* v_get` tuple emitted by the registry overlay (visibility=PUBLIC);":  "    # `system_class:anonymous v_get` tuple emitted by the registry overlay (visibility=PUBLIC);",
	"    # absent that tuple `user:*` has no access → uniform 404. ONLY v_get gains":   "    # absent that tuple the class has no access → uniform 404. ONLY v_get gains",
	"    # the wildcard — no write relation does (anon is a read-only floor, B14).":    "    # the class — no write relation does (anon is a read-only floor, B14).",
	"    # the repo owner fully manages their own repository; `user:*` wildcard stays": "    # the repo owner fully manages their own repository; the `system_class` subject stays",
	"    #   * `[service_account]` ONLY — no `user`, no `group#member`, no `user:*`.":  "    #   * `[service_account]` ONLY — no `user`, no `group#member`, no `system_class`.",
}

// newNoteProse — обратная таблица: новая проза → прежняя. Нужна одному читателю,
// [IsPriorEdition]: байты прежней редакции закреплены Р10 хешем блока С ПРЕЖНЕЙ
// ПРОЗОЙ, и блок, уже переведённый, приводится к ней перед хешированием, а не
// закрепление пересчитывается.
var newNoteProse = func() map[string]string {
	out := make(map[string]string, len(priorNoteProse))
	for prior, now := range priorNoteProse {
		out[now] = prior
	}
	return out
}()

// mapBlockLines — построчная замена блока по таблице; строка вне таблицы
// остаётся как есть, число и порядок строк не меняются.
func mapBlockLines(blk []byte, table map[string]string) []byte {
	lines := strings.Split(string(blk), "\n")
	for i, l := range lines {
		if to, ok := table[l]; ok {
			lines[i] = to
		}
	}
	return []byte(strings.Join(lines, "\n"))
}

// translateNoteProse — блок с прозой примечаний в записи после перевода.
func translateNoteProse(blk []byte) []byte { return mapBlockLines(blk, priorNoteProse) }

// RenderForCanon — блок манифеста в виде, в котором его судят против канона:
// [Render] плюс [translateNoteProse]. Единственный вход обоих судей совпадения
// канона с манифестом — сборки модели на старте и сверки дерева: разойдясь, они
// принимали бы разную прозу. Каждого судью держит своя проба: сборку —
// `modelcompose` (SC-829, SC-70), сверку — sweep_note_prose_test.go.
func RenderForCanon(r manifest.Resource) ([]byte, error) {
	b, _, err := RenderForCanonWithKeyTerms(r)
	return b, err
}

// RenderForCanonWithKeyTerms — [RenderForCanon] вместе с термами ключа
// публичного чтения из [RenderWithKeyTerms]: сборке модели нужны оба — текст
// блока в форме судей канона и перечень термов для допуска (kaname#866).
// Перевод меняет только строки прозы примечаний, строк отношений не трогает,
// поэтому термы, отмеченные проходом рендера, остаются термами переведённого
// блока.
func RenderForCanonWithKeyTerms(r manifest.Resource) ([]byte, []authzmodel.KeyTerm, error) {
	b, terms, err := RenderWithKeyTerms(r)
	if err != nil {
		return nil, nil, err
	}
	return translateNoteProse(b), terms, nil
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package publicreadfixture — фикстуры доставки стадии S5 (kaname#856) и их
// законные близнецы с ВЫЧИСЛЕННОЙ дельтой.
//
// Приёмка: docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md,
// П6, SC-60…73.
//
// # Зачем отдельный пакет, а не по копии в каждой пробе
//
// Фикстура новой редакции манифеста registry нужна пробам ПЯТИ пакетов сразу
// (manifest, modelrender, modelcompose, reconcile, access_binding). Копия в
// каждом — пять мест об одном предмете; разойдясь, они дали бы пробы, зелёные
// по разным манифестам. Так же устроен `catalogfixture`.
//
// # Близнец строится ПРАВКОЙ, а дельту считает пакет, а не автор
//
// Отрицательному кейсу положен положительный близнец, отличающийся ровно одним
// фактом. Объявление «отличается одним» здесь не принимается на веру: всякий
// близнец строится из документа-основы заменой, и [Delta] сверяет вычисленную
// разницу строк с объявленной. Близнец, меняющий два факта, отвергается раньше,
// чем проба дойдёт до испытуемого: вердикта держателя он не даёт.
package publicreadfixture

import (
	"bytes"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// Имена файлов фикстур в `internal/manifest/testdata`.
const (
	// NewEditionFile — манифест registry новой редакции (kacho#3274): ключ на
	// `registries` и раздел `roles` с ролью `registry.public.read`.
	NewEditionFile = "registry.public-read-fixture.yaml"
	// PriorEditionFile — раздел `resources` манифеста registry kacho @a95248464.
	PriorEditionFile = "registry.prior-edition-fixture.yaml"
	// ProbemodFile — модуль, отличный от registry (SC-65 «И»).
	ProbemodFile = "probemod.public-read-fixture.yaml"
	// ChildrenProbemodFile — модуль трёх уровней родства (П3 приёмки
	// `nested-rule-reaches-descendants-of-a-named-container.md`, kaname#874):
	// глубину вложенного правила утверждают на нём (ND-08).
	ChildrenProbemodFile = "probemod.children-fixture.yaml"
)

// Ключ и его единственная законная форма (Р9 «Способ»: ключ либо отсутствует,
// либо равен true).
const (
	Key     = "publicReadToChildren"
	keyLine = "    publicReadToChildren: true"
)

// PublicReadRoleName / PublicReadRoleID — роль Р9 п. 4 и её id
// ('rol' || substr(md5(имя), 1, 17)).
const (
	PublicReadRoleName = "registry.public.read"
	PublicReadRoleID   = "rolb1325b011aa17211d"
)

// testdataDir — каталог фикстур, найденный от ЭТОГО файла: пробы зовут пакет из
// разных каталогов, и рабочий каталог процесса о нём не говорит ничего.
func testdataDir() (string, error) {
	_, self, _, ok := runtime.Caller(0)
	if !ok {
		return "", fmt.Errorf("publicreadfixture: путь своего исходника не определён")
	}
	return filepath.Join(filepath.Dir(self), "..", "..", "manifest", "testdata"), nil
}

// Read — байты фикстуры по имени файла.
func Read(name string) ([]byte, error) {
	dir, err := testdataDir()
	if err != nil {
		return nil, err
	}
	// Чтение — из ФИКСИРОВАННОГО корня фикстур через `os.DirFS`: имя проверяется
	// как локальное (`fs.ValidPath` — без `..` и абсолютного пути), и выйти за
	// каталог `testdata` им нельзя.
	if !fs.ValidPath(name) {
		return nil, fmt.Errorf("publicreadfixture: имя фикстуры %q не локальное", name)
	}
	b, err := fs.ReadFile(os.DirFS(dir), name)
	if err != nil {
		return nil, fmt.Errorf("publicreadfixture: фикстура %s не прочитана: %w", name, err)
	}
	if len(bytes.TrimSpace(b)) == 0 {
		return nil, fmt.Errorf("publicreadfixture: фикстура %s пуста", name)
	}
	return b, nil
}

// Delta — разница двух документов построчно: строки, которых нет во втором
// (removed), и строки, которых нет в первом (added). Порядок — порядок
// появления. Повторяющиеся строки считаются кратностью.
func Delta(base, twin []byte) (removed, added []string) {
	count := func(doc []byte) map[string]int {
		m := map[string]int{}
		for _, l := range strings.Split(string(doc), "\n") {
			m[l]++
		}
		return m
	}
	bc, tc := count(base), count(twin)
	seenR, seenA := map[string]int{}, map[string]int{}
	for _, l := range strings.Split(string(base), "\n") {
		seenR[l]++
		if seenR[l] > tc[l] {
			removed = append(removed, l)
		}
	}
	for _, l := range strings.Split(string(twin), "\n") {
		seenA[l]++
		if seenA[l] > bc[l] {
			added = append(added, l)
		}
	}
	return removed, added
}

// replaceOnce — замена ровно одного вхождения; иное число вхождений — отказ
// фикстуры, а не молчаливая правка «где нашлось».
func replaceOnce(doc []byte, old, repl, what string) ([]byte, error) {
	if n := bytes.Count(doc, []byte(old)); n != 1 {
		return nil, fmt.Errorf("publicreadfixture: %s: ожидалось одно вхождение %q, найдено %d", what, old, n)
	}
	return bytes.Replace(doc, []byte(old), []byte(repl), 1), nil
}

// WithoutKey — близнец «ключ отсутствует»: вычеркнута ровно одна строка ключа.
// Дельта сверяется: удалена одна строка, добавлено ноль.
func WithoutKey(doc []byte) ([]byte, error) {
	twin, err := replaceOnce(doc, keyLine+"\n", "", "вычеркнуть ключ")
	if err != nil {
		return nil, err
	}
	return twin, requireDelta(doc, twin, []string{keyLine}, nil)
}

// WithKeyValue — близнец «ключ равен <value>» (SC-71 (в): `false`). Дельта —
// одна строка заменена одной.
func WithKeyValue(doc []byte, value string) ([]byte, error) {
	repl := "    " + Key + ": " + value
	twin, err := replaceOnce(doc, keyLine+"\n", repl+"\n", "сменить значение ключа")
	if err != nil {
		return nil, err
	}
	return twin, requireDelta(doc, twin, []string{keyLine}, []string{repl})
}

// KeyMovedToRepositories — третья форма SC-70 (в): ключ стоит на
// `repositories` (`resources[1]`) вместо `registries`. Один факт — ресурс, на
// котором стоит ключ: строка ключа уходит из одного ресурса и встаёт в другой.
func KeyMovedToRepositories(doc []byte) ([]byte, error) {
	withoutKey, err := replaceOnce(doc, keyLine+"\n", "", "снять ключ с registries")
	if err != nil {
		return nil, err
	}
	anchor := "    objectType: registry_repository\n"
	twin, err := replaceOnce(withoutKey, anchor, anchor+keyLine+"\n", "поставить ключ на repositories")
	if err != nil {
		return nil, err
	}
	// Построчная разница здесь пуста: та же строка переехала. Факт сверяется
	// позицией — ключ теперь стоит в записи repositories и только в ней.
	if r, a := Delta(doc, twin); len(r) != 0 || len(a) != 0 {
		return nil, fmt.Errorf("publicreadfixture: перенос ключа изменил не только позицию: удалено %q, добавлено %q", r, a)
	}
	if !bytes.Contains(twin, []byte(anchor+keyLine+"\n")) {
		return nil, fmt.Errorf("publicreadfixture: ключ не встал в запись repositories")
	}
	return twin, nil
}

// OneWordInRegistriesNote — третья форма SC-70 (г): в авторском примечании
// ресурса `registries` изменено одно слово. Дельта — одна строка заменена
// одной, и отличаются они ровно одним словом.
func OneWordInRegistriesNote(doc []byte) ([]byte, error) {
	const (
		old  = "          # computed relation (like `editor: this or admin`), NOT a hierarchy cascade.\n"
		repl = "          # computed relation (like `editor: this or admin`), NOT a hierarchy waterfall.\n"
	)
	twin, err := replaceOnce(doc, old, repl, "сменить слово примечания registries")
	if err != nil {
		return nil, err
	}
	return twin, requireDelta(doc, twin,
		[]string{strings.TrimSuffix(old, "\n")}, []string{strings.TrimSuffix(repl, "\n")})
}

// WithoutRoles — документ без раздела `roles` (всё от строки `roles:` до конца).
// Нужен там, где близнецу положено нести ровно прежний состав ролей.
func WithoutRoles(doc []byte) ([]byte, error) {
	i := bytes.Index(doc, []byte("\nroles:\n"))
	if i < 0 {
		return nil, fmt.Errorf("publicreadfixture: раздела roles в документе нет")
	}
	return append([]byte(nil), doc[:i+1]...), nil
}

// OnlyPublicReadRole — документ, в разделе `roles` которого осталась одна роль
// `registry.public.read`: вычеркнуты пробные роли kaname#874, стоящие после неё
// (их kacho#3274 не вносит). Это редакция ровно в том составе, в каком её
// доставляет kacho#3274: правило `[get, list]` над `registries` с вложенным
// `[get, list]` над `repositories`.
//
// Нужен пробам, чьи числа — свойство этой одной роли: пробные роли добавили бы
// к переписи свои пары, и число мерило бы состав фикстуры, а не предмет.
func OnlyPublicReadRole(doc []byte) ([]byte, error) {
	head := []byte("\n  - id: " + PublicReadRoleName + "\n")
	if n := bytes.Count(doc, head); n != 1 {
		return nil, fmt.Errorf("publicreadfixture: роль %s в документе встречается %d раз, нужна ровно одна",
			PublicReadRoleName, n)
	}
	start := bytes.Index(doc, head) + len(head)
	out := doc
	if next := bytes.Index(doc[start:], []byte("\n  - id: ")); next >= 0 {
		out = append([]byte(nil), doc[:start+next+1]...)
	}
	// Вычеркнуть разрешено только роли: раздел верхнего уровня после `roles`
	// ушёл бы вместе с ними молча.
	for _, l := range strings.Split(string(doc[len(out):]), "\n") {
		if l != "" && l[0] != ' ' && l[0] != '#' {
			return nil, fmt.Errorf("publicreadfixture: после ролей стоит раздел верхнего уровня %q — "+
				"вычёркивание сняло бы и его", l)
		}
	}
	if n := bytes.Count(out, []byte("\n  - id: ")); n != 1 {
		return nil, fmt.Errorf("publicreadfixture: после вычёркивания ролей осталось %d, нужна одна", n)
	}
	return out, nil
}

// requireDelta — вычисленная разница обязана совпасть с объявленной.
func requireDelta(base, twin []byte, wantRemoved, wantAdded []string) error {
	r, a := Delta(base, twin)
	if strings.Join(r, "\n") != strings.Join(wantRemoved, "\n") || strings.Join(a, "\n") != strings.Join(wantAdded, "\n") {
		return fmt.Errorf("publicreadfixture: близнец отличается не объявленным фактом: удалено %q (объявлено %q), добавлено %q (объявлено %q)",
			r, wantRemoved, a, wantAdded)
	}
	return nil
}

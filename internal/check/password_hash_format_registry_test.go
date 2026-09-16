// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

// password_hash_format_registry_test.go — гейт: перечень форматов сверен с
// проверяющими дерева (приёмка ID-PW-1 §5 PWV-13, строки 13.1…13.6, и 07.4).

import (
	"os"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// passwordHashRegistrySpec — объявление предмета. Живёт ЗДЕСЬ, в файле пробы:
// координаты перечня и проверяющего в ядре гейта сделали бы гейт своей же
// находкой, а эталон пола, прочитанный из текста приёмки, сверялся бы с
// прозой, а не с нормой.
func passwordHashRegistrySpec() check.PasswordHashRegistrySpec {
	return check.PasswordHashRegistrySpec{
		RegistryRel:  "internal/domain/password_hash_format.go",
		VerifierRel:  "internal/passwordverify/verifier.go",
		SelectorFunc: "inspectAndCompare",
		SettingType:  "Declared",
		RecordType:   "PasswordHashFormatRecord",

		// Эталон пола — строка «хеш нового пароля» одобренной Ф1 §4.1:
		// argon2id, память 64 МБ (65536 КиБ), итераций 3, параллельность 4.
		// Правится ТОЛЬКО вместе с той строкой, её собственным кругом: пол,
		// опущенный одной правкой перечня, обязан быть находкой.
		FloorReference: map[string]map[string]uint32{
			string(domain.PasswordHashFormatArgon2id): {
				string(domain.CostParamArgon2Memory):      65536,
				string(domain.CostParamArgon2Iterations):  3,
				string(domain.CostParamArgon2Parallelism): 4,
			},
		},
	}
}

// liveRegistryRecords — перечень, как его объявляет дерево.
func liveRegistryRecords() []check.PasswordHashRecordView {
	out := make([]check.PasswordHashRecordView, 0)
	for _, r := range domain.PasswordHashFormats() {
		view := check.PasswordHashRecordView{
			Format:   string(r.Format),
			Writable: r.Writable,
			Ceiling:  map[string]uint32{},
			Floor:    map[string]uint32{},
			Range:    map[string][2]uint32{},
		}
		for _, p := range r.Format.CostParams() {
			name := string(p)
			if v, ok := r.Ceiling[p]; ok {
				view.Ceiling[name] = v
			}
			if v, ok := r.Floor[p]; ok {
				view.Floor[name] = v
			}
			if rng, ok := r.Format.Admissibility(p); ok {
				view.Range[name] = [2]uint32{rng.Min, rng.Max}
			}
			view.Params = append(view.Params, name)
		}
		out = append(out, view)
	}
	return out
}

// TestPasswordHashRegistryMatchesItsVerifiers — сам гейт.
//
// Что делать, если он сработал, — исходов три, четвёртого нет:
//
//  1. формат объявлен, а читателя нет → написать проверяющего ЛИБО снять
//     запись; снятие записи вместе с проверяющим гейт пропускает, и это НЕ
//     разрешение снимать: хранилищ установок он не читает, разрешение даёт
//     перепись каждой из них (PWV-17);
//  2. читатель есть, а записи нет → завести запись с потолком и отметкой
//     записываемости: проверяющий без потолка даёт чужому источнику назначать
//     цену каждой попытки;
//  3. пол опущен ниже строки «хеш нового пароля» Ф1 §4.1 → правится та строка
//     своим кругом, вместе с эталоном здесь. Опустить пол одной правкой
//     перечня — не исход: стойкость каждого нового пароля упала бы молча.
func TestPasswordHashRegistryMatchesItsVerifiers(t *testing.T) {
	t.Parallel()

	wd, err := os.Getwd()
	require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: рабочий каталог не установлен")
	root, err := platformtree.ModuleRootFrom(wd)
	require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не найден")
	tree, err := treecorpus.NewTree(root)
	require.NoErrorf(t, err, "состав дерева не установлен — «ноль находок» здесь означало бы «ноль прочитанного»")
	corpus, err := check.CorpusFrom(tree, check.ProductionGoFile)
	require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ: корпус не собран")

	findings, census, err := check.AuditPasswordHashFormatRegistry(corpus, liveRegistryRecords(), passwordHashRegistrySpec())
	require.NoErrorf(t, err, "проверка НЕ ИСПОЛНЯЛАСЬ")
	t.Logf("%s; находок %d", census, len(findings))

	for _, f := range findings {
		t.Error(f)
	}
}

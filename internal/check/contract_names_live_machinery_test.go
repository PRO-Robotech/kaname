// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// contract_names_live_machinery_test.go — ССЫЛКА КОНТРАКТА НА СОСЕДНИЙ КОНТРАКТ
// ОБЯЗАНА РЕЗОЛВИТЬСЯ.
//
// # Предмет (kacho#2486)
//
// Комментарий `InternalSessionRevocationsService` отсылал за полосой выхода к
// `back_channel_logout_service.proto`. Файла в модуле нет ни одного; отсылка
// пережила свой предмет и продолжала читаться интегратором как адрес, по
// которому лежит описание механизма.
//
// Ссылка на файл дешевле любой другой лжи контракта ровно в одном: она
// проверяема одним обходом. Поэтому у неё есть гейт, а не обещание.
//
// # Что под ось НЕ подпадает, и это решение
//
// Ссылка С КАТАЛОГОМ (`kacho/cloud/validation.proto`) адресует контракт ЧУЖОГО
// репозитория — после выноса службы отдельным продуктом его файла здесь нет by
// construction. Предикат этого дерева о чужом дереве не высказывается: включив
// такие ссылки, гейт начал бы с двух ложных находок и потребовал бы ведомости
// прощений, то есть исключения, выданного вперёд. Замер на дереве службы:
// ссылок с каталогом — 2, обе законны.
//
// # Вторая ось живёт отдельно, и это тоже решение
//
// Заявление о ТАБЛИЦЕ и КАНАЛЕ судится по ЖИВОЙ схеме, а не по тексту
// миграций, — `internal/migrations/contract_names_live_machinery_integration_test.go`.
// Причина та же, по которой так устроен соседний гейт каналов: текстовый
// предикат считает производителем и то объявление, чей предмет снят более
// поздней миграцией.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `contract_names_live_machinery_injection_test.go`.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// contractCorpusDir — корень набора контрактов ОТНОСИТЕЛЬНО корня модуля.
const contractCorpusDir = "proto"

// TestContractNamesOnlyExistingSiblingContracts — ссылка на соседний контракт
// резолвится.
func TestContractNamesOnlyExistingSiblingContracts(t *testing.T) {
	t.Parallel()

	moduleRoot, err := platformtree.ModuleRootFrom(wdOf(t))
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: корень модуля не установлен: %v", err)
	}
	root := filepath.Join(moduleRoot, contractCorpusDir)

	sources, contracts := readContractCorpus(t, root)
	if len(sources) == 0 {
		t.Fatalf("обход пуст: под %s не прочитано ни одного контракта — «ноль находок» "+
			"здесь означало бы «ноль прочитанного»", root)
	}

	facts := check.MachineryFacts{Sources: sources, Contracts: contracts}
	found, census := check.AuditMachineryClaims(facts)

	// Заявления о схеме без фактов схемы не судятся: их предмет — живая база, и
	// отвечает за них интеграционный собрат. Здесь они отсеиваются, а не
	// объявляются находками.
	found = onlyKind(found, check.MachineryContract)

	t.Logf("перепись: контрактов прочитано %d · блоков комментария %d · ссылок на "+
		"соседний контракт %d · резолвится %d",
		census.Files, census.CommentBlocks,
		census.ByKind[check.MachineryContract],
		census.ByKind[check.MachineryContract]-len(found))

	if census.ByKind[check.MachineryContract] == 0 {
		t.Fatalf("ни одной ссылки на соседний контракт не распознано: предмета у гейта "+
			"нет, и его молчание неотличимо от молчания мёртвой проверки")
	}

	for _, c := range found {
		t.Errorf("%s:%d: комментарий отсылает к контракту %q, которого в модуле нет. "+
			"Исходов три: поправить имя · снять отсылку вместе с предметом · завести файл. "+
			"Интегратор перемерить не может — для него адрес, по которому ничего нет, "+
			"неотличим от адреса действующего описания", c.File, c.Line, c.Name)
	}
}

// onlyKind — находки одного вида.
func onlyKind(in []check.MachineryClaim, kind check.MachineryKind) []check.MachineryClaim {
	var out []check.MachineryClaim
	for _, c := range in {
		if c.Kind == kind {
			out = append(out, c)
		}
	}
	return out
}

// readContractCorpus — исходники набора и базовые имена его файлов.
func readContractCorpus(t *testing.T, root string) (map[string]string, map[string]struct{}) {
	t.Helper()
	sources := map[string]string{}
	names := map[string]struct{}{}

	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".proto") {
			return nil
		}
		body, rerr := os.ReadFile(path) // #nosec G304 -- обход собственного набора контрактов
		if rerr != nil {
			return rerr
		}
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			return rerr
		}
		sources[filepath.ToSlash(rel)] = string(body)
		names[d.Name()] = struct{}{}
		return nil
	})
	if err != nil {
		t.Fatalf("обход набора контрактов %s: %v — гейт не может назвать дерево, "+
			"о котором он говорит", root, err)
	}
	return sources, names
}

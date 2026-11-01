// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelcompose_test

// registry_create_note_test.go — примечание канона о `v_create` реестра и
// композиция с разделом потребителя (PRO-Robotech/kaname#953).
//
// Примечание `registry_registry` утверждало, что заведение репозитория
// спрашивает `v_create` реестра, — у всякого модуля. Это верно о модуле, который
// гейтит создание на контейнере, и неверно о модуле, заводящем репозиторий по
// `v_update` реестра. Блок канона неприкосновенен, поэтому потребитель не мог
// привести своё примечание к своему поведению: композиция отказывала.
//
// Три пробы, каждая меняет ровно один факт против соседней — прозу трёх строк
// примечания:
//
//	1  раздел потребителя с НОВОЙ прозой → композиция подтверждает оба типа;
//	2  законный близнец — раздел с ПРЕЖНЕЙ прозой (доставленный сегодня) →
//	   композиция подтверждает оба типа: переход идёт парой «канон + потребитель»;
//	3  третья проза → отказ о расхождении блоков: сверка по-прежнему кусается.

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// createNotePrior и createNoteNew — три строки примечания о `v_create` в
// прежней и новой прозе, без отступа: отступ у манифеста и у канона разный.
var (
	createNotePrior = []string{
		"# asked — by the control plane (CreateRepository / RenameRepository) and by the",
		"# data plane (docker push to a new repo, cross-repo mount into a new dst, and",
		"# the first-push blob-reveal guard). Every other type answered a question no",
	}
	createNoteNew = []string{
		"# asked — by modules that gate repository creation on the container (create and",
		"# rename, push to a new repo, cross-repo mount, first-push blob guard); a module",
		"# may ask `v_update` here instead. Every other type answered a question no",
	}
)

// registryDocWithNote — фикстура манифеста registry новой редакции с прозой
// примечания `note` на месте любой из двух известных. Предусловие: фикстура
// несёт ровно одну из них, каждую строку ровно один раз.
func registryDocWithNote(t *testing.T, note []string) string {
	t.Helper()
	raw, err := publicreadfixture.Read(publicreadfixture.NewEditionFile)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	doc := string(raw)
	for i := range createNotePrior {
		var from string
		switch {
		case strings.Count(doc, createNotePrior[i]) == 1:
			from = createNotePrior[i]
		case strings.Count(doc, createNoteNew[i]) == 1:
			from = createNoteNew[i]
		default:
			t.Fatalf("фикстура не несёт строки %d примечания о v_create ровно один раз ни в одной прозе — проба беспредметна", i+1)
		}
		doc = strings.Replace(doc, from, note[i], 1)
	}
	return doc
}

func composeRegistry(t *testing.T, doc string) (modelcompose.Report, error) {
	t.Helper()
	m, err := manifest.Load([]byte(doc))
	if err != nil {
		t.Fatalf("загрузчик отверг вход: %v", err)
	}
	_, rep, cerr := modelcompose.Compose(authzmodel.DSL, []*manifest.Manifest{m})
	t.Logf("перепись композиции: %s", rep.Census())
	return rep, cerr
}

func requireBothReaffirmed(t *testing.T, rep modelcompose.Report, cerr error, form string) {
	t.Helper()
	if cerr != nil {
		t.Fatalf("kaname#953: композиция отвергла раздел потребителя с %s прозой примечания: %v", form, cerr)
	}
	if len(rep.Reaffirmed) != 2 || len(rep.Composed) != 0 || len(rep.PriorEdition) != 0 {
		t.Fatalf("kaname#953: ожидалось подтверждение ровно двух типов registry, ноль добавленных и ноль "+
			"прежней редакции (%s проза): %s", form, rep.Census())
	}
}

// Проба 1: раздел потребителя с новой прозой подтверждается каноном.
func TestRegistryCreateNote_NewProseIsTheCanon(t *testing.T) {
	rep, cerr := composeRegistry(t, registryDocWithNote(t, createNoteNew))
	requireBothReaffirmed(t, rep, cerr, "новой")
	block := string(canonBlock(t, "registry_registry"))
	for _, l := range createNoteNew {
		if !strings.Contains(block, "    "+l+"\n") {
			t.Fatalf("kaname#953: канон registry_registry не несёт строки новой прозы %q", l)
		}
	}
}

// Проба 2: законный близнец — раздел, доставленный сегодня, с прежней прозой.
func TestRegistryCreateNote_PriorProseStillComposes(t *testing.T) {
	rep, cerr := composeRegistry(t, registryDocWithNote(t, createNotePrior))
	requireBothReaffirmed(t, rep, cerr, "прежней")
}

// Проба 3: третья проза — отказ о расхождении блоков.
func TestRegistryCreateNote_ThirdProseIsRefused(t *testing.T) {
	third := append([]string(nil), createNoteNew...)
	third[2] = "# may ask anything here instead. Every other type answered a question no"
	_, cerr := composeRegistry(t, registryDocWithNote(t, third))
	if cerr == nil || !strings.Contains(cerr.Error(), `тип "registry_registry" объявлен и каноном`) {
		t.Fatalf("kaname#953: третья проза примечания обязана получить отказ о расхождении блока registry_registry; got %v", cerr)
	}
}

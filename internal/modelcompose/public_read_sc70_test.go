// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package modelcompose_test

// public_read_sc70_test.go — выкатка S5: kaname новой версии стартует с прежним
// манифестом registry, затем с новым; третья форма — отказ (задача
// PRO-Robotech/kaname#856).
//
// Приёмка docs/engineering/acceptance/anonymous-and-authenticated-are-subject-classes.md,
// редакция 10, отпечаток 198db838d0a75b7f5b5bdbd5564bacec23a79cc00550a26e8830f3c6be61aac9:
// SC-70 (а), (б), (г) — сборка модели; (в) — отказ ЗАГРУЗКИ, он в пакете
// `internal/manifest` (`TestLoadDelivered_SC70_c_…`).
//
// Путь — тот же, что у старта (`cmd/kaname/model_compose.go`): каталог доставки
// читает `manifest.LoadDelivered`, модель собирает `modelcompose.Compose` над
// вшитым каноном `authzmodel.DSL`.
//
// # Порядок несущий
//
// Сначала фикстура: прежняя редакция и близнец новой редакции без ключа обязаны
// доставляться, а рендер прежней редакции — совпадать с байтами Р10. Потом
// предмет.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/authzmodel"
	"github.com/PRO-Robotech/kaname/internal/manifest"
	"github.com/PRO-Robotech/kaname/internal/modelcompose"
	"github.com/PRO-Robotech/kaname/internal/modelrender"
	"github.com/PRO-Robotech/kaname/internal/testsupport/publicreadfixture"
)

// Байты Р10 «прежняя редакция» (sha256 блоков канона @a7a726802).
var sc70PriorSHA = map[string]string{
	"registry_registry":   "b115c3c18f6ffdda0c22c1c742da50fbecd1a1f888d28810663429a97b240359",
	"registry_repository": "d2aafdbdba912a2680d636230bf6e046f7434b057ec77f3070968b35de7aaa69",
}

func sc70SHA(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// sc70Deliver — каталог доставки с одним манифестом registry.
func sc70Deliver(t *testing.T, doc []byte) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "registry")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("фикстура: каталог доставки: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "manifest.yaml"), doc, 0o600); err != nil {
		t.Fatalf("фикстура: манифест доставки: %v", err)
	}
	return root
}

// sc70Fixture — байты фикстуры.
func sc70Fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := publicreadfixture.Read(name)
	if err != nil {
		t.Fatalf("фикстура: %v", err)
	}
	return b
}

// sc70CanonBlock — блок канона образа по типу.
func sc70CanonBlock(t *testing.T, typ string) []byte {
	t.Helper()
	for _, b := range modelrender.SplitCanon([]byte(authzmodel.DSL)) {
		if b.Type == typ {
			return b.Body
		}
	}
	t.Fatalf("канон образа не объявляет %s", typ)
	return nil
}

// sc70ComposedBlock — блок собранной модели по типу.
func sc70ComposedBlock(t *testing.T, composed, typ string) []byte {
	t.Helper()
	for _, b := range modelrender.SplitCanon([]byte(composed)) {
		if b.Type == typ {
			return b.Body
		}
	}
	t.Fatalf("собранная модель не объявляет %s", typ)
	return nil
}

// sc70ControlPrior — положительный контроль фикстуры: прежняя редакция
// доставляется, её рендер равен байтам Р10.
func sc70ControlPrior(t *testing.T) []*manifest.Manifest {
	t.Helper()
	rep, err := manifest.LoadDelivered(sc70Deliver(t, sc70Fixture(t, publicreadfixture.PriorEditionFile)))
	if err != nil {
		t.Fatalf("фикстура: прежняя редакция обязана доставляться: %v", err)
	}
	for _, res := range rep.Manifests[0].Resources {
		blk, err := modelrender.Render(res)
		if err != nil {
			t.Fatalf("фикстура: рендер %s: %v", res.ObjectType, err)
		}
		if got := sc70SHA(blk); got != sc70PriorSHA[res.ObjectType] {
			t.Fatalf("фикстура: рендер %s прежней редакции %s, Р10 требует %s", res.ObjectType, got, sc70PriorSHA[res.ObjectType])
		}
	}
	return rep.Manifests
}

// sc70ControlKeyless — контроль: новая редакция без ключа доставляется (её
// отличие от предмета — один факт, ключ).
func sc70ControlKeyless(t *testing.T, doc []byte) {
	t.Helper()
	twin, err := publicreadfixture.WithoutKey(doc)
	if err != nil {
		t.Fatalf("фикстура: близнец без ключа: %v", err)
	}
	if _, err := manifest.LoadDelivered(sc70Deliver(t, twin)); err != nil {
		t.Fatalf("фикстура: новая редакция без ключа обязана доставляться: %v", err)
	}
}

// sc70DeliverSubject — предмет: документ С ключом доставляется. Отказ — ключа у
// загрузчика нет (предмета S5 нет).
func sc70DeliverSubject(t *testing.T, sc string, doc []byte) []*manifest.Manifest {
	t.Helper()
	rep, err := manifest.LoadDelivered(sc70Deliver(t, doc))
	if err != nil {
		t.Fatalf("%s: доставка документа с ключом %s отвергнута (предмета S5 нет): %v", sc, publicreadfixture.Key, err)
	}
	return rep.Manifests
}

// TestCompose_SC70_a_PriorEditionStartsAndTheCanonStaysActive — SC-70 (а):
// kaname новой версии стартует с манифестом прежней редакции; действует при
// этом КАНОН новой версии — прежняя редакция только допускается к сверке и в
// модель не попадает (Р10, «Что принимается»).
func TestCompose_SC70_a_PriorEditionStartsAndTheCanonStaysActive(t *testing.T) {
	prior := sc70ControlPrior(t)

	composed, rep, err := modelcompose.Compose(authzmodel.DSL, prior)
	if err != nil {
		t.Fatalf("SC-70 (а): старт с прежней редакцией обязан быть успешен, отказ: %v", err)
	}
	t.Logf("SC-70 (а): %s", rep.Census())
	for _, typ := range []string{"registry_registry", "registry_repository"} {
		if got, want := sc70ComposedBlock(t, composed, typ), sc70CanonBlock(t, typ); string(got) != string(want) {
			t.Fatalf("SC-70 (а): в собранной модели блок %s не равен канону новой версии — прежняя редакция попала в модель", typ)
		}
	}
	// Канон новой версии — это канон С публичным чтением (Р9 п. 1). Пока его
	// нет, «действует канон» неотличимо от «действует прежняя редакция».
	if !strings.Contains(string(sc70CanonBlock(t, "registry_registry")), "define public_reader: [system_class]") {
		t.Fatalf("SC-70 (а): канон новой версии не несёт `public_reader` у registry_registry (предмета S5 нет) — " +
			"прежняя редакция и канон сегодня совпадают, и приём прежней редакции здесь не испытан")
	}
}

// TestCompose_SC70_b_NewEditionIsReaffirmedByteForByte — SC-70 (б): старт с
// манифестом новой редакции успешен, блоки registry в переписи `Reaffirmed` —
// их рендер равен канону байт в байт.
func TestCompose_SC70_b_NewEditionIsReaffirmedByteForByte(t *testing.T) {
	sc70ControlPrior(t)
	doc := sc70Fixture(t, publicreadfixture.NewEditionFile)
	sc70ControlKeyless(t, doc)

	ms := sc70DeliverSubject(t, "SC-70 (б)", doc)
	_, rep, err := modelcompose.Compose(authzmodel.DSL, ms)
	if err != nil {
		t.Fatalf("SC-70 (б): старт с новой редакцией обязан быть успешен, отказ: %v", err)
	}
	for _, typ := range []string{"registry_registry", "registry_repository"} {
		found := false
		for _, r := range rep.Reaffirmed {
			found = found || r == typ
		}
		if !found {
			t.Fatalf("SC-70 (б): %s нет в переписи Reaffirmed (%s)", typ, rep.Census())
		}
	}
}

// TestCompose_SC70_d_ThirdFormPassingTheLoadIsRefusedAtCompose — SC-70 (г):
// манифест (б) с одним изменённым словом примечания `registries` загрузку
// проходит, а его блок не равен ни канону, ни прежней редакции — отказ пуска
// сегодняшним текстом расхождения. Близнец — (б): одно слово примечания.
func TestCompose_SC70_d_ThirdFormPassingTheLoadIsRefusedAtCompose(t *testing.T) {
	sc70ControlPrior(t)
	doc := sc70Fixture(t, publicreadfixture.NewEditionFile)
	sc70ControlKeyless(t, doc)
	third, err := publicreadfixture.OneWordInRegistriesNote(doc)
	if err != nil {
		t.Fatalf("фикстура: третья форма (г): %v", err)
	}

	if _, _, err := modelcompose.Compose(authzmodel.DSL, sc70DeliverSubject(t, "SC-70 (г) близнец (б)", doc)); err != nil {
		t.Fatalf("SC-70 (г) близнец (б): новая редакция обязана собираться, отказ: %v", err)
	}
	ms := sc70DeliverSubject(t, "SC-70 (г)", third)
	// Два вида одного блока: прежнюю редакцию судят по рендеру как есть (её
	// закрепление снято с прежней прозы), а длину в тексте отказа называет та
	// форма, которую сборщик сверяет с каноном, — после перевода прозы
	// примечаний (`RenderForCanon`; в блоке реестра его строки есть с kaname#953).
	var raw, blk []byte
	for _, res := range ms[0].Resources {
		if res.ObjectType == "registry_registry" {
			if raw, err = modelrender.Render(res); err != nil {
				t.Fatalf("SC-70 (г): рендер registry_registry: %v", err)
			}
			if blk, err = modelrender.RenderForCanon(res); err != nil {
				t.Fatalf("SC-70 (г): рендер registry_registry для сверки с каноном: %v", err)
			}
		}
	}
	if sc70SHA(raw) == sc70PriorSHA["registry_registry"] {
		t.Fatalf("фикстура: третья форма (г) рендерит прежнюю редакцию — она не третья")
	}
	_, _, err = modelcompose.Compose(authzmodel.DSL, ms)
	want := fmt.Sprintf("modelcompose: тип %q объявлен и каноном, и модулем %q, а их блоки расходятся побайтово "+
		"(канон %d Б, рендер %d Б) — канон неприкосновенен, и расхождение обязано быть решено, а не сглажено",
		"registry_registry", "registry", len(sc70CanonBlock(t, "registry_registry")), len(blk))
	if err == nil || err.Error() != want {
		t.Fatalf("SC-70 (г): отказ пуска обязан быть дословно\n%s\nполучено: %v", want, err)
	}
}

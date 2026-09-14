// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// published_key_private_half_test.go — публикуемая форма подписного ключа не
// имеет поля для приватной половины (приёмка F1, сценарий F1-05).
//
// Устройство разбора, словарь слов и НАЗВАННЫЙ РАДИУС — в годке
// `published_key_private_half.go`; здесь они не пересказываются.
//
// Способность гейта упасть и смолчать доказана инъекцией —
// `published_key_private_half_injection_test.go`.
//
// # Предмет
//
// Приватный материал не покидает процесс — ни журналом, ни текстом ошибки, ни
// метрикой, ни ответом. Из всех этих носителей ОТВЕТ отличается тем, что его
// содержимое задаётся ТИПОМ, а тип проверяет компилятор. Значит требование
// выражается формой, а не вниманием: у публикуемого типа поля приватной
// половины нет, и положить её туда НЕ ВЫРАЖАЕТСЯ.
//
// Форма «поле есть, но на этом пути мы его не заполняем» отвергнута осознанно:
// она возлагает свойство на каждого будущего вызывающего сразу — заполнить поле
// законно, компилятор не возразит, а проба заметит это лишь там, где кто-то
// догадался сравнить ответ побайтово.
//
// # Почему у гейта ОБЯЗАН быть положительный близнец
//
// Предмет этого гейта — ОТСУТСТВИЕ. Проверка отсутствия молчит одинаково в двух
// разных случаях: предмет исчез (хорошо) и сломалась сама проверка (плохо).
// Различить их нечем, пока рядом нет места, которое гейт ОБЯЗАН находить.
//
// Близнец здесь не приписан списком, а получается из самого разбора: пара
// «хранимая форма → публикуемая» опознаётся по тому, что ПРИЁМНИК проекции
// несёт приватное поле. Сломается разбор — пропадут и пары, и гейт скажет об
// этом прямо, вместо того чтобы молча зазеленеть.
package check_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/PRO-Robotech/kaname/internal/check"
	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// keyProjectionCensusFloor — сколько не-тестовых файлов Go гейт обязан
// разобрать, чтобы его молчание вообще что-то значило.
//
// Порог занижен на порядок относительно дерева НАМЕРЕННО: он ловит обвал
// переписи (пустой индекс, чужой каталог, обрезанный обход), а не рост или
// усадку дерева.
const keyProjectionCensusFloor = 500

// keyProjectionWalkable — что гейт осматривает. Вынесено функцией: инъекция
// обязана проверять ТОТ ЖЕ отбор, которым судит гейт.
func keyProjectionWalkable(rel string) bool {
	return strings.HasSuffix(rel, ".go") &&
		!strings.HasSuffix(rel, "_test.go") &&
		!strings.HasSuffix(rel, ".pb.go")
}

// keyProjectionFindings — находки по разобранным парам. Тот же предикат зовёт
// инъекция.
//
// Находок ДВЕ разновидности, и обе несущие: приватное поле в публикуемой форме
// и публикуемая форма, не отделённая от хранимой (проекция в себя же).
func keyProjectionFindings(ps []check.KeyProjection) []string {
	var out []string
	for _, p := range ps {
		if p.SameType {
			out = append(out, fmt.Sprintf(
				"%s:%d  %s.%s() возвращает ТОТ ЖЕ тип %s — публикуемая форма не отделена "+
					"от хранимой, и приватная половина уезжает вместе с ней",
				p.File, p.Line, p.StoredType, p.Method, p.PublishedType))
			continue
		}
		for _, f := range p.PrivateInPublished {
			out = append(out, fmt.Sprintf(
				"%s:%d  публикуемая форма %s несёт приватное поле %s %s (проекция %s.%s)",
				p.File, f.Line, p.PublishedType, f.Name, f.Type, p.StoredType, p.Method))
		}
	}
	sort.Strings(out)
	return out
}

// TestPublishedKeyFormCarriesNoPrivateHalf — сам гейт.
func TestPublishedKeyFormCarriesNoPrivateHalf(t *testing.T) {
	t.Parallel()

	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}

	files, err := treecorpus.UnderWithSuffix(ownDir, ".go")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: состав дерева не прочитан: %v", err)
	}

	var parsed, types, fields int
	var projections []check.KeyProjection
	for _, abs := range files {
		rel, rerr := filepath.Rel(corpusRoot, abs)
		if rerr != nil {
			t.Fatalf("относительный путь для %s: %v", abs, rerr)
		}
		rel = filepath.ToSlash(rel)
		if !keyProjectionWalkable(rel) {
			continue
		}
		src, rderr := os.ReadFile(abs) // #nosec G304 -- путь взят индексом git, не вводом снаружи
		if rderr != nil {
			// Файл индекса, которого нет на диске, в перепись не идёт: он не
			// находка и не тишина, он просто не прочитан.
			continue
		}
		ps, census, serr := check.ScanKeyProjections(rel, src)
		if serr != nil {
			t.Fatalf("разбор %s не удался (%v) — гейт не вправе трактовать неразобранный "+
				"файл как «пар не найдено»", rel, serr)
		}
		parsed++
		types += census.TypesInspected
		fields += census.FieldsInspected
		projections = append(projections, ps...)
	}

	t.Logf("перепись: не-тестовых файлов Go разобрано %d, структурных типов осмотрено %d, "+
		"полей прочитано %d, пар «хранимая → публикуемая» найдено %d",
		parsed, types, fields, len(projections))
	for _, p := range projections {
		t.Logf("  пара: %s:%d  %s.%s() → %s (приватное в хранимой: %d, в публикуемой: %d)",
			p.File, p.Line, p.StoredType, p.Method, p.PublishedType,
			len(p.StoredPrivate), len(p.PrivateInPublished))
	}

	if parsed < keyProjectionCensusFloor {
		t.Fatalf("перепись обвалилась: разобрано %d файлов при пороге %d — на таком объёме "+
			"«ноль находок» означало бы «ноль прочитанного»", parsed, keyProjectionCensusFloor)
	}
	if types == 0 || fields == 0 {
		t.Fatalf("структурных типов осмотрено %d, полей %d на %d файлах — разбор перестал "+
			"видеть предмет, и его молчание сказано ни о чём", types, fields, parsed)
	}

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: предмет этого гейта — отсутствие, поэтому молчание
	// доказывает что-либо ТОЛЬКО рядом с парой, которую разбор обязан находить.
	if len(projections) == 0 {
		t.Fatalf("не найдено НИ ОДНОЙ пары «хранимая форма → публикуемая» на %d файлах.\n"+
			"Предмет гейта — ОТСУТСТВИЕ приватного поля в публикуемой форме, и его "+
			"молчание неотличимо от поломки самого разбора, пока рядом нет места, которое "+
			"разбор обязан находить.\nЛибо пара ушла из дерева (тогда гейт снимается вместе "+
			"с предметом), либо сломался разбор (тогда чинится он)", parsed)
	}

	for _, f := range keyProjectionFindings(projections) {
		t.Errorf("%s.\nПриватная половина покидает процесс ОТВЕТОМ, а содержимое ответа "+
			"задаётся типом — значит требование выражается формой, а не вниманием. "+
			"Исход один: снять поле с публикуемого типа, чтобы положить его туда НЕ "+
			"ВЫРАЖАЛОСЬ", f)
	}
}

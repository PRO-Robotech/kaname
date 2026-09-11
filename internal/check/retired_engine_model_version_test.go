// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// retired_engine_model_version_test.go — таблица версии модели, загруженной
// во ВНЕШНИЙ движок прав, не живёт в схеме kaname (задача продукта #1717).
//
// Порт с монорепо (`internal/repohygiene/retiredenginemodelversion_test.go`,
// снят вынесением службы — `kacho#2597`). Изменилось СУЩЕСТВЕННО: там
// проверка была ЧАСТНЫМ СЛУЧАЕМ общего гейта роста таблиц
// (`tablegrowth.go`/`tablegrowth_test.go`, обходившего миграции ВСЕХ шести
// оставшихся служб платформы; таблица различалась ПАРОЙ «владелец+имя»,
// потому что одно имя носят таблицы разных служб). Тот общий механизм НЕ
// иам-специфичен, живёт в монорепо и не переносится этим изменением.
//
// Здесь — самостоятельный, узкий разбор ТОЙ ЖЕ формы (CREATE/DROP TABLE в
// порядке применения goose), но только для ОДНОГО предмета и ОДНОГО дерева:
// собственных миграций kaname. Диспамбигуация «владелец+имя» больше не
// нужна: служба здесь ровно одна, второй владелец этого имени не появится
// by construction.
//
// # Почему это НЕ ослабление, а сужение по факту
//
// Собственный ledger-успешник этого семейства прямо предупреждает: «гейт
// обходит миграции ВСЕГО дерева ... После выноса службы её миграций в
// дереве [монорепо] нет, вход, на котором он находит нарушение, стал
// непредставим ... вернуть снятый объект молча можно теперь только в
// дереве службы, и судить это обязано ОНО». Это ровно то, что делает этот
// файл: единственное место, способное заметить регресс, — kaname сам.
//
// # Предмет (дословно из монорепо)
//
// Внешний движок отношений снят линией R7-3: вердикт вычисляет реляционная
// форма в собственной базе службы. Таблица `fga_model_version` хранила
// идентификатор модели, ЗАГРУЖЕННОЙ в этот движок, и версию её языка.
// Загружать стало некуда, писателя у строки не осталось ни одного, а форма
// таблицы читается как действующее версионирование модели прав.
//
// # Почему проверка именная, а не по имени движка (дословно из монорепо)
//
// Имя движка в схеме остаётся законно во множестве мест (`fga_outbox` и
// т.п.). Проверка по имени движка краснела бы на исправном дереве.
package check_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho/pkg/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// retiredEngineModelVersionTable — единственный предмет проверки, без
// приставки схемы: разбор снимает `kaname.`/др. приставку сам.
const retiredEngineModelVersionTable = "fga_model_version"

var (
	engineVersionCreateRe = regexp.MustCompile(
		`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:[a-z_]+\.)?(` + retiredEngineModelVersionTable + `)\b`)
	engineVersionDropRe = regexp.MustCompile(
		`(?i)DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?(?:[a-z_]+\.)?(` + retiredEngineModelVersionTable + `)\b`)
	engineVersionLineCommentRe = regexp.MustCompile(`--.*`)
)

// stripEngineVersionLineComment — снимает `--`-комментарий одной строки SQL.
//
// Без него гейт краснеет на ОБЪЯСНЕНИИ собственного запрета: строка
// «-- было бы неверно снова заводить CREATE TABLE fga_model_version»
// синтаксически содержит ту же подпоследовательность, что и настоящий
// оператор, и распознаватель по подстроке не отличил бы прозу от кода
// (`testing.md` §«Гейт читает исполняемую часть, а не текст»).
func stripEngineVersionLineComment(line string) string {
	return engineVersionLineCommentRe.ReplaceAllString(line, "")
}

// retiredEngineVersionSite — координата находки.
type retiredEngineVersionSite struct {
	File string
	Line int
}

// retiredEngineVersionCensus — объём осмотренного.
type retiredEngineVersionCensus struct {
	MigrationFiles int
	Creates        int
	Drops          int
}

// TestRetiredEngineModelVersionTableIsGone — сама проверка.
func TestRetiredEngineModelVersionTableIsGone(t *testing.T) {
	corpusRoot, modulePrefix := platformtree.RequireCorpus(t)
	ownDir := corpusRoot
	if modulePrefix != "" {
		ownDir = filepath.Join(corpusRoot, filepath.FromSlash(modulePrefix))
	}

	sqlFiles, err := treecorpus.UnderWithSuffix(filepath.Join(ownDir, "internal", "migrations"), ".sql")
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: перечень миграций не прочитан: %v", err)
	}
	sort.Strings(sqlFiles) // порядок применения goose = лексикографический порядок имён

	var (
		alive  *retiredEngineVersionSite
		global retiredEngineVersionCensus
	)

	for _, abs := range sqlFiles {
		raw, rerr := os.ReadFile(abs)
		if rerr != nil {
			t.Fatalf("чтение %s: %v", abs, rerr)
		}
		global.MigrationFiles++
		src := string(raw)
		if !strings.Contains(src, "-- +goose Up") {
			continue
		}
		lines := strings.Split(src, "\n")
		for i, raw := range lines {
			line := stripEngineVersionLineComment(raw)
			if engineVersionCreateRe.MatchString(line) {
				global.Creates++
				rel, _ := filepath.Rel(ownDir, abs)
				s := retiredEngineVersionSite{File: filepath.ToSlash(rel), Line: i + 1}
				alive = &s
			}
			if engineVersionDropRe.MatchString(line) {
				global.Drops++
				alive = nil
			}
		}
	}

	t.Logf("перепись обхода: миграций прочитано %d, операторов создания таблицы %s %d, "+
		"снятия %d; таблица сейчас %s",
		global.MigrationFiles, retiredEngineModelVersionTable, global.Creates, global.Drops,
		map[bool]string{true: "ЖИВА", false: "снята/не заводилась"}[alive != nil])

	// Порог, а не «не ноль»: обвал корпуса миграций до одной-двух — тот же
	// беспредметный обход, что и полный ноль, только менее заметный.
	const migrationCensusFloor = 5
	if global.MigrationFiles < migrationCensusFloor {
		t.Fatalf("прочитано миграций %d при пороге %d — обход беспредметен, и «таблицы нет» "+
			"здесь означало бы «почти ничего не прочитано»", global.MigrationFiles, migrationCensusFloor)
	}
	// Creates/Drops здесь легитимно МОГУТ быть нулём: сама таблица была снята
	// ДО сведения первичной миграции в один файл (`pg_dump`-свод несёт только
	// живое состояние), поэтому ни одного `DROP TABLE fga_model_version` в
	// дереве kaname уже нет — и это не слепота разбора, а факт истории. Что
	// разбор способен увидеть CREATE и DROP этой формы, когда они есть,
	// доказывает инъекция (`retired_engine_model_version_injection_test.go`),
	// а не эта проба: подделывать историю ради лишнего утверждения здесь
	// не нужно.

	if alive != nil {
		t.Errorf("%s:%d — живая таблица версии модели, загружаемой во ВНЕШНИЙ движок прав, "+
			"который снят линией R7-3. Загружать некуда: писателя у строки нет ни одного, "+
			"а форма таблицы читается как действующее версионирование модели. Снимите её "+
			"новой миграцией (применённые не правятся, ban #5)",
			alive.File, alive.Line)
	}
}

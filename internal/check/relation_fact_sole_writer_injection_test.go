// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// relation_fact_sole_writer_injection_test.go — доказательство способности
// гейта упасть И смолчать.
//
// Инъекция герметична: дефект подаётся синтетическим исходником прямо в разбор,
// поэтому роняет ТОЛЬКО проверяемое и не может задеть соседние гейты — они
// судят дерево, а дерево не тронуто.
//
// Оси — по одной на каждую названную форму записи плюс границы, на которых гейт
// обязан МОЛЧАТЬ. Форма, о которой разбор не знает, не даёт ни красного, ни
// зелёного: она молчит, и это молчание неотличимо от «записей нет».
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// factScan — разбор одного синтетического файла ТЕМ ЖЕ средством, которым судит
// гейт, с проверкой непустоты переписи.
func factScan(t *testing.T, rel, src string) ([]check.FactWriteSite, check.FactScanCensus) {
	t.Helper()
	sites, census, err := check.ScanFactWrites(rel, []byte(src), check.FactTable, check.FactMutationVerbs)
	if err != nil {
		t.Fatalf("разбор инъекции %s: %v", rel, err)
	}
	if census.Strings == 0 && census.Comments == 0 {
		t.Fatalf("перепись инъекции пуста — разбор ничего не прочитал, и его молчание "+
			"сказано ни о чём: %+v", census)
	}
	return sites, census
}

// TestFactWriterGateRedsOnEveryWriteForm — КРАСНОЕ по каждой названной форме.
func TestFactWriterGateRedsOnEveryWriteForm(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		verb string
		src  string
	}{
		{
			name: "INSERT одной строкой",
			verb: "INSERT INTO",
			src: `package pg
const q = "INSERT INTO kaname.relation_fact (subject, object) VALUES ($1, $2)"
`,
		},
		{
			name: "insert нижним регистром",
			verb: "INSERT INTO",
			src: `package pg
const q = "insert into kaname.relation_fact (subject) values ($1)"
`,
		},
		{
			name: "INSERT переносом и отступом",
			verb: "INSERT INTO",
			src: `package pg
const q = "INSERT INTO\n\t\tkaname.relation_fact (subject)\n\t\tVALUES ($1)"
`,
		},
		{
			name: "UPDATE",
			verb: "UPDATE",
			src: `package pg
const q = "UPDATE kaname.relation_fact SET object = $1 WHERE subject = $2"
`,
		},
		{
			name: "DELETE FROM",
			verb: "DELETE FROM",
			src: `package pg
const q = "DELETE FROM kaname.relation_fact WHERE subject = $1"
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			const rel = "internal/repo/kaname/pg/fact_writer.go"
			sites, census := factScan(t, rel, tc.src)
			if census.TableInStrings == 0 {
				t.Fatalf("форма ВНЕ наблюдения: литерал с таблицей не прочитан (%+v) — "+
					"такая запись не даёт ни красного, ни зелёного, она молчит", census)
			}
			if len(sites) != 1 {
				t.Fatalf("форма %q НЕ стала находкой: записей %d при переписи %+v",
					tc.name, len(sites), census)
			}
			if sites[0].Verb != tc.verb {
				t.Errorf("глагол опознан как %q, ожидался %q", sites[0].Verb, tc.verb)
			}
			f := factFindings(sites)
			if len(f) != 1 || !strings.Contains(f[0], rel) {
				t.Errorf("находка не называет координату: %v", f)
			}
		})
	}
}

// TestFactWriterGateStaysSilentOnLegalTwins — ЗАКОННЫЕ БЛИЗНЕЦЫ, по одному на
// каждый способ ошибиться.
func TestFactWriterGateStaysSilentOnLegalTwins(t *testing.T) {
	t.Parallel()

	// Эта ось и есть причина переноса на узлы разбора: в дереве ДВА прод-файла
	// объясняют комментарием, что таблицу пишет триггер. Подстрочный разбор дал
	// бы находку на объяснении инварианта.
	t.Run("та же запись в КОММЕНТАРИИ", func(t *testing.T) {
		const src = `package pg

// Строку факта складывает триггер: INSERT INTO kaname.relation_fact делает
// relation_fact_follows_journal, а не этот код.
func read() string { return "SELECT 1" }
`
		sites, census := factScan(t, "internal/repo/kaname/pg/module_seed_writer.go", src)
		if census.TableInComments == 0 {
			t.Fatalf("комментарий с таблицей не прочитан — положительный контроль не "+
				"выполнен, и молчание ниже сказано ни о чём: %+v", census)
		}
		if len(sites) != 0 {
			t.Fatalf("гейт краснеет на ОБЪЯСНЕНИИ инварианта — он судит подстроку, а не "+
				"узел разбора: %v", factFindings(sites))
		}
	})

	t.Run("чтение SELECT законно", func(t *testing.T) {
		const src = `package pg
const q = "SELECT subject, object FROM kaname.relation_fact WHERE subject = $1"
`
		sites, census := factScan(t, "internal/repo/kaname/pg/relverdict/query.go", src)
		if census.TableInStrings == 0 {
			t.Fatalf("литерал с таблицей не прочитан — контроль не выполнен: %+v", census)
		}
		if len(sites) != 0 {
			t.Fatalf("чтение объявлено записью: %v", factFindings(sites))
		}
	})

	t.Run("запись в ДРУГУЮ таблицу", func(t *testing.T) {
		const src = `package pg
const q = "INSERT INTO kaname.fga_outbox (subject, object) VALUES ($1, $2)"
`
		sites, _ := factScan(t, "internal/repo/kaname/pg/fga_outbox/emitter.go", src)
		if len(sites) != 0 {
			t.Fatalf("запись в журнал намерений объявлена записью в факт — журнал и есть "+
				"законный производитель: %v", factFindings(sites))
		}
	})

	t.Run("имя таблицы как часть более длинного", func(t *testing.T) {
		const src = `package pg
const q = "INSERT INTO kaname.relation_fact_archive (subject) VALUES ($1)"
`
		sites, _ := factScan(t, "internal/repo/kaname/pg/archive.go", src)
		if len(sites) != 0 {
			t.Fatalf("запись в СОСЕДНЮЮ таблицу объявлена записью в факт — совпадение "+
				"идёт не по границе имени: %v", factFindings(sites))
		}
	})
}

// TestFactWriterGateSelection — отбор берёт прод-код и не берёт пробы и
// сгенерированное. Проверяется ТОТ ЖЕ предикат, которым судит гейт.
func TestFactWriterGateSelection(t *testing.T) {
	t.Parallel()
	if !factWalkable("internal/repo/kaname/pg/relverdict/query.go") {
		t.Errorf("отбор не берёт прод-файл — осматривать нечего")
	}
	if factWalkable("internal/repo/kaname/pg/relverdict/query_test.go") {
		t.Errorf("отбор берёт пробу — подготовка состояния в пробе стала бы находкой")
	}
	if factWalkable("pkg/api/kaname/iam/v1/service.pb.go") {
		t.Errorf("отбор берёт сгенерированное")
	}
}

// TestFactWriterScanRefusesAnUnparsableFile — неразобранный файл НЕ трактуется
// как «записей нет»: это третья категория, и вызывающий обязан её увидеть.
func TestFactWriterScanRefusesAnUnparsableFile(t *testing.T) {
	t.Parallel()
	_, _, err := check.ScanFactWrites("internal/broken.go", []byte("package \x00 {{{"),
		check.FactTable, check.FactMutationVerbs)
	if err == nil {
		t.Fatalf("разбор неразобранного файла вернул успех — молчание такого файла " +
			"неотличимо от «записей нет»")
	}
}

// TestFactWriterBlindSpotIsNamed — НАЗВАННАЯ слепая зона: динамически собранное
// имя таблицы разбору не видно, и молчание на нём доказательством не является.
//
// Утверждение стоит здесь намеренно: граница, записанная только прозой, при
// следующей правке читается как «проверено».
func TestFactWriterBlindSpotIsNamed(t *testing.T) {
	t.Parallel()
	const src = `package pg

import "fmt"

const schema = "kaname"

func write() string { return fmt.Sprintf("INSERT INTO %s.relation_fact (subject) VALUES ($1)", schema) }
`
	sites, census := factScan(t, "internal/repo/kaname/pg/dynamic.go", src)
	if len(sites) != 0 {
		t.Fatalf("разбор внезапно ВИДИТ собранное имя — граница в годке названа неверно "+
			"и обязана быть переписана: %v", factFindings(sites))
	}
	if census.Strings == 0 {
		t.Fatalf("литералы не прочитаны — утверждение о слепой зоне сказано ни о чём: %+v",
			census)
	}
	t.Logf("слепая зона подтверждена: собранное имя таблицы не ловится образцом "+
		"(литералов прочитано %d, записей найдено 0) — молчание гейта на такой форме "+
		"доказательством НЕ является", census.Strings)
}

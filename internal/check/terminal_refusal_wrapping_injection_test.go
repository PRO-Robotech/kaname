// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// terminal_refusal_wrapping_injection_test.go — KN-RTX-07: доказательство, что
// гейты KN-RTX-06 и KN-RTX-08 СПОСОБНЫ упасть, и падают на существе, а не на
// форме записи.
//
// Инъекция идёт в ОБЕ стороны по каждой оси: дефект находится С КООРДИНАТОЙ,
// законный близнец молчит. Без второй половины гейт ловил бы форму, и первый же
// ложный срабат его отключил бы.
package check_test

import (
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// ── KN-RTX-07, ось 1: сырой репозиторий в use-case ──────────────────────────

func TestTerminalRefusalGateCatchesARawRepo(t *testing.T) {
	t.Parallel()
	root := synthAuditTree(t, map[string]string{
		"internal/thing/wiring.go": `package thing

func wire(pool *Pool) {
	opsRepo := operations.NewRepo(pool, "kaname")
	_ = opsRepo
}
`,
	})
	sites, census, err := check.ScanRawOperationsRepo(root)
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if census.Read == 0 {
		t.Fatal("синтетическое дерево не прочитано")
	}
	if census.Ctors != 1 {
		t.Fatalf("вызовов конструктора найдено %d, ожидался 1\n%s", census.Ctors, census)
	}
	if len(sites) != 1 || sites[0].Wrapped {
		t.Fatalf("сырой репозиторий НЕ опознан находкой: %v", sites)
	}
	if !strings.Contains(sites[0].Where, "internal/thing/wiring.go:4") {
		t.Fatalf("находка названа координатой %q, ожидалась wiring.go:4", sites[0].Where)
	}
}

// Законный близнец ОДНО-ФАКТНЫЙ: тот же вызов, обёрнутый надстройкой. Меняется
// ровно один факт против дефекта выше.
func TestTerminalRefusalGateIsSilentOnTheWrappedRepo(t *testing.T) {
	t.Parallel()
	root := synthAuditTree(t, map[string]string{
		"internal/thing/wiring.go": `package thing

func wire(pool *Pool) {
	opsRepo := shared.NewTerminalRefusalRepo(operations.NewRepo(pool, "kaname"))
	_ = opsRepo
}
`,
	})
	sites, census, err := check.ScanRawOperationsRepo(root)
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if census.Ctors != 1 {
		t.Fatalf("вызовов конструктора найдено %d, ожидался 1 — молчание означает "+
			"«не заглянул», а не «чисто»\n%s", census.Ctors, census)
	}
	if len(sites) != 1 || !sites[0].Wrapped {
		t.Fatalf("обёрнутый репозиторий объявлен находкой: %v", sites)
	}
}

// ── Ось 2: УПОМИНАНИЕ имени вызовом не является ─────────────────────────────
//
// Ось несущая: без неё гейт судил бы по подстроке и краснел бы на собственном
// объяснении соседнего файла. В этом дереве имя конструктора встречается в
// комментариях четыре раза при ОДНОМ настоящем вызове.

func TestTerminalRefusalGateDoesNotMistakeAMentionForACall(t *testing.T) {
	t.Parallel()
	root := synthAuditTree(t, map[string]string{
		"internal/thing/prose.go": `package thing

// Здесь объясняется, почему operations.NewRepo оборачивают надстройкой, и само
// это объяснение вызовом не является.
func nothing() {}
`,
	})
	sites, census, err := check.ScanRawOperationsRepo(root)
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if census.Ctors != 0 || len(sites) != 0 {
		t.Fatalf("упоминание в комментарии принято за вызов: %v\n%s", sites, census)
	}
	if census.Mentions == 0 {
		t.Fatalf("упоминание НЕ посчитано — разрыв между «сколько раз имя встречается» "+
			"и «сколько это вызовов» остался бы неназванным\n%s", census)
	}
}

// ── Ось 3: чужой конструктор с тем же именем ────────────────────────────────
//
// `NewRepo` — имя частое. Без сверки пакета гейт считал бы чужие конструкторы и
// требовал бы оборачивать репозиторий ролей.

func TestTerminalRefusalGateIsSilentOnAnotherPackagesNewRepo(t *testing.T) {
	t.Parallel()
	root := synthAuditTree(t, map[string]string{
		"internal/thing/other.go": `package thing

func wire(pool *Pool) {
	roles := roles.NewRepo(pool, "kaname")
	_ = roles
}
`,
	})
	sites, census, err := check.ScanRawOperationsRepo(root)
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if census.Ctors != 0 || len(sites) != 0 {
		t.Fatalf("чужой конструктор принят за свой: %v", sites)
	}
}

// ── KN-RTX-07, ось 4: второе объявление текста ──────────────────────────────
//
// Приставка имён — `TestRefusalTextDeclarationGate…`, а не `TestRefusalTextGate…`:
// вторая уже занята СОСЕДНИМ семейством о другом предмете
// (`refusal_text_is_fixed_injection_test.go` — фиксированный текст отказа без
// утечки). Общая приставка смешала бы два семейства в одном `-run`, и читатель,
// отбирающий по ней, получал бы вперемешку два разных предмета.

func TestRefusalTextDeclarationGateCatchesASecondDeclaration(t *testing.T) {
	t.Parallel()
	const text = "conflicting concurrent change, retry the request"
	root := synthAuditTree(t, map[string]string{
		"internal/errors/errors.go": "package errors\n\nconst SyncText = " + strconv.Quote(text) + "\n",
		"internal/thing/copy.go":    "package thing\n\nconst sneaky = " + strconv.Quote(text) + "\n",
	})
	found, census, err := check.ScanRefusalTextLiterals(root, []string{text})
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if census.Read == 0 {
		t.Fatal("синтетическое дерево не прочитано")
	}
	if len(found[text]) != 2 {
		t.Fatalf("объявлений найдено %d, ожидалось 2 — вторая копия не опознана: %v",
			len(found[text]), found[text])
	}
}

// Законный близнец: объявление ОДНО. Один факт против оси выше.
func TestRefusalTextDeclarationGateIsSilentOnASingleDeclaration(t *testing.T) {
	t.Parallel()
	const text = "conflicting concurrent change, retry the request"
	root := synthAuditTree(t, map[string]string{
		"internal/errors/errors.go": "package errors\n\nconst SyncText = " + strconv.Quote(text) + "\n",
		"internal/thing/user.go":    "package thing\n\nfunc f() string { return errors.SyncText }\n",
	})
	found, census, err := check.ScanRefusalTextLiterals(root, []string{text})
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if census.Read == 0 {
		t.Fatal("синтетическое дерево не прочитано")
	}
	if len(found[text]) != 1 {
		t.Fatalf("объявлений найдено %d, ожидалось 1 — потребитель по ИМЕНИ копией не "+
			"является: %v", len(found[text]), found[text])
	}
}

// ── Ось 5: СКЛЕЙКА — вторая законная форма записи того же текста ────────────
//
// Ось заведена не из осторожности, а по факту: собственное объявление этих
// текстов написано склейкой по ширине строки, и гейт на первом прогоне сказал
// «не объявлен НИ РАЗУ» о константе, лежащей рядом. Форма, о которой разбор не
// знает, не даёт ни красного, ни зелёного — она молчит.

func TestRefusalTextDeclarationGateFoldsAConcatenatedDeclaration(t *testing.T) {
	t.Parallel()
	const text = "conflicting concurrent change, the operation was not applied"
	root := synthAuditTree(t, map[string]string{
		"internal/errors/errors.go": "package errors\n\nconst T = \"conflicting concurrent change, \" +\n\t\"the operation was not applied\"\n",
	})
	found, _, err := check.ScanRefusalTextLiterals(root, []string{text})
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if len(found[text]) != 1 {
		t.Fatalf("склеенное объявление опознано %d раз(а), ожидалось 1 — либо форма не "+
			"свёрнута, либо её половины засчитаны отдельно: %v", len(found[text]), found[text])
	}
}

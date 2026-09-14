// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// guard_named_in_comment_injection_test.go — доказательство способности гейта
// упасть И смолчать.
//
// # Почему инъекция ГЕРМЕТИЧНА
//
// Дефект подаётся СИНТЕТИЧЕСКИМ исходником прямо в разбор, а не вносится в
// дерево. Отсюда свойство, которого правка дерева не даёт: инъекция роняет
// ТОЛЬКО проверяемое и не может задеть ни один соседний гейт by construction —
// соседи судят дерево, а дерево не тронуто. Третий прогон требования («соседние
// молчат на том же входе») обеспечен построением, и подтверждается прогоном
// всего пакета `internal/check` целиком.
//
// # Оси инъекции — по одной на форму записи, плюс границы
//
// Форма, о которой распознаватель не знает, даёт не красное и не зелёное, а
// молчание. Поэтому утверждение стоит по КАЖДОЙ из четырёх форм упоминания и по
// каждой из четырёх форм наличия, а не по одной «типичной».
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// guardInjectionNames — реестр инъекции. Берутся имена ДЕЙСТВУЮЩЕГО реестра:
// инъекция обязана идти тем же входом, которым судит гейт.
func guardInjectionNames() []string { return guardNames() }

// guardScanOne — разбор одного синтетического файла тем же средством, которым
// судит гейт.
func guardScanOne(t *testing.T, rel, src string, isTest bool) check.GuardFileScan {
	t.Helper()
	scan, err := check.ScanGuardNaming(rel, []byte(src), isTest, guardInjectionNames())
	if err != nil {
		t.Fatalf("разбор инъекции %s: %v", rel, err)
	}
	if scan.Census.Comments == 0 && scan.Census.Idents == 0 {
		t.Fatalf("перепись инъекции пуста — разбор ничего не прочитал, и его молчание "+
			"сказано ни о чём: %+v", scan.Census)
	}
	return scan
}

// guardVerdict — находки по одному файлу, сведённые тем же предикатом, что у
// гейта. Отбор переписан быть не может: зовётся guardFindings.
func guardVerdict(pkg string, scan check.GuardFileScan) []string {
	mentions := map[string]map[string][]check.GuardMention{}
	uses := map[string]map[string]bool{}
	for _, m := range scan.Mentions {
		if mentions[pkg] == nil {
			mentions[pkg] = map[string][]check.GuardMention{}
		}
		mentions[pkg][m.Name] = append(mentions[pkg][m.Name], m)
	}
	for name := range scan.Uses {
		if uses[pkg] == nil {
			uses[pkg] = map[string]bool{}
		}
		uses[pkg][name] = true
	}
	return guardFindings(mentions, uses)
}

// ─────────────────────────────────────────────────────────────────────────────
// КРАСНОЕ: комментарий назвал защиту, прод-код её не вызывает

// guardDefectSrc — настоящий вход, из которого гейт выведен: комментарий
// утверждает, что сегмент закрыт словарём, а вызова в пакете нет.
const guardDefectSrc = `package roles

// Сегмент глагола закрывается набором типа: принадлежность проверяет
// IsVerbOfType, поэтому отдельной сверки здесь не нужно.
func emit(verb string) string {
	return verb
}
`

func TestGuardNamingGateRedsOnACommentWithoutTheGuard(t *testing.T) {
	t.Parallel()
	const rel = "internal/apps/kaname/api/roles/emit.go"
	scan := guardScanOne(t, rel, guardDefectSrc, false)

	if len(scan.Mentions) != 1 {
		t.Fatalf("упоминание защиты НЕ прочитано: найдено %d при переписи %+v",
			len(scan.Mentions), scan.Census)
	}
	if scan.Uses["IsVerbOfType"] {
		t.Fatalf("разбор засчитал НАЛИЧИЕ там, где имя стоит только в комментарии — "+
			"гейт зеленел бы на собственном объяснении: %+v", scan.Uses)
	}

	findings := guardVerdict("internal/apps/kaname/api/roles", scan)
	if len(findings) != 1 {
		t.Fatalf("комментарий без защиты НЕ стал находкой: находок %d при переписи %+v\n"+
			"Гейт, не краснеющий на дефекте, из которого он выведен, не удерживает ничего",
			len(findings), scan.Census)
	}
	for _, want := range []string{rel, "IsVerbOfType", "internal/apps/kaname/api/roles"} {
		if !strings.Contains(findings[0], want) {
			t.Errorf("находка не называет %q: %q", want, findings[0])
		}
	}
}

// TestGuardNamingGateReadsEveryMentionForm — ЧЕТЫРЕ формы упоминания, по
// утверждению на каждую. Форма, о которой разбор не знает, молчит — и это
// молчание неотличимо от «упоминаний нет».
func TestGuardNamingGateReadsEveryMentionForm(t *testing.T) {
	t.Parallel()
	cases := []struct {
		form    check.GuardMentionForm
		comment string
	}{
		{check.GuardMentionBare, "// принадлежность проверяет IsVerbOfType на этом пути"},
		{check.GuardMentionQualified, "// принадлежность проверяет domain.IsVerbOfType здесь"},
		{check.GuardMentionCall, "// принадлежность проверяет IsVerbOfType() на этом пути"},
		{check.GuardMentionBacktick, "// принадлежность проверяет `IsVerbOfType` на этом пути"},
	}
	for _, tc := range cases {
		t.Run(string(tc.form), func(t *testing.T) {
			src := "package roles\n\n" + tc.comment + "\nfunc emit() {}\n"
			scan := guardScanOne(t, "internal/apps/kaname/api/roles/emit.go", src, false)
			if len(scan.Mentions) != 1 {
				t.Fatalf("форма %s ВНЕ наблюдения: упоминаний %d — такая запись не даёт ни "+
					"красного, ни зелёного, она молчит", tc.form, len(scan.Mentions))
			}
			if got := scan.Mentions[0].Form; got != tc.form {
				t.Errorf("форма названа %q, ожидалась %q — перепись по формам вводит в "+
					"заблуждение", got, tc.form)
			}
			if len(guardVerdict("internal/apps/kaname/api/roles", scan)) != 1 {
				t.Errorf("форма %s прочитана, но находкой не стала", tc.form)
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// ЗАКОННЫЕ БЛИЗНЕЦЫ: на каждом гейт обязан МОЛЧАТЬ

// TestGuardNamingGateStaysSilentOnLegalTwins — по оси на каждый законный случай.
func TestGuardNamingGateStaysSilentOnLegalTwins(t *testing.T) {
	t.Parallel()

	t.Run("защита и названа, и вызвана — прямой вызов", func(t *testing.T) {
		const src = `package roles

import "github.com/PRO-Robotech/kaname/internal/domain"

// принадлежность проверяет IsVerbOfType на этом пути
func emit(v string, set []string) bool {
	_ = domain.Rule{}
	return IsVerbOfType(v, set)
}
`
		scan := guardScanOne(t, "internal/apps/kaname/api/roles/emit.go", src, false)
		if !scan.Uses["IsVerbOfType"] {
			t.Fatalf("прямой вызов НЕ засчитан наличием — форма вне наблюдения: %+v", scan.Uses)
		}
		if f := guardVerdict("internal/apps/kaname/api/roles", scan); len(f) != 0 {
			t.Fatalf("гейт краснеет на законном пакете: %v", f)
		}
	})

	t.Run("вызов с квалификатором пакета", func(t *testing.T) {
		const src = `package roles

import "github.com/PRO-Robotech/kaname/internal/domain"

// принадлежность проверяет domain.IsVerbOfType здесь
func emit(v string, set []string) bool { return domain.IsVerbOfType(v, set) }
`
		scan := guardScanOne(t, "internal/apps/kaname/api/roles/emit.go", src, false)
		if !scan.Uses["IsVerbOfType"] {
			t.Fatalf("вызов с квалификатором НЕ засчитан наличием: Sel — тот же узел "+
				"ast.Ident, и форма обязана быть в наблюдении: %+v", scan.Uses)
		}
		if f := guardVerdict("internal/apps/kaname/api/roles", scan); len(f) != 0 {
			t.Fatalf("гейт краснеет на законном пакете: %v", f)
		}
	})

	t.Run("значение функции без вызова", func(t *testing.T) {
		const src = `package roles

// приведение делает NormalizeVerb
var normalize = NormalizeVerb
`
		scan := guardScanOne(t, "internal/apps/kaname/api/roles/emit.go", src, false)
		if !scan.Uses["NormalizeVerb"] {
			t.Fatalf("значение функции НЕ засчитано наличием — форма вне наблюдения: %+v",
				scan.Uses)
		}
		if f := guardVerdict("internal/apps/kaname/api/roles", scan); len(f) != 0 {
			t.Fatalf("гейт краснеет на законном пакете: %v", f)
		}
	})

	t.Run("более длинный идентификатор упоминанием НЕ является", func(t *testing.T) {
		const src = `package roles

// сегмент закрывает IsVerbOfTypeStrict — своя, более узкая проверка
func emit() {}
`
		scan := guardScanOne(t, "internal/apps/kaname/api/roles/emit.go", src, false)
		if len(scan.Mentions) != 0 {
			t.Fatalf("IsVerbOfTypeStrict засчитан упоминанием IsVerbOfType — совпадение "+
				"идёт по подстроке, а не по границе имени: находка пришла бы на имя, "+
				"которого комментарий не называл: %+v", scan.Mentions)
		}
	})
}

// TestGuardNamingGateDoesNotCountAStringLiteralAsPresence — строковый литерал,
// несущий то же имя, наличием НЕ является: он узел ast.BasicLit, а не ast.Ident.
//
// Это отрицание, и рядом с ним стоит ПОЛОЖИТЕЛЬНЫЙ контроль: без него проба
// зеленела бы на разборе, который не читает ничего.
func TestGuardNamingGateDoesNotCountAStringLiteralAsPresence(t *testing.T) {
	t.Parallel()
	const src = `package roles

// принадлежность проверяет IsVerbOfType на этом пути
const why = "принадлежность проверяет IsVerbOfType"

func emit() string { return why }
`
	scan := guardScanOne(t, "internal/apps/kaname/api/roles/emit.go", src, false)

	// положительный контроль: разбор ЧИТАЕТ этот файл.
	if scan.Census.Idents == 0 || scan.Census.Comments == 0 {
		t.Fatalf("положительный контроль не выполнен: перепись %+v — отрицание ниже "+
			"зеленело бы на пустом разборе", scan.Census)
	}
	if scan.Uses["IsVerbOfType"] {
		t.Fatalf("строковый литерал засчитан НАЛИЧИЕМ защиты — гейт судит подстроку, " +
			"а не узел разбора")
	}
	if f := guardVerdict("internal/apps/kaname/api/roles", scan); len(f) != 1 {
		t.Fatalf("пакет, где имя есть только в тексте, находкой НЕ стал: находок %d", len(f))
	}
}

// TestGuardNamingGateCountsPresenceOnlyFromProductionCode — вызов защиты внутри
// ПРОБЫ не делает её действующей в прод-пути.
func TestGuardNamingGateCountsPresenceOnlyFromProductionCode(t *testing.T) {
	t.Parallel()
	const src = `package roles

// принадлежность проверяет IsVerbOfType на этом пути
func TestEmit(t *testing.T) { _ = IsVerbOfType("a", nil) }
`
	scan := guardScanOne(t, "internal/apps/kaname/api/roles/emit_test.go", src, true)
	if scan.Uses["IsVerbOfType"] {
		t.Fatalf("вызов внутри пробы засчитан наличием в прод-коде — тогда защита, " +
			"вызываемая только пробой, считалась бы действующей")
	}
	if len(scan.Mentions) != 1 {
		t.Fatalf("упоминание в комментарии пробы не прочитано: %d", len(scan.Mentions))
	}
}

// TestGuardNamingScanRefusesAnUnparsableFile — неразобранный файл НЕ трактуется
// как «упоминаний нет»: это третья категория, и вызывающий обязан её увидеть.
func TestGuardNamingScanRefusesAnUnparsableFile(t *testing.T) {
	t.Parallel()
	_, err := check.ScanGuardNaming("internal/broken.go", []byte("package \x00 {{{"), false,
		guardInjectionNames())
	if err == nil {
		t.Fatalf("разбор неразобранного файла вернул успех — молчание такого файла " +
			"неотличимо от «упоминаний нет»")
	}
}

// TestGuardNamingRegistryIsNotEmpty — предпосылка самого гейта.
func TestGuardNamingRegistryIsNotEmpty(t *testing.T) {
	t.Parallel()
	if len(guardedIdentifiers) == 0 {
		t.Fatalf("реестр пуст — гейт проходит by construction и не стережёт ничего")
	}
	for _, g := range guardedIdentifiers {
		if g.name == "" || g.why == "" || g.retireWhen == "" {
			t.Errorf("запись реестра неполна: %+v — без условия снятия она переживёт "+
				"свой предмет молча", g)
		}
	}
}

// TestGuardNamingWalkableSelection — отбор гейта берёт прод-код и пробы и не
// берёт сгенерированное. Проверяется ТОТ ЖЕ предикат, которым судит гейт.
func TestGuardNamingWalkableSelection(t *testing.T) {
	t.Parallel()
	for _, rel := range []string{"internal/domain/rule_verbs.go", "internal/domain/rule_verbs_test.go"} {
		if !guardWalkable(rel) {
			t.Errorf("отбор не берёт %s — тогда осматривать нечего", rel)
		}
	}
	if guardWalkable("pkg/api/kaname/iam/v1/service.pb.go") {
		t.Errorf("отбор берёт сгенерированное — комментарий генератора стал бы находкой")
	}
}

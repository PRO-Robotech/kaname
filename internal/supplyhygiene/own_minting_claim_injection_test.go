// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// own_minting_claim_injection_test.go — доказательство того, что проверка
// СПОСОБНА упасть, молчит на законном близнеце и судит СУЩЕСТВО, а не слово.
//
// ─────────────────────────────────────────────────────────────────────────────
// ТРИ ПРОГОНА, И ТРЕТИЙ ОБЯЗАТЕЛЕН
//
//  1. КОНТРОЛЬ — якорь на месте, проза верна: находок ноль;
//  2. НОВОЕ СВОЙСТВО — та же проза с запрещённым утверждением: КРАСНОЕ с
//     координатой;
//  3. СУЩЕСТВУЮЩЕЕ — то же запрещённое утверждение, но якорь СНЯТ: МОЛЧАНИЕ,
//     потому что утверждение стало верным.
//
// Без третьего молчание гейта на снятом якоре неотличимо от молчания мёртвого:
// он выглядел бы работающим и на дереве, где чеканки нет вовсе.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОДИН ФАКТ ПРОТИВ БЛИЗНЕЦА
//
// Синтетическое дерево собрано ОДИН раз; каждая проба меняет ровно одну вещь —
// либо фразу, либо якорь, но никогда обе. Настоящее дерево для инъекции не
// годится: в нём семь тысяч файлов, и красное могло бы прийти от любого.
//
// ─────────────────────────────────────────────────────────────────────────────
// ГДЕ ЖИВЁТ СИНТЕТИКА
//
// В каталоге пробы, то есть ВНЕ всякого репозитория (TMPDIR выведен из дерева).
// Свой индекс git заводится там же: обход считает ОТСЛЕЖИВАЕМЫЕ элементы, и
// заведи мы его внутри — писали бы в чужой индекс.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/gitenv"
)

// anchorWiredGo — композиционный корень, ПУБЛИКУЮЩИЙ наш набор. Якорь стоит
// узлом вызова, а не словом.
const anchorWiredGo = `package main

func serve() {
	records = append(records, jwksproxyhttp.Record{
		Handler: jwksproxyhttp.NewKeySetHandler(jwksproxyhttp.KeySetConfig{Source: ks}),
	})
}
`

// anchorAbsentGo — тот же корень БЕЗ якоря. Имя якоря стоит в комментарии —
// разбор обязан его не засчитать: иначе гейт опирался бы на собственное
// объяснение.
const anchorAbsentGo = `package main

// Здесь когда-то звали jwksproxyhttp.NewKeySetHandler и
// registrytokenwire.NewLocalMinter — обоих больше нет.
func serve() {
	records = append(records, jwksproxyhttp.Record{Handler: mirror})
}
`

// proseTrue — ЗАКОННЫЙ БЛИЗНЕЦ: утверждение о провайдере как об издателе ЗАПИСИ
// ЗЕРКАЛА. Оно верно и обязано молчать — иначе гейт объявлял бы находкой
// правду, и его отключили бы первым.
const proseTrue = `# Руководство дежурного

| запись | чьи ключи |
|---|---|
| зеркало прежнего издателя | **провайдер** — он издатель и подписант этой записи |
| наша запись | ключница платформы |
`

// mintingClaimSamples — по одному образцу НА КАЖДЫЙ запрещённый образец.
// Положительный контроль каждого стоит здесь, а не в собственной прозе гейта:
// проза правится, и красное о дереве, в котором ничего не менялось, — худший
// вид находки.
var mintingClaimSamples = []struct {
	Name string
	Body string
	Want string
}{
	{"en-mints-nothing",
		"// The listener proxies the provider JWKS; iam mints nothing here.\n",
		"не чеканит ничего"},
	{"en-has-no-keyset",
		"// The shim advertises no real kids: iam has no keyset to serve.\n",
		"набора ключей у платформы нет"},
	{"en-no-keyset-of-its-own",
		"// kaname owns no keyset of its own; verification rides on the provider.\n",
		"набора ключей у платформы нет"},
	{"ru-keys-not-minted",
		"// Зеркало байт-в-байт; iam ключей не чеканит и издателем не является.\n",
		"ключей не чеканит"},
	{"ru-nothing-minted",
		"// Прокси короткого срока: платформа ничего не чеканит.\n",
		"не чеканит ничего"},
	{"ru-sole-signer",
		"Провайдер остаётся **единственным** подписантом платформы.\n",
		"единственный подписант"},
}

// proseAboutSomethingElse — ЗАКОННЫЕ БЛИЗНЕЦЫ, найденные ЗАМЕРОМ, а не
// придуманные: первая редакция образца объявила находкой каждый из них.
//
// Во всех трёх подлежащее — НЕ платформа: отвергнутое создание, анонимная
// мутация, отключённая служебная учётка. Фразы верны, и гейт, краснеющий на
// них, перестают читать.
var proseAboutSomethingElse = []struct{ Name, Body string }{
	{"rejected-create", "// Leak-free: a rejected create mints nothing. iam logs the refusal.\n"},
	{"anonymous-mutation", "// An anonymous mutation is a 401 negative: it mints nothing.\n"},
	{"disabled-sa", "// A service account that may not authenticate mints nothing, on either branch.\n"},
}

// wrappedClaim — ФОРМА ГЛАВНОЙ НАХОДКИ: фраза разорвана переносом строки.
// Разборщик, читающий по строке, слеп ровно здесь — и слеп молча.
const wrappedClaim = `// jwks_proxy.go — настройка публикатора.
//
// Зеркало короткого срока: плоскость данных берёт ключи проверки у нас, а не у
// провайдера напрямую, при том что провайдер остаётся издателем (iam mints
// nothing). Слушатель выставлен только на внутренний Service.
`

// syntheticMintingTree — дерево с СОБСТВЕННЫМ индексом git.
//
// anchors — тело композиционного корня; docs — карта «относительный путь →
// содержимое». Возвращается корень и каталог якорей относительно него.
func syntheticMintingTree(t *testing.T, anchorBody string, docs map[string]string) (root string, anchorDirs []string) {
	t.Helper()
	root = t.TempDir()

	anchorRel := filepath.Join("services", "iam", "cmd", "kaname")
	require.NoError(t, os.MkdirAll(filepath.Join(root, anchorRel), 0o750))
	require.NoError(t, os.WriteFile(
		filepath.Join(root, anchorRel, "serve.go"), []byte(anchorBody), 0o600))

	for rel, body := range docs {
		p := filepath.Join(root, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o750))
		require.NoError(t, os.WriteFile(p, []byte(body), 0o600))
	}

	for _, args := range [][]string{{"init", "-q"}, {"add", "-A"}} {
		// ПОМОЩНИК, А НЕ exec.Command: он вычищает GIT_DIR / GIT_WORK_TREE /
		// GIT_INDEX_FILE из окружения. Первая редакция брала `os.Environ()` и
		// потому МОГЛА завести индекс в том дереве, из которого идёт прогон, —
		// ровно та порча чужого состояния, которую корпус запрещает. Поймал это
		// гейт платформы, а не чтение.
		cmd := gitenv.Command(root, args...)
		cmd.Env = append(cmd.Env, "GIT_CONFIG_GLOBAL=/dev/null", "GIT_CONFIG_SYSTEM=/dev/null")
		out, err := cmd.CombinedOutput()
		require.NoErrorf(t, err, "синтетика не собрана: git %v: %s", args, out)
	}
	return root, []string{filepath.ToSlash(anchorRel)}
}

// runMintingScan — обход синтетики с проверкой предпосылки.
func runMintingScan(t *testing.T, anchorBody string, docs map[string]string) (mintingCensus, []mintingFinding) {
	t.Helper()
	root, dirs := syntheticMintingTree(t, anchorBody, docs)
	census, findings, err := scanOwnMintingClaims(root, dirs)
	require.NoError(t, err)
	require.NotZero(t, census.filesRead, "инъекция беспредметна: обход пуст")
	require.NotZero(t, census.blocks, "инъекция беспредметна: блоков ноль")
	return census, findings
}

// TestOwnMintingInjection_ControlIsSilent — ПРОГОН 1: якорь на месте, проза
// верна — находок ноль.
func TestOwnMintingInjection_ControlIsSilent(t *testing.T) {
	t.Parallel()
	census, findings := runMintingScan(t, anchorWiredGo, map[string]string{
		"docs/runbook.md": proseTrue,
	})
	require.NotEmpty(t, census.anchorsFound, "якорь не найден разбором — инъекция беспредметна")
	require.Empty(t, findings,
		"гейт краснеет на ВЕРНОМ утверждении о провайдере — он ловит слово, а не существо.\nнаходки: %v", findings)
}

// TestOwnMintingInjection_EachClaimShapeIsCaught — ПРОГОН 2: по одному внесению
// на КАЖДЫЙ образец. Один факт против контроля: меняется только фраза.
func TestOwnMintingInjection_EachClaimShapeIsCaught(t *testing.T) {
	t.Parallel()
	for _, s := range mintingClaimSamples {
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
			_, findings := runMintingScan(t, anchorWiredGo, map[string]string{
				"docs/runbook.md":      proseTrue,
				"services/iam/note.go": s.Body,
			})
			require.Lenf(t, findings, 1,
				"внесён ОДИН дефект, найдено %d — проверка ловит не то, что внесли: %v", len(findings), findings)
			require.Contains(t, findings[0].Path, "note.go", "находка называет не тот файл")
			require.Containsf(t, findings[0].Why, s.Want,
				"находка называет симптом, а не предмет: %q", findings[0].Why)
		})
	}
}

// TestOwnMintingInjection_ClaimAboutSomethingElseIsSilent — законные близнецы:
// то же слово, ДРУГОЕ подлежащее. Молчание обязательно.
func TestOwnMintingInjection_ClaimAboutSomethingElseIsSilent(t *testing.T) {
	t.Parallel()
	for _, s := range proseAboutSomethingElse {
		t.Run(s.Name, func(t *testing.T) {
			t.Parallel()
			_, findings := runMintingScan(t, anchorWiredGo, map[string]string{
				"services/iam/note.go": s.Body,
			})
			require.Emptyf(t, findings,
				"гейт объявил находкой ВЕРНУЮ фразу о другом предмете — он судит слово, а не подлежащее.\nнаходки: %v",
				findings)
		})
	}
}

// TestOwnMintingInjection_QuotedRetractionIsSilent — ЦИТАТА снятого утверждения
// молчит, ТО ЖЕ утверждение без кавычек — краснеет.
//
// Один факт против близнеца: различаются ровно ёлочки. Без этой пары гейт
// краснел бы на собственной починке, а с ней видно, что он судит утверждение, а
// не слово.
func TestOwnMintingInjection_QuotedRetractionIsSilent(t *testing.T) {
	t.Parallel()
	const claim = "iam mints nothing"
	retraction := "// Здесь стояло «" + claim + "» — утверждение пережило свой предмет.\n"
	asserted := "// " + claim + " — ключи проверки приезжают от провайдера.\n"

	_, quiet := runMintingScan(t, anchorWiredGo, map[string]string{
		"services/iam/note.go": retraction,
	})
	require.Emptyf(t, quiet,
		"гейт краснеет на ЦИТАТЕ снятого утверждения — он не отличает утверждение от прозы о нём, "+
			"и первая же честная починка сделает его красным.\nнаходки: %v", quiet)

	_, loud := runMintingScan(t, anchorWiredGo, map[string]string{
		"services/iam/note.go": asserted,
	})
	require.Lenf(t, loud, 1,
		"то же утверждение БЕЗ кавычек обязано быть находкой — иначе снятие кавычек стало маской: %v", loud)
}

// TestOwnMintingInjection_WrappedAcrossLinesIsCaught — фраза, разорванная
// переносом. Форма главной находки; построчный разборщик слеп ровно здесь.
func TestOwnMintingInjection_WrappedAcrossLinesIsCaught(t *testing.T) {
	t.Parallel()
	_, findings := runMintingScan(t, anchorWiredGo, map[string]string{
		"services/iam/internal/apps/kaname/config/jwks_proxy.go": wrappedClaim,
	})
	require.Lenf(t, findings, 1,
		"перенос строки уводит фразу из-под наблюдения: найдено %d", len(findings))
	require.Contains(t, findings[0].Path, "jwks_proxy.go")
	// Координата — строка САМОГО утверждения (4), а не начало абзаца (3) и не
	// начало комментария (1). Фраза разорвана переносом, и править её идут туда,
	// где она начинается.
	require.Equal(t, 4, findings[0].Line,
		"координата называет не строку утверждения — читатель пойдёт править не туда")
}

// TestOwnMintingInjection_WithoutAnchorTheClaimIsTrue — ПРОГОН 3: то же
// запрещённое утверждение при СНЯТОМ якоре — молчание.
//
// Здесь же проверено, что якорь берётся РАЗБОРОМ: его имя стоит в комментарии
// снятого корня, и словесный поиск засчитал бы его.
func TestOwnMintingInjection_WithoutAnchorTheClaimIsTrue(t *testing.T) {
	t.Parallel()
	census, findings := runMintingScan(t, anchorAbsentGo, map[string]string{
		"services/iam/note.go": mintingClaimSamples[0].Body,
	})
	require.Empty(t, census.anchorsFound,
		"имя якоря в КОММЕНТАРИИ засчитано за якорь — гейт опирается на слово, а не на узел вызова")
	require.Empty(t, findings,
		"гейт объявляет находкой утверждение, которое дерево ПОДТВЕРЖДАЕТ: чеканки в нём нет.\nнаходки: %v", findings)
	require.NotZero(t, census.byLang["en"],
		"перепись не увидела совпадения вовсе — молчание пришло не от якоря, а от слепоты")
}

// TestOwnMintingInjection_SelfExclusionExpires — изъятие, потерявшее предмет,
// обязано быть видимым: файла нет в обходе ⇒ его нет и в переписи встреченных.
func TestOwnMintingInjection_SelfExclusionExpires(t *testing.T) {
	t.Parallel()
	census, _ := runMintingScan(t, anchorWiredGo, map[string]string{
		"docs/runbook.md": proseTrue,
	})
	for _, s := range mintingSelfFiles {
		require.Falsef(t, census.selfSeen[s],
			"в синтетике файла %s нет, а перепись объявила его встреченным — предпосылка изъятия не проверяется", s)
	}
}

// TestOwnMintingInjection_EmptyTraversalIsRefused — обход без предмета не
// зеленеет: «ноль находок» обязано быть отличимо от «ноль прочитанного».
func TestOwnMintingInjection_EmptyTraversalIsRefused(t *testing.T) {
	t.Parallel()
	root := t.TempDir()
	_, _, err := scanOwnMintingClaims(root, []string{"services/iam/cmd/kaname"})
	require.Error(t, err, "обход по дереву без композиционного корня обязан ОТКАЗАТЬ, а не смолчать")
	require.Contains(t, strings.ToLower(err.Error()), "не прочитан")
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// audit_payload_pii_injection_test.go — доказательство, что
// TestAuditPayloadCarriesNoPersonalData СПОСОБЕН упасть, и падает он на
// существе, а не на форме.
//
// Инъекция идёт в ОБЕ стороны по каждой оси: дефект обязан находиться С
// КООРДИНАТОЙ, законный близнец — молчать. Без второй половины гейт ловил бы
// форму записи, а не личное поле, и первый же ложный срабат его отключил бы.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/gitenv"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// synthAuditTree — синтетическое дерево с индексом git: состав обход берёт у
// индекса, поэтому файлы обязаны быть добавлены, а дерево — непустым.
func synthAuditTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	run := func(args ...string) {
		t.Helper()
		if out, err := gitenv.Command(root, args...).CombinedOutput(); err != nil {
			t.Fatalf("git %v: %v\n%s", args, err, out)
		}
	}
	write := func(rel, body string) {
		t.Helper()
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	run("init", "--quiet", "-b", "main")
	// Дерево обязано быть непустым: обход берёт состав у индекса, и «смотреть
	// не на что» есть отказ, а не успех.
	write("README.md", "# синтетическое дерево пробы\n")
	for rel, body := range files {
		write(rel, body)
	}
	run("add", "-A")
	return root
}

// requireOneAuditFinding — дефект найден РОВНО один, и назван координатой.
func requireOneAuditFinding(t *testing.T, root, wantWhere, wantKey string) {
	t.Helper()
	findings, census, err := check.ScanAuditPayloads(root)
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if census.Read == 0 {
		t.Fatal("синтетическое дерево не прочитано")
	}
	if len(findings) != 1 {
		t.Fatalf("находок %d, ожидалась 1: %v\n%s", len(findings), findings, census)
	}
	if !strings.Contains(findings[0].Where, wantWhere) {
		t.Fatalf("находка названа координатой %q, ожидалась %q", findings[0].Where, wantWhere)
	}
	if findings[0].Key != wantKey {
		t.Fatalf("находка назвала ключ %q, ожидался %q", findings[0].Key, wantKey)
	}
	if strings.TrimSpace(findings[0].Why) == "" {
		t.Fatal("находка не назвала причины — такую проверку снимают следующей как непонятную")
	}
}

// requireNoAuditFinding — законный близнец МОЛЧИТ, и при этом место разобрано.
//
// Второе условие несущее: молчание разбора, который ничего не нашёл, и
// молчание разбора, который никуда не заглянул, выглядят одинаково.
func requireNoAuditFinding(t *testing.T, root string, wantSites int) {
	t.Helper()
	findings, census, err := check.ScanAuditPayloads(root)
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if census.Read == 0 {
		t.Fatal("синтетическое дерево не прочитано")
	}
	if census.Sites < wantSites {
		t.Fatalf("мест построения нагрузки осмотрено %d, ожидалось не меньше %d — молчание "+
			"означает «не заглянул», а не «чисто»\n%s", census.Sites, wantSites, census)
	}
	if len(findings) != 0 {
		t.Fatalf("законный близнец объявлен находкой: %v", findings)
	}
}

// ── Ось 1: литерал прямо в поле ─────────────────────────────────────────────

func TestAuditGateCatchesPersonalKeyInAFieldLiteral(t *testing.T) {
	t.Parallel()
	root := synthAuditTree(t, map[string]string{
		"internal/thing/thing.go": `package thing

func emit(u User) {
	_ = Event{Payload: map[string]any{
		"actor":   "system",
		"user_id": u.ID,
		"email":   u.Email,
	}}
}
`,
	})
	requireOneAuditFinding(t, root, "internal/thing/thing.go:7", "email")
}

// Законный близнец ОДНО-ФАКТНЫЙ: та же нагрузка, тот же субъект — но названный
// идентификатором вместо почты. Меняется ровно один факт против дефекта выше.
func TestAuditGateIsSilentWhenTheSubjectIsNamedByID(t *testing.T) {
	t.Parallel()
	root := synthAuditTree(t, map[string]string{
		"internal/thing/thing.go": `package thing

func emit(u User) {
	_ = Event{Payload: map[string]any{
		"actor":   "system",
		"user_id": u.ID,
	}}
}
`,
	})
	requireNoAuditFinding(t, root, 1)
}

// ── Ось 2: построитель ──────────────────────────────────────────────────────

func TestAuditGateCatchesPersonalKeyInABuilder(t *testing.T) {
	t.Parallel()
	root := synthAuditTree(t, map[string]string{
		"internal/thing/audit.go": `package thing

func thingAuditPayload(actor, userID, email string) map[string]any {
	return map[string]any{
		"actor":        actor,
		"user_id":      userID,
		"display_name": email,
	}
}
`,
	})
	requireOneAuditFinding(t, root, "internal/thing/audit.go:7", "display_name")
}

// ── Ось 3: ключ, досланный присваиванием по индексу ─────────────────────────
//
// Ось заведена потому, что литеральный разбор эту форму НЕ видит: условный ключ
// в литерале не стоит вовсе. Без неё он был бы вне наблюдения, оставаясь на вид
// покрытым.

func TestAuditGateCatchesPersonalKeyAddedByIndex(t *testing.T) {
	t.Parallel()
	root := synthAuditTree(t, map[string]string{
		"internal/thing/audit.go": `package thing

func thingAuditPayload(actor, userID, phone string) map[string]any {
	p := map[string]any{
		"actor":   actor,
		"user_id": userID,
	}
	if phone != "" {
		p["phone"] = phone
	}
	return p
}
`,
	})
	requireOneAuditFinding(t, root, "internal/thing/audit.go:9", "phone")
}

// ── Ось 4: нагрузка, собранная в имя и подставленная в поле ─────────────────

func TestAuditGateCatchesPersonalKeyBehindALocalName(t *testing.T) {
	t.Parallel()
	root := synthAuditTree(t, map[string]string{
		"internal/thing/thing.go": `package thing

func emit(u User) {
	p := map[string]any{
		"actor":       "system",
		"external_id": u.ExternalID,
	}
	_ = Event{Payload: p}
}
`,
	})
	requireOneAuditFinding(t, root, "internal/thing/thing.go:6", "external_id")
}

// ── Ось 5: близнец, отличающий НАГРУЗКУ от любой карты ──────────────────────
//
// Ось несущая: без неё гейт судил бы всякий литерал `map[string]any` со словом
// «email», то есть краснел бы на разборе запроса, на фикстуре и на кэше. Гейт,
// краснеющий на верном коде, отключают первым.

func TestAuditGateIsSilentOnANonPayloadMap(t *testing.T) {
	t.Parallel()
	root := synthAuditTree(t, map[string]string{
		"internal/thing/thing.go": `package thing

func decode(u User) map[string]any {
	// Не нагрузка журнала: тело ответа вызывающему, где почта законна.
	return map[string]any{
		"email":        u.Email,
		"display_name": u.DisplayName,
	}
}

func emit(u User) {
	_ = Event{Payload: map[string]any{"actor": "system", "user_id": u.ID}}
}
`,
	})
	requireNoAuditFinding(t, root, 1)
}

// ── Ось 6: близнец, отличающий ключ от ПОХОЖЕГО ключа ───────────────────────
//
// Сверка точная, а не подстрочная: `token_id` — идентификатор выданного
// предъявления, он законен и стоит в дереве. Подстрочное сравнение сделало бы
// находкой его, а заодно `user_id` под ключом `id`.

func TestAuditGateIsSilentOnAnIdentifierThatMerelyLooksLikeASecret(t *testing.T) {
	t.Parallel()
	root := synthAuditTree(t, map[string]string{
		"internal/thing/audit.go": `package thing

func tokenAuditPayload(actor, userID, tokenID string) map[string]any {
	return map[string]any{
		"actor":    actor,
		"user_id":  userID,
		"token_id": tokenID,
	}
}
`,
	})
	requireNoAuditFinding(t, root, 1)
}

// ── Ось 7: сериализованные байты у писателя НАГРУЗКОЙ не являются ───────────
//
// `EventPayload` — уже сериализованное значение у писателя, а не место
// построения. Разбор по подстроке `Payload:` принял бы его за форму и судил бы
// место, где ключей нет вовсе; заодно он не увидел бы там ни одного ключа и
// молчал бы — то есть засчитал бы в покрытие место, о котором не сказал ничего.

func TestAuditGateDoesNotMistakeTheSerialisedFieldForABuildSite(t *testing.T) {
	t.Parallel()
	root := synthAuditTree(t, map[string]string{
		"internal/thing/writer.go": `package thing

func write(payloadJSON []byte) {
	_ = Row{EventPayload: payloadJSON}
}

func emit(u User) {
	_ = Event{Payload: map[string]any{"actor": "system", "user_id": u.ID}}
}
`,
	})
	findings, census, err := check.ScanAuditPayloads(root)
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("сериализованное поле принято за место построения: %v", findings)
	}
	// Мест ровно одно — настоящее. Было бы два, значит `EventPayload` сочтён
	// формой, и перепись завысила бы покрытие.
	if census.Sites != 1 {
		t.Fatalf("мест построения нагрузки %d, ожидалось 1 (`EventPayload` формой не "+
			"является)\n%s", census.Sites, census)
	}
}

// ── Ось 8: непрозрачная нагрузка НАЗЫВАЕТСЯ, а не проглатывается ────────────
//
// Значение, не сводящееся ни к одной форме, литеральным разбором не судится.
// Сказать о нём обязан сам разбор: иначе «личных ключей нет» тихо расширилось
// бы на места, о которых не сказано ничего.

func TestAuditGateNamesAnOpaquePayloadInsteadOfSwallowingIt(t *testing.T) {
	t.Parallel()
	root := synthAuditTree(t, map[string]string{
		"internal/thing/thing.go": `package thing

func emit(src Source) {
	_ = Event{Payload: src.build()}
}
`,
	})
	_, census, err := check.ScanAuditPayloads(root)
	if err != nil {
		t.Fatalf("обход синтетического дерева: %v", err)
	}
	if census.SitesByForm[check.FormOpaque] != 1 {
		t.Fatalf("непрозрачных мест %d, ожидалось 1 — граница вердикта не названа\n%s",
			census.SitesByForm[check.FormOpaque], census)
	}
}

// ── Ось 9: перепись растёт вместе с осмотренным ─────────────────────────────
//
// Перепись, не меняющаяся от прибавления предмета, не измеряет объём: тогда
// «ноль находок» неотличимо от «ноль прочитанного» ровно так же, как без неё.

func TestAuditCensusGrowsWithTheTree(t *testing.T) {
	t.Parallel()
	one := `package thing

func emit(u User) {
	_ = Event{Payload: map[string]any{"actor": "system", "user_id": u.ID}}
}
`
	small := synthAuditTree(t, map[string]string{"internal/a/a.go": one})
	big := synthAuditTree(t, map[string]string{
		"internal/a/a.go": one,
		"internal/b/b.go": strings.Replace(one, "package thing", "package other", 1),
	})
	_, cs, err := check.ScanAuditPayloads(small)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	_, cb, err := check.ScanAuditPayloads(big)
	if err != nil {
		t.Fatalf("обход: %v", err)
	}
	if !(cb.Read > cs.Read && cb.Sites > cs.Sites && cb.Keys > cs.Keys) {
		t.Fatalf("перепись не выросла вместе с деревом: было (%d/%d/%d), стало (%d/%d/%d)",
			cs.Read, cs.Sites, cs.Keys, cb.Read, cb.Sites, cb.Keys)
	}
}

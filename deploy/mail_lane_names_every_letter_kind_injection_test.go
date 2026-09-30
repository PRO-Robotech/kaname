// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_lane_names_every_letter_kind_injection_test.go — доказательство того,
// что гейт `TestMailLaneDeclarationNamesEveryLetterKind` СПОСОБЕН упасть и
// падает на своём предмете.
//
// Инъекция зовёт ТО ЖЕ суждение (`judgeMailLane`) и те же распознаватели
// (`mailLaneDocSites`, `declaresMailRelay`, `mailLaneChartSite`,
// `readMailLaneInputs`), что исполняются на дереве, и берёт вход у дерева.
// Подменяется ОДИН факт на случай, и у каждого отрицания рядом законный близнец.
package deploy_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// treeMailLaneInputs — вход гейта, собранный с дерева.
func treeMailLaneInputs(t *testing.T) mailLaneInputs {
	t.Helper()
	in, _, err := readMailLaneInputs(serviceRoot(t))
	if err != nil {
		t.Fatalf("вход гейта с дерева не собран: %v", err)
	}
	if len(in.kinds) == 0 || in.chart == nil || len(in.installSites) == 0 || len(in.siteSites) == 0 {
		t.Fatalf("вход гейта с дерева неполон (видов %d, узел чарта %v, мест в документе установки %d, "+
			"на сайте %d) — подменять не в чем", len(in.kinds), in.chart != nil, len(in.installSites), len(in.siteSites))
	}
	return in
}

// replacedSite — копия перечня мест, где у одного места заменён текст;
// перечень дерева не трогается.
func replacedSite(sites []mailLaneSite, i int, text string) []mailLaneSite {
	cp := append([]mailLaneSite{}, sites...)
	cp[i].text = text
	return cp
}

func TestMailLaneInjection_TreeInputsAreSilent(t *testing.T) {
	// КОНТРОЛЬ: вход дерева как есть — близнец каждой инъекции ниже.
	if f := judgeMailLane(treeMailLaneInputs(t)); len(f) != 0 {
		t.Fatalf("суждение покраснело на входе дерева: %v", f)
	}
}

func TestMailLaneInjection_KindDroppedFromTheInstallDocIsAFinding(t *testing.T) {
	in := treeMailLaneInputs(t)
	kind := in.kinds[len(in.kinds)-1]
	site := in.installSites[0]
	if !namesKind(site.text, kind) {
		t.Fatalf("предпосылка: %s не называет %s на дереве", site.where, kind)
	}
	in.installSites = replacedSite(in.installSites, 0, strings.ReplaceAll(site.text, "`"+kind+"`", ""))
	f := judgeMailLane(in)
	if len(f) != 1 || !strings.Contains(f[0], mailInstallDoc) || !strings.Contains(f[0], kind) {
		t.Fatalf("вид, снятый с документа установки, не найден ровно одной находкой с координатой и видом: %v", f)
	}
}

func TestMailLaneInjection_KindDroppedFromTheSitePageIsAFinding(t *testing.T) {
	in := treeMailLaneInputs(t)
	kind := in.kinds[0]
	site := in.siteSites[0]
	in.siteSites = replacedSite(in.siteSites, 0, strings.ReplaceAll(site.text, "<code>"+kind+"</code>", ""))
	f := judgeMailLane(in)
	if len(f) != 1 || !strings.Contains(f[0], site.where) || !strings.Contains(f[0], kind) {
		t.Fatalf("вид, снятый со страницы сайта, не найден ровно одной находкой: %v", f)
	}
}

func TestMailLaneInjection_KindWithoutCodeBoundaryIsNotNamed(t *testing.T) {
	// Граница фрагмента входит в суждение: вид прозой и вид с приставкой видом не
	// считаются. Близнец — вход дерева, где тот же вид назван фрагментом.
	for name, spoil := range map[string]func(k string) string{
		"проза":     func(k string) string { return k },
		"приставка": func(k string) string { return "`" + k + ".v2`" },
	} {
		t.Run(name, func(t *testing.T) {
			in := treeMailLaneInputs(t)
			kind := in.kinds[0]
			chart := *in.chart
			chart.text = strings.ReplaceAll(chart.text, "`"+kind+"`", spoil(kind))
			in.chart = &chart
			f := judgeMailLane(in)
			if len(f) != 1 || !strings.Contains(f[0], "deploy/values.yaml") || !strings.Contains(f[0], kind) {
				t.Fatalf("вид без границы фрагмента засчитан названным: %v", f)
			}
		})
	}
}

func TestMailLaneInjection_NewSchemaKindIsAFindingAtEverySite(t *testing.T) {
	// Словарь схемы вырос на вид, которого не называет ни одно место: находка на
	// каждом — узел, документ установки, страница сайта.
	in := treeMailLaneInputs(t)
	in.kinds = append(append([]string{}, in.kinds...), "mail.digest.send")
	f := judgeMailLane(in)
	want := 1 + len(in.installSites) + len(in.siteSites)
	if len(f) != want {
		t.Fatalf("новый вид схемы: находок %d, ждали %d (по одной на место): %v", len(f), want, f)
	}
	for _, x := range f {
		if !strings.Contains(x, "mail.digest.send") {
			t.Fatalf("находка не называет нового вида: %s", x)
		}
	}
}

func TestMailLaneInjection_ChartNodeWithoutCommentIsAFinding(t *testing.T) {
	in := treeMailLaneInputs(t)
	in.chart = &mailLaneSite{where: in.chart.where, text: ""}
	f := judgeMailLane(in)
	if len(f) != 1 || !strings.Contains(f[0], "deploy/values.yaml") {
		t.Fatalf("узел чарта без комментария не найден: %v", f)
	}
	in.chart = nil
	f = judgeMailLane(in)
	if len(f) != 1 || !strings.Contains(f[0], mailNodeChartKey) {
		t.Fatalf("отсутствующий узел чарта не найден: %v", f)
	}
}

func TestMailLaneInjection_DeclaringRowRemovedLeavesTheDocWithoutASite(t *testing.T) {
	// Настоящая страница дерева: строка таблицы, объявляющая адрес узла, снята —
	// места объявления на сайте не остаётся, и это находка, а не молчание.
	root := serviceRoot(t)
	rel := "docs/content/install/configuration.mdx"
	body, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatal(err)
	}
	if got := len(mailLaneDocSites(rel, string(body))); got != 1 {
		t.Fatalf("предпосылка: %s объявляет узел в %d разделах, ждали 1", rel, got)
	}
	var kept []string
	for _, line := range strings.Split(string(body), "\n") {
		if !declaresMailRelay(line) {
			kept = append(kept, line)
		}
	}
	if got := mailLaneDocSites(rel, strings.Join(kept, "\n")); len(got) != 0 {
		t.Fatalf("страница без строки адреса всё ещё объявляет узел: %v", got)
	}
	in := treeMailLaneInputs(t)
	in.siteSites = nil
	if f := judgeMailLane(in); len(f) != 1 || !strings.Contains(f[0], mailSiteDocsDir) {
		t.Fatalf("сайт без места объявления не найден: %v", f)
	}
}

func TestMailLaneInjection_ProseMentionIsNotADeclaration(t *testing.T) {
	// Упоминание узла в прозе местом объявления не считается; близнец — та же
	// страница со строкой таблицы.
	prose := "## Приглашение\n\nпока не объявлены `inviteMail.relay` и `inviteMail.from`, письмо не уходит\n"
	if got := mailLaneDocSites("x.md", prose); len(got) != 0 {
		t.Fatalf("проза засчитана местом объявления: %v", got)
	}
	table := prose + "\n| Ключ | Что |\n|---|---|\n| `inviteMail.relay` | узел |\n"
	if got := mailLaneDocSites("x.md", table); len(got) != 1 {
		t.Fatalf("строка таблицы не засчитана местом объявления: %v", got)
	}
	html := "## Узел\n<table><tbody>\n    <tr><td><code>invite-mail.relay</code> · <code>KANAME_INVITE_MAIL&#95;&#95;RELAY</code></td><td>узел</td></tr>\n</tbody></table>\n"
	if got := mailLaneDocSites("x.mdx", html); len(got) != 1 {
		t.Fatalf("строка разметки не засчитана местом объявления: %v", got)
	}
	secondCell := "## Узел\n| Что | Ключ |\n|---|---|\n| узел | `inviteMail.relay` |\n"
	if got := mailLaneDocSites("x.md", secondCell); len(got) != 0 {
		t.Fatalf("ключ во второй клетке засчитан объявлением: %v", got)
	}
}

func TestMailLaneInjection_FencedHashLineDoesNotSplitTheSection(t *testing.T) {
	// `# …` внутри огороженного кода раздела не открывает: вид, названный после
	// примера оболочки, остаётся в разделе, где объявлен узел.
	doc := "### Узел\n| `inviteMail.relay` | узел |\n```sh\n# /etc/kaname/config.yaml\n```\nвиды: `mail.invite.send`\n"
	got := mailLaneDocSites("x.md", doc)
	if len(got) != 1 || !namesKind(got[0].text, "mail.invite.send") {
		t.Fatalf("строка огороженного кода разрезала раздел: %v", got)
	}
	unfenced := strings.Replace(doc, "```sh\n", "", 1)
	unfenced = strings.Replace(unfenced, "```\n", "", 1)
	got = mailLaneDocSites("x.md", unfenced)
	if len(got) != 1 || namesKind(got[0].text, "mail.invite.send") {
		t.Fatalf("близнец без ограды: заголовок `#` обязан закрыть раздел: %v", got)
	}
}

func TestMailLaneInjection_ChartReaderRefusesARenamedRelay(t *testing.T) {
	good := "# `mail.invite.send`\ninviteMail:\n  relay: \"\"\n"
	s, err := mailLaneChartSite([]byte(good))
	if err != nil || s == nil || !namesKind(s.text, "mail.invite.send") {
		t.Fatalf("законный близнец: узел с листом адреса и комментарием не прочитан: %v %v", s, err)
	}
	renamed := "# `mail.invite.send`\ninviteMail:\n  host: \"\"\n"
	if _, err := mailLaneChartSite([]byte(renamed)); err == nil {
		t.Fatal("узел без листа адреса прочитан молча — проба судила бы не тот предмет")
	}
}

func TestMailLaneInjection_EmptyMigrationCorpusIsNotExecuted(t *testing.T) {
	// Пустой корпус миграций — «проверка НЕ ИСПОЛНЯЛАСЬ», а не «видов ноль».
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, filepath.FromSlash(check.MigrationsDirRel)), 0o755); err != nil {
		t.Fatal(err)
	}
	corpus, err := readMigrationCorpus(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, _, err := check.MailKindsOfSchema(corpus); err == nil {
		t.Fatal("пустой корпус миграций дал словарь видов")
	}
	if _, _, err := readMailLaneInputs(root); err == nil {
		t.Fatal("вход гейта собран с дерева без миграций")
	}
}

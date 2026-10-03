// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// mail_lane_names_every_letter_kind_test.go — ПОЧТОВЫЙ УЗЕЛ ОБЪЯВЛЕН НА КАЖДЫЙ
// ВИД ПИСЬМА, КОТОРЫЙ СЛУЖБА ЧЕРЕЗ НЕГО ШЛЁТ (kaname#259, п. 2).
//
// # Предмет
//
// Почтовая полоса у службы одна: очередь `invite_mail_outbox`, один дренаж и
// один узел — ключи `inviteMail.*` чарта. Видов письма в ней несколько, и
// словарь их закрыт ограничением схемы на колонке вида события. Ключи узла
// названы по первому виду (приглашение), и объявление узла говорило только о
// нём: чарт — «почтовая полоса приглашения», документ установки — «на два вида
// письма», когда видов стало три, страница настроек сайта — ничего. Под посадкой
// `own` через тот же узел уходят коды восстановления доступа и подтверждения
// адреса, а старт требует их сроков. Ставящий, прочитав объявление, решает, что
// узел нужен только приглашениям, и молчит о нём — и коды чеканятся, а
// доставить их нечем.
//
// # Что здесь утверждается
//
//	Р1  ИСТОЧНИК видов — словарь схемы (`check.MailKindsOfSchema`), тот же, что
//	    судит `TestEveryMailKindHasExactlyOneSender`; здесь он не выписывается;
//	Р2  МЕСТА ОБЪЯВЛЕНИЯ узла выводятся из дерева, а не перечисляются:
//	      · узел `inviteMail` базовых значений чарта — его головной комментарий;
//	      · каждый раздел `INSTALL.md` и страниц `docs/content`, где строка
//	        ТАБЛИЦЫ объявляет адрес узла (ключ чарта, ключ настройки процесса
//	        либо его переменная окружения). Упоминание в прозе местом объявления
//	        не считается: оно говорит о письме своего раздела, а не об узле;
//	Р3  документ установки и сайт объявляют узел хотя бы одной строкой таблицы
//	    каждый: узел, которого в перечне ручек нет вовсе, не объявлен никому;
//	Р4  каждое место называет КАЖДЫЙ вид словаря кодовым фрагментом
//	    (`mail.x.send` в Markdown и комментарии, <code>mail.x.send</code> в
//	    разметке страницы) — граница фрагмента входит в суждение: слово в прозе
//	    и вид с приставкой видом не считаются;
//	Р5  перепись печатается числами; пустой словарь, непрочитанный документ
//	    установки и ноль страниц сайта — «проверка НЕ ИСПОЛНЯЛАСЬ», а не зелёное.
//
// # Область
//
// Судится ОБЪЯВЛЕНИЕ. Доставку письма, согласованность величин узла и то,
// кто ставит письмо в очередь, судят страж старта (`InviteMailConfig.Validate`)
// и гейты дерева `internal/check`; здесь второго места о них не заводится.
package deploy_test

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// Координаты узла. Ключ настройки процесса — владелец; ключ чарта и
// переменная выводятся и сверяются с деревом предпосылкой ниже, чтобы
// переименованная ручка роняла пробу, а не делала её слепой.
const (
	mailRelayProcessKey = "invite-mail.relay"
	mailNodeChartKey    = "inviteMail"
	mailRelayChartLeaf  = "relay"
	mailInstallDoc      = "INSTALL.md"
	mailSiteDocsDir     = "docs/content"
)

// mailRelaySpellings — все написания адреса узла, которыми его объявляет
// строка таблицы: ключ чарта, ключ настройки процесса, переменная окружения.
func mailRelaySpellings() []string {
	return []string{
		mailNodeChartKey + "." + mailRelayChartLeaf,
		mailRelayProcessKey,
		canonicalEnvName(mailRelayProcessKey),
	}
}

// mailLaneSite — одно место объявления узла: где оно и его текст.
type mailLaneSite struct {
	where string
	text  string
}

// mailLaneInputs — всё, что читает суждение. Собирается из дерева пробой и
// подменяется по одному факту доказательством способности упасть.
type mailLaneInputs struct {
	kinds        []string
	chart        *mailLaneSite // nil — узла в базовых значениях нет
	installSites []mailLaneSite
	siteSites    []mailLaneSite
}

// mailLaneCensus — объём осмотренного.
type mailLaneCensus struct {
	kinds          int
	kindSite       string
	migrationsRead int
	siteFilesRead  int
	chartNodes     int
	installRows    int
	siteRows       int
}

func (c mailLaneCensus) String() string {
	return fmt.Sprintf("перепись: видов письма в словаре схемы %d (%s) · миграций прочитано %d · "+
		"страниц сайта прочитано %d · мест объявления узла: чарт %d, документ установки %d, сайт %d",
		c.kinds, c.kindSite, c.migrationsRead, c.siteFilesRead, c.chartNodes, c.installRows, c.siteRows)
}

// TestMailLaneDeclarationNamesEveryLetterKind — сам гейт.
func TestMailLaneDeclarationNamesEveryLetterKind(t *testing.T) {
	root := serviceRoot(t)
	in, census, err := readMailLaneInputs(root)
	if err != nil {
		t.Fatalf("проверка НЕ ИСПОЛНЯЛАСЬ: %v", err)
	}
	t.Log(census)
	findings := judgeMailLane(in)
	if len(findings) > 0 {
		t.Fatalf("почтовый узел объявлен не на каждый вид письма, который через него уходит — находок %d:\n  - %s",
			len(findings), strings.Join(findings, "\n  - "))
	}
}

// readMailLaneInputs собирает вход из дерева. Состав каталогов берётся обходом
// диска, а не индексом git подпроцессом: обход виден кешу `go test`, и
// появившаяся миграция либо страница сбрасывают кешированный вердикт.
func readMailLaneInputs(root string) (mailLaneInputs, mailLaneCensus, error) {
	var in mailLaneInputs
	var c mailLaneCensus

	migrations, err := readMigrationCorpus(root)
	if err != nil {
		return in, c, err
	}
	kinds, site, read, _, err := check.MailKindsOfSchema(migrations)
	if err != nil {
		return in, c, fmt.Errorf("словарь видов письма не собран: %w", err)
	}
	in.kinds, c.kinds, c.kindSite, c.migrationsRead = kinds, len(kinds), site, read

	values, err := os.ReadFile(filepath.Join(root, "deploy", "values.yaml"))
	if err != nil {
		return in, c, fmt.Errorf("базовые значения чарта: %w", err)
	}
	chart, err := mailLaneChartSite(values)
	if err != nil {
		return in, c, err
	}
	in.chart = chart
	if chart != nil {
		c.chartNodes = 1
	}

	install, err := os.ReadFile(filepath.Join(root, mailInstallDoc))
	if err != nil {
		return in, c, fmt.Errorf("документ установки не прочитан: %w", err)
	}
	in.installSites = mailLaneDocSites(mailInstallDoc, string(install))
	c.installRows = len(in.installSites)

	siteRoot := filepath.Join(root, filepath.FromSlash(mailSiteDocsDir))
	werr := filepath.WalkDir(siteRoot, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !(strings.HasSuffix(path, ".mdx") || strings.HasSuffix(path, ".md")) {
			return nil
		}
		body, rerr := os.ReadFile(path)
		if rerr != nil {
			return rerr
		}
		rel, _ := filepath.Rel(root, path)
		c.siteFilesRead++
		in.siteSites = append(in.siteSites, mailLaneDocSites(filepath.ToSlash(rel), string(body))...)
		return nil
	})
	if werr != nil {
		return in, c, fmt.Errorf("страницы сайта: %w", werr)
	}
	if c.siteFilesRead == 0 {
		return in, c, fmt.Errorf("в %s не прочитано ни одной страницы — «узел не объявлен» было бы "+
			"неотличимо от «ничего не прочитано»", mailSiteDocsDir)
	}
	c.siteRows = len(in.siteSites)
	return in, c, nil
}

// readMigrationCorpus — корпус миграций обходом каталога.
func readMigrationCorpus(root string) (check.TreeCorpus, error) {
	dir := filepath.Join(root, filepath.FromSlash(check.MigrationsDirRel))
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("каталог миграций %s: %w", check.MigrationsDirRel, err)
	}
	corpus := check.TreeCorpus{}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".sql") {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		corpus[check.MigrationsDirRel+"/"+e.Name()] = string(body)
	}
	return corpus, nil
}

// mailLaneChartSite — головной комментарий узла `inviteMail` базовых значений.
//
// Предпосылка названа отказом, а не находкой: узел без листа `relay` значит,
// что ключ чарта переименован, и тогда проба судила бы не тот предмет.
func mailLaneChartSite(values []byte) (*mailLaneSite, error) {
	var doc yaml.Node
	if err := yaml.Unmarshal(values, &doc); err != nil {
		return nil, fmt.Errorf("базовые значения чарта не разбираются: %w", err)
	}
	if doc.Kind != yaml.DocumentNode || len(doc.Content) == 0 || doc.Content[0].Kind != yaml.MappingNode {
		return nil, fmt.Errorf("базовые значения чарта — не отображение верхнего уровня")
	}
	top := doc.Content[0]
	for i := 0; i+1 < len(top.Content); i += 2 {
		k, v := top.Content[i], top.Content[i+1]
		if k.Value != mailNodeChartKey {
			continue
		}
		hasRelay := false
		for j := 0; v.Kind == yaml.MappingNode && j+1 < len(v.Content); j += 2 {
			if v.Content[j].Value == mailRelayChartLeaf {
				hasRelay = true
			}
		}
		if !hasRelay {
			return nil, fmt.Errorf("узел %s базовых значений не несёт листа %s — ключ адреса узла "+
				"переименован, и проба судила бы не тот предмет", mailNodeChartKey, mailRelayChartLeaf)
		}
		return &mailLaneSite{where: "deploy/values.yaml: комментарий узла " + mailNodeChartKey, text: k.HeadComment}, nil
	}
	return nil, nil
}

var (
	mdHeadingRe = regexp.MustCompile(`^#{1,6}\s`)
	mdFenceRe   = regexp.MustCompile("^\\s*(```|~~~)")
	htmlTDRe    = regexp.MustCompile(`<td>(.*?)</td>`)
)

// mailLaneDocSites — разделы документа, где строка таблицы объявляет адрес
// узла. Раздел — от заголовка до следующего заголовка любого уровня; строки
// внутри огороженного кода заголовками не считаются (`# …` в примере оболочки
// раздела не открывает).
func mailLaneDocSites(rel, body string) []mailLaneSite {
	type section struct {
		heading string
		lines   []string
	}
	var sections []section
	cur := section{heading: "(до первого заголовка)"}
	inFence := false
	for _, line := range strings.Split(body, "\n") {
		if mdFenceRe.MatchString(line) {
			inFence = !inFence
		}
		if !inFence && mdHeadingRe.MatchString(line) {
			sections = append(sections, cur)
			cur = section{heading: strings.TrimSpace(line)}
			continue
		}
		cur.lines = append(cur.lines, line)
	}
	sections = append(sections, cur)

	var out []mailLaneSite
	for _, s := range sections {
		declares := false
		for _, line := range s.lines {
			if declaresMailRelay(line) {
				declares = true
				break
			}
		}
		if declares {
			out = append(out, mailLaneSite{where: rel + ": " + s.heading, text: strings.Join(s.lines, "\n")})
		}
	}
	return out
}

// declaresMailRelay — объявляет ли строка таблицы адрес узла: первая клетка
// строки Markdown (`| … |`) либо первая <td> строки разметки несёт написание
// адреса кодовым фрагментом.
func declaresMailRelay(line string) bool {
	s := strings.ReplaceAll(strings.TrimSpace(line), "&#95;", "_")
	var first string
	switch {
	case strings.HasPrefix(s, "|"):
		cells := strings.Split(s, "|")
		if len(cells) < 3 {
			return false
		}
		first = cells[1]
	case strings.Contains(s, "<tr>"):
		m := htmlTDRe.FindStringSubmatch(s)
		if m == nil {
			return false
		}
		first = m[1]
	default:
		return false
	}
	for _, sp := range mailRelaySpellings() {
		if strings.Contains(first, "`"+sp+"`") || strings.Contains(first, "<code>"+sp+"</code>") {
			return true
		}
	}
	return false
}

// namesKind — называет ли текст вид кодовым фрагментом с границами.
func namesKind(text, kind string) bool {
	return strings.Contains(text, "`"+kind+"`") || strings.Contains(text, "<code>"+kind+"</code>")
}

// judgeMailLane — САМО СУЖДЕНИЕ. Доказательство способности упасть зовёт его же.
func judgeMailLane(in mailLaneInputs) []string {
	var findings []string
	missing := func(site mailLaneSite) {
		var absent []string
		for _, k := range in.kinds {
			if !namesKind(site.text, k) {
				absent = append(absent, k)
			}
		}
		if len(absent) > 0 {
			findings = append(findings, fmt.Sprintf(
				"%s не называет виды письма %s из %d словаря схемы: ставящий, прочитав это место, "+
					"решит, что узел этим письмам не нужен", site.where, strings.Join(absent, ", "), len(in.kinds)))
		}
	}
	if in.chart == nil {
		findings = append(findings, fmt.Sprintf("в базовых значениях чарта нет узла %s — адрес почтового "+
			"узла чарт не объявляет вовсе", mailNodeChartKey))
	} else {
		missing(*in.chart)
	}
	if len(in.installSites) == 0 {
		findings = append(findings, fmt.Sprintf("%s не объявляет адрес почтового узла ни одной строкой "+
			"таблицы (%s)", mailInstallDoc, strings.Join(mailRelaySpellings(), " | ")))
	}
	if len(in.siteSites) == 0 {
		findings = append(findings, fmt.Sprintf("страницы %s не объявляют адрес почтового узла ни одной "+
			"строкой таблицы (%s): в перечне ручек сайта узла нет", mailSiteDocsDir,
			strings.Join(mailRelaySpellings(), " | ")))
	}
	for _, s := range append(append([]mailLaneSite{}, in.installSites...), in.siteSites...) {
		missing(s)
	}
	sort.Strings(findings)
	return findings
}

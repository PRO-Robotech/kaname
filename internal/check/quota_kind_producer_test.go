// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// quota_kind_producer_test.go — репо-широкий гейт: вид, объявленный в
// ЗАКРЫТОМ каталоге потолков, обязан иметь производителя списания хоть у
// кого-нибудь (задача `PRO-Robotech/kacho#414`).
//
// Порт с монорепо (`internal/repohygiene/quotakindproducer_test.go`, снят
// вынесением службы — `kacho#2597`). Дословно: предикат, словарь недостающих
// частей, обе пробы-доказательства. Изменилось: пакет (`repohygiene` →
// `check_test`), обход дерева.
//
// # ПРЕДМЕТ — КРОСС-СЕРВИСНЫЙ, как и у соседнего `nested_quota_charger_test.go`
//
// Каталог живёт у владельца величин (эта служба), производители списания —
// в миграциях СОСЕДНИХ сервисов, которых в дереве kaname нет. Гейт требует
// ДЕРЕВО ПЛАТФОРМЫ целиком (`platformtree.Require`); в самостоятельном
// клоне — законный пропуск с названной предпосылкой. Довод и родство с
// `nested_quota_charger_test.go` — в её шапке, здесь не пересказывается.
package check_test

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"

	"github.com/PRO-Robotech/corelib/platformmodules"
)

var (
	quotaCatalogueStartRe = regexp.MustCompile(`(?m)^var countableKinds = \[\]CountableKind\{`)
	quotaCatalogueEntryRe = regexp.MustCompile(`\{"([a-zA-Z][a-zA-Z.]*)",`)

	quotaCountCallRe      = regexp.MustCompile(`(?s)kacho_quota_count\s*\(([^)]*)\)`)
	quotaCarrierCallRe    = regexp.MustCompile(`(?s)kacho_quota_carrier_lifecycle\s*\(([^)]*)\)`)
	quotaKindLiteralRe    = regexp.MustCompile(`'([a-zA-Z][a-zA-Z.]*)'`)
	quotaSQLLineCommentRe = regexp.MustCompile(`(?m)^\s*--.*$`)
)

// quotaMissingPiece — ЧЕГО именно не хватает виду. Закрытый словарь, а не проза.
type quotaMissingPiece string

const (
	quotaMissingAccountingTable  quotaMissingPiece = "таблица учёта"
	quotaMissingCountingFunction quotaMissingPiece = "функция счёта"
	quotaMissingKindTrigger      quotaMissingPiece = "списывающий триггер вида"
)

// quotaDebt — запись объявленного долга.
type quotaDebt struct {
	Missing []quotaMissingPiece
	Why     string
}

// kindsWithoutADebitProducer — ОБЪЯВЛЕННЫЙ ДОЛГ. Пуст на день переноса: шесть
// видов службы доступа снялись вместе с каталогом (`kacho#2117`), остаток
// («danger the owner named») закрыт своим списанием.
var kindsWithoutADebitProducer = map[string]quotaDebt{}

// TestEveryCatalogueKindHasADebitProducer — сам гейт.
func TestEveryCatalogueKindHasADebitProducer(t *testing.T) {
	root := platformtree.Require(t)
	ownDir := filepath.Join(root, filepath.FromSlash(platformtree.ModuleDirInPlatform()))

	catalogue := readQuotaCatalogue(t, ownDir)
	if len(catalogue) == 0 {
		t.Fatalf("предпосылка гейта не выполнена: в %s не найдено ни одной записи каталога — "+
			"форма объявления `countableKinds` изменилась, и гейт судит пустоту",
			filepath.Join(ownDir, "internal", "domain", "limit.go"))
	}

	produced, filesRead, servicesSeen := readQuotaDebitProducers(t, root)
	if len(produced) == 0 {
		t.Fatal("предпосылка гейта не выполнена: ни в одной миграции не найдено вызова " +
			"списывающего триггера — форма объявления изменилась, и гейт судит пустоту")
	}

	t.Logf("перепись: видов в каталоге %d; сервисов осмотрено %d; файлов миграций прочитано %d; "+
		"видов со списанием %d; объявленный долг %d",
		len(catalogue), servicesSeen, filesRead, len(produced), len(kindsWithoutADebitProducer))

	var findings []string

	for _, kind := range catalogue {
		if produced[kind] {
			continue
		}
		if _, declared := kindsWithoutADebitProducer[kind]; declared {
			continue
		}
		findings = append(findings, "вид «"+kind+"» объявлен каталогом, но не списывается ничем "+
			"и не стоит в объявленном долге: потолок на него сохраняется, отвечает успехом "+
			"и не применяется никогда")
	}

	for kind, debt := range kindsWithoutADebitProducer {
		if produced[kind] {
			findings = append(findings, "запись долга «"+kind+"» ("+debt.Why+") устарела: "+
				"у вида ПОЯВИЛСЯ производитель списания — снять запись")
		}
	}

	for kind := range kindsWithoutADebitProducer {
		if !listsKind(catalogue, kind) {
			findings = append(findings, "запись долга «"+kind+"» не названа каталогом: "+
				"исключается вид, которого нет, — значит исключение шире своего предмета")
		}
	}

	for kind := range produced {
		if !listsKind(catalogue, kind) {
			findings = append(findings, "вид «"+kind+"» списывается триггером, но каталог его "+
				"НЕ называет: место занимается под потолок, которого не существует")
		}
	}

	for kind, debt := range kindsWithoutADebitProducer {
		if len(debt.Missing) == 0 {
			findings = append(findings, "запись долга «"+kind+"» не называет ни одной "+
				"недостающей части: снять её нечем, потому что нечего проверять")
		}
	}

	mechanisms, mechFiles := readQuotaMechanisms(t, root)
	t.Logf("перепись механизмов учёта: владельцев осмотрено %d; файлов миграций прочитано %d",
		len(mechanisms), mechFiles)
	var piecesJudged, piecesDeferred int
	for kind, debt := range kindsWithoutADebitProducer {
		owner := quotaOwnerDirOfKind(kind)
		present, known := mechanisms[owner]
		if !known {
			findings = append(findings, "запись долга «"+kind+"» указывает на владельца «"+owner+
				"», у которого в дереве нет миграций: причина долга не проверяема")
			continue
		}
		for _, piece := range debt.Missing {
			if _, judged := quotaMechanismPieceProbe[piece]; judged {
				piecesJudged++
			} else {
				piecesDeferred++
			}
		}
		for _, stale := range staleDebtPieces(debt.Missing, present) {
			findings = append(findings, "причина долга «"+kind+"» устарела: она называет "+
				"недостающей часть «"+string(stale)+"», а у владельца «"+owner+
				"» эта часть ЗАВЕДЕНА — недостаёт только вида и его триггера")
		}
	}
	t.Logf("перепись причин долга: записей %d; частей названо %d, из них сверено обходом %d, "+
		"отдано веткам (а)/(б) %d",
		len(kindsWithoutADebitProducer), piecesJudged+piecesDeferred, piecesJudged, piecesDeferred)

	sort.Strings(findings)
	if len(findings) > 0 {
		t.Fatalf("каталог видов и производители списания разошлись (%d):\n  %s",
			len(findings), strings.Join(findings, "\n  "))
	}
}

// TestQuotaKindProducerGate_CanFailAndNamesTheKind — доказательство падучести
// и молчания на законной форме.
func TestQuotaKindProducerGate_CanFailAndNamesTheKind(t *testing.T) {
	const nested = `
DROP TRIGGER IF EXISTS listeners_quota_count ON kacho_nlb.listeners;
CREATE TRIGGER listeners_quota_count
    AFTER INSERT OR DELETE ON kacho_nlb.listeners
    FOR EACH ROW EXECUTE FUNCTION kacho_nlb.kacho_quota_count(
        'loadbalancer.listeners',
        'load_balancer_id',
        'loadbalancer.networkLoadBalancers.listeners');`

	got := quotaKindsInSQL(nested)
	for _, want := range []string{"loadbalancer.listeners", "loadbalancer.networkLoadBalancers.listeners"} {
		if !got[want] {
			t.Fatalf("трёхаргументная форма: вид %q не найден, найдено %v", want, quotaKeysOf(got))
		}
	}
	if got["load_balancer_id"] {
		t.Fatal("имя столбца принято за вид: множество списываемых загрязнено")
	}

	single := quotaKindsInSQL(
		`FOR EACH ROW EXECUTE FUNCTION kacho_vpc.kacho_quota_count('vpc.network');`)
	if !single["vpc.network"] {
		t.Fatalf("однострочная форма перестала читаться: %v", quotaKeysOf(single))
	}

	prose := quotaKindsInSQL(
		`-- вид пишется как kacho_quota_count('vpc.cidrGroup'), а не по памяти`)
	if len(prose) != 0 {
		t.Fatalf("вид, названный в комментарии, принят за производителя: %v", quotaKeysOf(prose))
	}
}

// readQuotaCatalogue достаёт виды из объявления `countableKinds`. ownDir —
// каталог СВОЕГО модуля.
func readQuotaCatalogue(t *testing.T, ownDir string) []string {
	t.Helper()
	path := filepath.Join(ownDir, "internal", "domain", "limit.go")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("каталог видов не прочитан (%s): %v", path, err)
	}
	src := string(b)
	loc := quotaCatalogueStartRe.FindStringIndex(src)
	if loc == nil {
		return nil
	}
	rest := src[loc[1]:]
	if end := strings.Index(rest, "\n}"); end >= 0 {
		rest = rest[:end]
	}
	var out []string
	seen := map[string]bool{}
	for _, m := range quotaCatalogueEntryRe.FindAllStringSubmatch(rest, -1) {
		if !seen[m[1]] {
			seen[m[1]] = true
			out = append(out, m[1])
		}
	}
	sort.Strings(out)
	return out
}

// readQuotaDebitProducers обходит миграции ВСЕХ сервисов платформы (root).
func readQuotaDebitProducers(t *testing.T, root string) (kinds map[string]bool, filesRead, servicesSeen int) {
	t.Helper()
	kinds = map[string]bool{}

	services, err := treecorpus.UnderWithSuffix(filepath.Join(root, "services"), ".sql")
	if err != nil {
		t.Fatalf("состав дерева под services/: %v", err)
	}
	svcSeen := map[string]bool{}
	for _, path := range services {
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		parts := strings.Split(rel, "/")
		if len(parts) < 5 || parts[2] != "internal" || parts[3] != "migrations" {
			continue
		}
		b, ferr := os.ReadFile(path)
		if ferr != nil {
			t.Fatalf("чтение %s: %v", rel, ferr)
		}
		filesRead++
		svcSeen[parts[1]] = true
		for k := range quotaKindsInSQL(string(b)) {
			kinds[k] = true
		}
	}
	return kinds, filesRead, len(svcSeen)
}

// quotaKindsInSQL достаёт виды из объявлений списывающих триггеров.
func quotaKindsInSQL(sql string) map[string]bool {
	sql = quotaSQLLineCommentRe.ReplaceAllString(sql, "")
	out := map[string]bool{}
	for _, re := range []*regexp.Regexp{quotaCountCallRe, quotaCarrierCallRe} {
		for _, call := range re.FindAllStringSubmatch(sql, -1) {
			for _, lit := range quotaKindLiteralRe.FindAllStringSubmatch(call[1], -1) {
				if strings.Contains(lit[1], ".") {
					out[lit[1]] = true
				}
			}
		}
	}
	return out
}

func listsKind(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

func quotaKeysOf(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// quotaMechanismPieceProbe — как часть механизма учёта опознаётся в миграции.
var quotaMechanismPieceProbe = map[quotaMissingPiece]*regexp.Regexp{
	quotaMissingAccountingTable:  regexp.MustCompile(`(?i)CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[a-z_]+\.project_resource_quotas`),
	quotaMissingCountingFunction: regexp.MustCompile(`(?i)CREATE\s+(?:OR\s+REPLACE\s+)?FUNCTION\s+[a-z_]+\.kacho_quota_count`),
}

// quotaOwnerAliasDir — расхождения «первый сегмент вида» ↔ «каталог сервиса».
var quotaOwnerAliasDir = platformmodules.AliasesByCatalogModule()

// quotaOwnerDirOfKind — каталог сервиса-владельца по виду.
func quotaOwnerDirOfKind(kind string) string {
	head := kind
	if i := strings.Index(kind, "."); i >= 0 {
		head = kind[:i]
	}
	if alias, ok := quotaOwnerAliasDir[head]; ok {
		return alias
	}
	return head
}

// staleDebtPieces — части, названные долгом недостающими, которые дерево
// показывает СУЩЕСТВУЮЩИМИ.
func staleDebtPieces(named []quotaMissingPiece, present map[quotaMissingPiece]bool) []quotaMissingPiece {
	var out []quotaMissingPiece
	for _, piece := range named {
		if _, judged := quotaMechanismPieceProbe[piece]; !judged {
			continue
		}
		if present[piece] {
			out = append(out, piece)
		}
	}
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// quotaMechanismInSQL — какие части механизма учёта заводит этот текст.
func quotaMechanismInSQL(sql string) map[quotaMissingPiece]bool {
	sql = quotaSQLLineCommentRe.ReplaceAllString(sql, "")
	out := map[quotaMissingPiece]bool{}
	for piece, re := range quotaMechanismPieceProbe {
		if re.MatchString(sql) {
			out[piece] = true
		}
	}
	return out
}

// readQuotaMechanisms — какие части механизма учёта заведены у каждого владельца.
func readQuotaMechanisms(t *testing.T, root string) (map[string]map[quotaMissingPiece]bool, int) {
	t.Helper()
	out := map[string]map[quotaMissingPiece]bool{}
	filesRead := 0

	paths, err := treecorpus.UnderWithSuffix(filepath.Join(root, "services"), ".sql")
	if err != nil {
		t.Fatalf("состав дерева под services/: %v", err)
	}
	for _, path := range paths {
		rel, rerr := filepath.Rel(root, path)
		if rerr != nil {
			continue
		}
		rel = filepath.ToSlash(rel)
		parts := strings.Split(rel, "/")
		if len(parts) < 5 || parts[2] != "internal" || parts[3] != "migrations" {
			continue
		}
		b, ferr := os.ReadFile(path)
		if ferr != nil {
			t.Fatalf("чтение %s: %v", rel, ferr)
		}
		filesRead++
		svc := parts[1]
		if out[svc] == nil {
			out[svc] = map[quotaMissingPiece]bool{}
		}
		for piece := range quotaMechanismInSQL(string(b)) {
			out[svc][piece] = true
		}
	}
	return out, filesRead
}

// TestQuotaDebtReasonProbe_CanFailAndStaysSilentOnTheGenuineGap — доказательство
// того, что сверка причины долга с деревом способна упасть и что законный
// близнец её не тревожит.
func TestQuotaDebtReasonProbe_CanFailAndStaysSilentOnTheGenuineGap(t *testing.T) {
	const real = `
CREATE TABLE IF NOT EXISTS kaname.project_resource_quotas (
    carrier_type text NOT NULL);
CREATE OR REPLACE FUNCTION kaname.kacho_quota_count()
RETURNS trigger LANGUAGE plpgsql AS $$ BEGIN RETURN NULL; END; $$;`

	present := quotaMechanismInSQL(real)
	if !present[quotaMissingAccountingTable] || !present[quotaMissingCountingFunction] {
		t.Fatalf("разбор не увидел заведённых частей: %v", present)
	}
	stale := staleDebtPieces(
		[]quotaMissingPiece{quotaMissingAccountingTable, quotaMissingCountingFunction, quotaMissingKindTrigger},
		present)
	if len(stale) != 2 {
		t.Fatalf("устаревшими названы %v, а заведены обе части", stale)
	}

	genuine := quotaMechanismInSQL(`ALTER TABLE kacho_geo.zones ADD COLUMN status text;`)
	if got := staleDebtPieces(
		[]quotaMissingPiece{quotaMissingAccountingTable, quotaMissingCountingFunction}, genuine); len(got) != 0 {
		t.Fatalf("настоящий пробел объявлен устаревшим долгом: %v", got)
	}

	prose := quotaMechanismInSQL(
		`-- у владельца нет ни kaname.project_resource_quotas, ни FUNCTION kaname.kacho_quota_count`)
	if len(prose) != 0 {
		t.Fatalf("часть, названная в комментарии, принята за заведённую: %v", prose)
	}

	if got := staleDebtPieces([]quotaMissingPiece{quotaMissingKindTrigger}, present); len(got) != 0 {
		t.Fatalf("триггер вида судится сверкой причины, хотя его предмет у соседа: %v", got)
	}

	if got := quotaOwnerDirOfKind("loadbalancer.listeners"); got != "nlb" {
		t.Fatalf("расхождение имени домена и каталога не учтено: %q", got)
	}
	if got := quotaOwnerDirOfKind("iam.account"); got != "iam" {
		t.Fatalf("владелец вида определён неверно: %q", got)
	}
}

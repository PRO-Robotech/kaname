// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// pack_test.go — общая механика: упаковать ревизию ПРАВИЛАМИ МОДУЛЯ Go и
// собрать распакованное ВНЕ всякого дерева.
//
// Механика одна на предмет и на его инъекцию намеренно. Проба, воспроизводящая
// упаковку своими словами, проверяла бы свою копию, а не то, что исполняется:
// инъекция обязана гонять ТОТ ЖЕ код, иначе она доказывает падучесть двойника.
//
// # Почему упаковка, а не копирование каталога
//
// Посторонний получает ОТСЛЕЖИВАЕМОЕ содержимое ревизии, разложенное по
// правилам модуля Go, — не то, что лежит в рабочем каталоге автора.
// `zip.CreateFromVCS` — та самая функция, которой модуль-прокси формирует зип
// версии; пересказ её правил своими словами проверял бы наш пересказ.
//
// # Почему сборка ЗДЕСЬ, а не у пустого потребителя
//
// Служба — двоичный продукт: её пакеты лежат под `internal/` и внешним
// импортом недостижимы by construction. Утверждение «посторонний соберёт»
// означает здесь «распакованное дерево собирается САМО», а не «его пакет
// импортируется». Это и есть то, что делает посторонний с самостоятельным
// клоном.
package release

import (
	"archive/zip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
)

// maxZipMiB — предел зипа модуля у прокси Go. Число печатается переписью рядом
// с фактическим размером: «влезаем» обязано быть видно числом, а не выводиться
// из молчания пробы.
const maxZipMiB = 500

// packRequest — что упаковать и как собрать.
type packRequest struct {
	vcsRoot    string // каталог с КАТАЛОГОМ .git — упаковывается отслеживаемое
	subdir     string // путь модуля ВНУТРИ репозитория; "" — модуль в корне
	modulePath string // путь публикуемого модуля
	version    string // пусто — псевдоверсия, выведенная из ревизии
	proxyDir   string // непусто — сборка идёт ТОЛЬКО через этот файловый прокси
	modcache   string // непусто — свой кэш модулей (герметичная инъекция)
}

// packResult — исход, разложенный по ТРЁМ категориям, а не по двум.
type packResult struct {
	revision   string
	filesInZip int
	zipBytes   int64
	packages   int    // пакетов в распакованном дереве
	unmet      string // непусто — УСЛОВИЕ НЕ СОЗДАНО (третья категория)
	err        error  // отказ упаковки, распаковки либо сборки
	output     string // захваченный вывод инструмента — диагностика, а не пересказ
}

// packAndBuildStandalone — упаковать `subdir` ревизии и собрать распакованное.
//
// Кэш модулей по умолчанию ОБЩИЙ (тот, что у запускающего), и это решение, а не
// упущение: зависимости — обычное дело потребителя, а их достижимость ведёт
// своя задача. Свой кэш здесь означал бы скачивание всего графа на каждый
// прогон, то есть пробу, измеряющую наличие сети. Герметичность нужна инъекции,
// и она её просит явно (`modcache` + `proxyDir`).
func packAndBuildStandalone(t *testing.T, req packRequest) packResult {
	t.Helper()

	var res packResult
	env := cleanGitEnv()

	// Инструмент — ТОТ ЖЕ, которым собран этот тест. Иначе `GOTOOLCHAIN=local`
	// поднимет системный go, а он может быть старше, чем требует объявление
	// модуля, и проба покраснела бы на версии инструмента, а не на предмете.
	goroot := strings.TrimSpace(runOut(t, env, "", "go", "env", "GOROOT"))
	goBin := filepath.Join(goroot, "bin", "go")

	res.revision = strings.TrimSpace(gitOut(t, env, req.vcsRoot, "rev-parse", "HEAD"))
	if len(res.revision) < 12 {
		t.Fatalf("ревизия не прочитана в %s", req.vcsRoot)
	}
	version := req.version
	if version == "" {
		version = "v0.0.0-20000101000000-" + res.revision[:12]
	}

	work := outsideAnyRepository(t)
	zipPath := filepath.Join(work, "module.zip")
	files, size, packErr := packZip(t, zipPath, req, version)
	res.filesInZip, res.zipBytes = files, size
	if packErr != nil {
		res.err = packErr
		res.output = "упаковка ревизии " + res.revision[:12] + " отвергнута правилами модуля Go"
		return res
	}

	// Распаковка ТЕМИ ЖЕ правилами: посторонний получает ровно это дерево.
	tree := filepath.Join(work, "tree")
	if err := modzip.Unzip(tree, module.Version{Path: req.modulePath, Version: version}, zipPath); err != nil {
		res.err = err
		res.output = "распаковка зипа модуля отвергнута правилами модуля Go"
		return res
	}

	consEnv := append(env,
		"GOWORK=off",              // объемлющее рабочее пространство не видно постороннему
		"GOFLAGS=-buildvcs=false", // и унаследованные флаги тоже сняты
		"GOTOOLCHAIN=local",
	)
	if req.proxyDir != "" {
		consEnv = append(consEnv,
			"GOPROXY=file://"+filepath.ToSlash(req.proxyDir),
			"GOFLAGS=-mod=mod -buildvcs=false",
			"GOSUMDB=off",
			"GONOSUMDB=",
			"GOPRIVATE=",
		)
	}
	if req.modcache != "" {
		consEnv = append(consEnv, "GOMODCACHE="+req.modcache)
		// Кэш модулей раскладывается ТОЛЬКО ДЛЯ ЧТЕНИЯ, и уборка каталога его
		// снести не может. Регистрируется ПОСЛЕ выдачи каталога, поэтому
		// исполняется РАНЬШЕ её — иначе проба краснеет на уборке при исправном
		// предмете.
		t.Cleanup(func() {
			if _, err := os.Stat(req.modcache); err == nil {
				c := exec.Command(goBin, "clean", "-modcache")
				c.Env = append(cleanGitEnv(), "GOMODCACHE="+req.modcache, "GOTOOLCHAIN=local", "GOFLAGS=")
				_ = c.Run()
			}
		})
	}

	var sb strings.Builder
	run := func(args ...string) (string, error) {
		cmd := exec.Command(goBin, args...) // #nosec G204 -- аргументы из этой пробы
		cmd.Dir = tree
		cmd.Env = consEnv
		out, err := cmd.CombinedOutput()
		sb.WriteString("$ go " + strings.Join(args, " ") + "\n")
		sb.Write(out)
		return string(out), err
	}

	// ШАГ 1 — достижимость зависимостей. Её отказ бывает ДВУХ РОДОВ, и
	// складывать их нельзя: до прокси нет сети — это «условие не создано», а
	// любой другой отказ (подмена пути, неполное объявление модуля) — находка.
	if out, err := run("mod", "download"); err != nil {
		if why := unmetReason(out); why != "" {
			res.unmet = why
			res.output = sb.String()
			return res
		}
		res.err = err
		res.output = sb.String()
		return res
	}

	// ШАГ 2 — перепись. Считается ОТДЕЛЬНО от вердикта (`-e` не роняет обход на
	// битом импорте), чтобы «пакетов 0» было отличимо от «пакеты не считали».
	if out, err := run("list", "-e", "./..."); err == nil {
		for _, line := range strings.Split(strings.TrimSpace(out), "\n") {
			if strings.TrimSpace(line) != "" {
				res.packages++
			}
		}
	}

	// ШАГ 3 — вердикт. Зависимости уже на диске, значит отказ здесь говорит о
	// СОДЕРЖИМОМ упакованного дерева, а не о сети.
	if _, err := run("build", "./..."); err != nil {
		res.err = err
	}
	res.output = sb.String()
	return res
}

// packZip — упаковка `subdir` ревизии в файл `dst` и её перепись.
func packZip(t *testing.T, dst string, req packRequest, version string) (int, int64, error) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		t.Fatalf("каталог зипа не создан: %v", err)
	}
	zf, err := os.Create(dst) // #nosec G304 -- путь выдан этой пробой
	if err != nil {
		t.Fatalf("зип не создан: %v", err)
	}
	mv := module.Version{Path: req.modulePath, Version: version}
	packErr := modzip.CreateFromVCS(zf, mv, req.vcsRoot, "HEAD", req.subdir)
	closeErr := zf.Close()
	if packErr != nil {
		return 0, 0, packErr
	}
	if closeErr != nil {
		t.Fatalf("зип не закрыт: %v", closeErr)
	}

	var size int64
	if st, statErr := os.Stat(dst); statErr == nil {
		size = st.Size()
	}
	files := 0
	if zr, openErr := zip.OpenReader(dst); openErr == nil {
		files = len(zr.File)
		_ = zr.Close()
	}
	return files, size, nil
}

// publishToProxy — положить упакованный модуль в файловый прокси.
//
// Нужно инъекции: она заводит ДВА модуля, чтобы зависимость службы резолвилась
// ПИНОМ, а не подменой пути, и делала это без сети.
func publishToProxy(t *testing.T, proxyDir string, req packRequest, version string) {
	t.Helper()
	esc, err := module.EscapePath(req.modulePath)
	if err != nil {
		t.Fatalf("путь модуля не экранируется: %v", err)
	}
	verDir := filepath.Join(proxyDir, filepath.FromSlash(esc), "@v")
	if err := os.MkdirAll(verDir, 0o755); err != nil {
		t.Fatalf("каталог прокси не создан: %v", err)
	}
	if _, _, packErr := packZip(t, filepath.Join(verDir, version+".zip"), req, version); packErr != nil {
		t.Fatalf("модуль зависимости не упакован: %v", packErr)
	}

	// `.mod` прокси обязан быть объявлением ИМЕННО ЭТОЙ ревизии: расхождение с
	// тем, что лежит в зипе, инструмент отвергает — и отвергает верно.
	src := filepath.Join(req.vcsRoot, filepath.FromSlash(req.subdir), "go.mod")
	gomod, err := os.ReadFile(src) // #nosec G304 -- путь выдан этой пробой
	if err != nil {
		t.Fatalf("объявление модуля не прочитано (%s): %v", src, err)
	}
	write(t, filepath.Join(verDir, version+".mod"), string(gomod))
	write(t, filepath.Join(verDir, version+".info"),
		`{"Version":"`+version+`","Time":"2000-01-01T00:00:00Z"}`)
	write(t, filepath.Join(verDir, "list"), version+"\n")
}

// unmetReason — отличить «до прокси нет сети» от находки о дереве.
//
// Требуются ДВА признака сразу: фраза инструмента о том, что он ходил за
// модулем, И причина транспортного уровня. Одного первого мало — та же фраза
// выходит на опечатке в адресе, а это НАША поломка и повтором не лечится.
//
// Ответ прокси «такой версии нет» третьей категорией НЕ считается: это ответ, а
// не отсутствие связи, и его предмет — разрешимость пина, у которой свой
// держатель.
func unmetReason(out string) string {
	// Отключённый поиск модулей — объявленный выбор запускающего, и он сам по
	// себе означает «сети нет».
	if strings.Contains(out, "module lookup disabled") {
		return "поиск модулей отключён настройкой прокси"
	}
	fetching := []string{"module lookup", "downloading", `Get "http`, "GOPROXY", "go.mod: module"}
	transport := []string{
		"dial tcp", "no such host", "connection refused", "network is unreachable",
		"i/o timeout", "TLS handshake timeout", "connection reset by peer",
		"server misbehaving", "proxyconnect tcp",
	}
	sawFetch := false
	for _, m := range fetching {
		if strings.Contains(out, m) {
			sawFetch = true
			break
		}
	}
	if !sawFetch {
		return ""
	}
	for _, m := range transport {
		if strings.Contains(out, m) {
			return "до прокси модулей нет сети: " + m
		}
	}
	return ""
}

// outsideAnyRepository — рабочий каталог, о котором доказано, что он не лежит
// внутри репозитория.
//
// Довод не гигиенический: инструмент, заводящий дерево, ищет `.git` ОБХОДОМ
// ВВЕРХ. Каталог внутри репозитория даёт вердикт о ЧУЖОМ дереве, и выглядит он
// как обычное красное. Предпосылка не выполняется — это ПРОПУСК с названной
// причиной, а не находка.
func outsideAnyRepository(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for cur := dir; ; {
		if _, err := os.Stat(filepath.Join(cur, ".git")); err == nil {
			t.Skipf("УСЛОВИЕ НЕ СОЗДАНО (не находка): временный каталог лежит внутри "+
				"репозитория %s — вердикт был бы о ТОМ дереве. Назовите TMPDIR вне "+
				"всякого дерева и на диске", cur)
		}
		parent := filepath.Dir(cur)
		if parent == cur {
			return dir
		}
		cur = parent
	}
}

// moduleRoot — поднимаемся до каталога с объявлением модуля.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatalf("объявление модуля не найдено выше %s", dir)
		}
		dir = parent
	}
}

func modulePathOf(t *testing.T, root string) string {
	t.Helper()
	raw, err := os.ReadFile(filepath.Join(root, "go.mod")) // #nosec G304 -- корень своего модуля
	if err != nil {
		t.Fatalf("объявление модуля не прочитано: %v", err)
	}
	for _, line := range strings.Split(string(raw), "\n") {
		if f := strings.Fields(line); len(f) >= 2 && f[0] == "module" {
			return f[1]
		}
	}
	t.Fatalf("в объявлении модуля нет строки module")
	return ""
}

// cleanGitEnv — окружение без унаследованных GIT_*.
//
// Унаследованный GIT_DIR сильнее рабочего каталога: без снятия действия пробы
// уезжают в индекс той копии, из которой она запущена, и портят чужое
// состояние. Перечень переменных объявлен ОДИН РАЗ — в общем помощнике; своя
// копия перечня разошлась бы с ним молча.
func cleanGitEnv() []string {
	return gitenv.Env()
}

func write(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("файл не записан (%s): %v", path, err)
	}
}

func runOut(t *testing.T, env []string, dir string, name string, args ...string) string {
	t.Helper()
	cmd := exec.Command(name, args...) // #nosec G204 -- аргументы из этой пробы
	cmd.Dir = dir
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", name, args, err, out)
	}
	return string(out)
}

func gitOut(t *testing.T, env []string, dir string, args ...string) string {
	t.Helper()
	cmd := gitenv.Command(dir, args...)
	cmd.Env = env
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("git %v в %s: %v\n%s", args, dir, err, out)
	}
	return string(out)
}

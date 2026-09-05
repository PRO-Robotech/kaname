// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package authzformbench

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/PRO-Robotech/kacho/pkg/gitenv"
)

// ОТПЕЧАТОК ПРИБОРА — «ИЗМЕНИЛОСЬ ЛИ ТО, ЧЕМ МЕРИЛИ»
//
// # Зачем
//
// На числах этого прибора стоит обоснование целой под-фазы. Отчёт, снятый на
// дереве, которого больше нет, — утверждение о прошлом, поданное как
// утверждение о настоящем; по самому отчёту это неразличимо, он выглядит
// одинаково в обоих случаях.
//
// # Почему отпечаток, а не «ревизия отчёта — предок вершины»
//
// Здесь вливают СХЛОПЫВАНИЕМ: squash рождает новый хеш, и записанная в шапке
// ревизия предком вершины не становится НИКОГДА. Гейт с таким плечом краснел бы
// на КАЖДОМ вливании, включая то, которым отчёт и приезжает.
//
// # Почему СВОЯ реализация, а не общая со `scalegrid`
//
// Не по вкусу, а по двум измеренным причинам:
//
//	(1) язык не даёт: отпечаток `scalegrid` живёт в
//	    `services/iam/internal/repo/kacho/pg/scalegrid` — внутреннем пакете
//	    сервиса, и `tools/` его импортировать не может;
//	(2) вынести общее в корневой `internal/` тоже нельзя ЗАДАРОМ: предмет
//	    отпечатка `scalegrid` — содержимое СВОЕГО каталога, и перенос файла из
//	    него изменил бы его собственный отпечаток состава, покраснив гейт
//	    полной сетки и потребовав 120-минутного перепрогона.
//
// Риск расхождения двух реализаций ограничен by construction: каждая сторожит
// СВОИ отчёты, ни одна не читает шапку чужих, и внутри этого пакета отпечаток
// считает ТА ЖЕ функция, что пишет его в шапку.
//
// # ПОЧЕМУ МНОЖЕСТВО ВЫВОДИТСЯ, А ЕГО СОСТАВ ВХОДИТ В ХЭШ
//
// Выписанный перечень не двигается от НОВОГО файла: положи в каталог прибора
// ещё один .go, меняющий замер, — содержимое прежних не изменится, отпечаток
// совпадёт, и гейт промолчит ровно там, где обязан заговорить. Поэтому хэшей
// ДВА: по составу (появление и исчезновение файла) и по содержимому (правка
// существующего). Разделены затем, чтобы гейт мог НАЗВАТЬ, что сдвинулось.

// benchDir — каталог прибора; его содержимое и есть предмет.
const benchDir = "services/iam/tools/authzformbench"

// FingerprintPredicate — предикат печатается В ШАПКУ рядом с отпечатком, чтобы
// читатель мог его ПОВТОРИТЬ и оспорить, а не поверить шестнадцати знакам хэша.
//
// Отличие от предиката `scalegrid` названо прямо: там под отпечаток идут только
// НЕ-тестовые файлы, здесь — ВСЕ. Причина в устройстве прибора: харнесс, задающий
// сценарий, размер страницы и число повторов, живёт именно в `_test.go`
// (`run_test.go`, `harness_test.go`), и замер, снятый другим харнессом, — другой
// замер. Исключив их, отпечаток молчал бы на смене того, ЧТО мерили.
const FingerprintPredicate = `все .go каталога ` + benchDir +
	` — включая _test.go: харнесс прогона (сценарий, размер страницы, повторы) живёт в них,` +
	` и замер, снятый другим харнессом, — другой замер`

// Fingerprint — отпечаток предмета замера.
type Fingerprint struct {
	// Composition — хэш отсортированного СПИСКА путей.
	Composition string
	// Content — хэш содержимого файлов в том же порядке.
	Content string
	// Files — сами пути, для сообщения гейта.
	Files []string
	// Predicate — ЧТО именно взято под отпечаток, словами.
	Predicate string
}

// ComputeFingerprint — отпечаток по дереву под root.
func ComputeFingerprint(root string) (Fingerprint, error) {
	return fingerprintFrom(root, benchGoFiles, readFileAt)
}

// fingerprintFrom — та же арифметика над ЛЮБЫМ источником содержимого.
//
// Источник параметром, а не `os.ReadFile` внутри: инъекция иначе не
// воспроизводима — «файл правлен» на настоящем дереве пришлось бы устраивать
// правкой настоящего дерева.
func fingerprintFrom(root string,
	list func(root string) ([]string, error),
	read func(root, rel string) ([]byte, error)) (Fingerprint, error) {
	fp := Fingerprint{Predicate: FingerprintPredicate}

	files, err := list(root)
	if err != nil {
		return fp, err
	}
	sort.Strings(files)
	fp.Files = files

	ch := sha256.New()
	for _, rel := range files {
		ch.Write([]byte(rel + "\n"))
	}
	fp.Composition = hex.EncodeToString(ch.Sum(nil))[:16]

	bh := sha256.New()
	for _, rel := range files {
		body, rerr := read(root, rel)
		if rerr != nil {
			return fp, fmt.Errorf("authzformbench: чтение %s: %w", rel, rerr)
		}
		bh.Write(body)
	}
	fp.Content = hex.EncodeToString(bh.Sum(nil))[:16]
	return fp, nil
}

// ContentOf — отпечаток содержимого ОДНОГО файла; гейт называет им виновника.
func ContentOf(root, rel string) string {
	body, err := readFileAt(root, rel)
	if err != nil {
		return "нечитаем"
	}
	sum := sha256.Sum256(body)
	return hex.EncodeToString(sum[:])[:16]
}

func readFileAt(root, rel string) ([]byte, error) {
	return os.ReadFile(filepath.Join(root, rel)) // #nosec G304 -- rel получен обходом СОБСТВЕННОГО каталога прибора под корнем репозитория, не из запроса и не от пользователя: прибор читает свои же файлы, чтобы взять их отпечаток
}

func benchGoFiles(root string) ([]string, error) {
	entries, err := os.ReadDir(filepath.Join(root, benchDir))
	if err != nil {
		return nil, fmt.Errorf("authzformbench: состав %s: %w", benchDir, err)
	}
	var out []string
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") {
			continue
		}
		out = append(out, benchDir+"/"+name)
	}
	return out, nil
}

// Marker* — приставки строк отпечатка в шапке. Читает их гейт, поэтому они
// объявлены здесь, рядом с писателем: разъехавшись, писатель и читатель дали бы
// «отпечаток не найден» на исправном отчёте.
const (
	MarkerComposition = "отпечаток прибора: состав     "
	MarkerContent     = "отпечаток прибора: содержимое "
	MarkerPredicate   = "отпечаток прибора: предикат   "
	MarkerFileList    = "ФАЙЛЫ ПОД ОТПЕЧАТКОМ ПРИБОРА (пофайлово, чтобы гейт назвал ВИНОВНИКА, а не только факт)"
	MarkerFile        = "    "
)

// FingerprintLines — строки отпечатка для шапки отчёта.
//
// Пофайлово, а не одним числом: гейт, знающий только итоговый хэш, умеет сказать
// «что-то сдвинулось» и не умеет сказать ЧТО — а находка без координаты требует
// от читателя той же работы заново.
func (fp Fingerprint) FingerprintLines(root string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%s%s\n", MarkerComposition, fp.Composition)
	fmt.Fprintf(&b, "%s%s\n", MarkerContent, fp.Content)
	predicate := fp.Predicate
	if predicate == "" {
		predicate = FingerprintPredicate
	}
	fmt.Fprintf(&b, "%s%s\n", MarkerPredicate, predicate)
	fmt.Fprintf(&b, "%s\n", MarkerFileList)
	for _, rel := range fp.Files {
		fmt.Fprintf(&b, "%s%s  %s\n", MarkerFile, ContentOf(root, rel), rel)
	}
	return b.String()
}

// FingerprintHeader — то, что печатает КАЖДЫЙ писатель отчёта.
//
// Корень спрашивается у git, а не собирается из `..`: число шагов вверх зависит
// от того, откуда прогон запущен, и переезд вызывающего молча увёл бы отпечаток
// считать чужой каталог.
//
// Отказ печатается СТРОКОЙ В ОТЧЁТ, а не глотается: отчёт без отпечатка обязан
// говорить, почему его нет, — иначе гейт увидит «шапки нет» и не отличит
// «прибор не смог» от «отчёт древний».
func FingerprintHeader() string {
	root, err := RepoRoot()
	if err != nil {
		return fmt.Sprintf("%sНЕ ВЗЯТ: корень дерева не установлен (%v)\n", MarkerContent, err)
	}
	fp, err := ComputeFingerprint(root)
	if err != nil {
		return fmt.Sprintf("%sНЕ ВЗЯТ: %v\n", MarkerContent, err)
	}
	return fp.FingerprintLines(root)
}

// RepoRoot — корень дерева, спрошенный у git.
//
// Через `pkg/gitenv`, а не прямым `exec.Command("git", …)`: унаследованные
// `GIT_DIR`/`GIT_INDEX_FILE` увели бы команду в чужой репозиторий — это находка
// отдельного гейта дерева.
func RepoRoot() (string, error) {
	out, err := gitenv.Command("", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(out)), nil
}

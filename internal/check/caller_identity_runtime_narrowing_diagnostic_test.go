// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package check_test

import (
	"bytes"
	"crypto/sha256"
	"encoding/json"
	"flag"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// Только scripts/registered-check-pair.py запускает отдельную ногу. Один
// успешный процесс не даёт сравнительного вердикта.
func callerNarrowingDiagnostic(t *testing.T, root, phase string) {
	t.Helper()
	run := flag.Lookup("test.run")
	pair := os.Getenv("KANAME_REGISTERED_CHECK_PAIR")
	if (phase != "lawful" && phase != "missing_row") || pair == "" || run == nil ||
		run.Value.String() != "^"+t.Name()+"$/^"+phase+"$" {
		t.Fatal("ожидались отдельный точный селектор Check и идентификатор пары")
	}
	t.Run(phase, func(t *testing.T) {
		fixture := root
		if phase == "missing_row" {
			fixture = callerMissingCheckRow(t, root)
		}
		before := callerCheckFixtureDigest(t, fixture)
		where := callerCheckCoordinate(t, fixture)
		if phase == "lawful" {
			callerCheckFrontControls(t, fixture)
		}
		ctx, cancel := callerFullTreeTestContext(t)
		defer cancel()
		witness := callerCheckWitness(t, ctx, fixture, phase)
		if phase == "lawful" {
			callerLawfulCheckFindings(t, witness, where)
		}
		if before != callerCheckFixtureDigest(t, fixture) {
			t.Fatal("дерево близнеца изменилось во время наблюдения")
		}
		report := struct {
			Schema        int
			Phase         string
			Pair          string
			RPC           string
			Producer      string
			Coordinate    string
			FixtureSHA256 string
			TableSHA256   string
			Reads         []check.CallerIdentityRead
			Findings      []string
		}{
			Schema: 1, Phase: phase, Pair: pair, RPC: narrowingRPC, Producer: narrowingProducer,
			Coordinate: where, FixtureSHA256: before.tree, TableSHA256: before.table,
			Reads: append([]check.CallerIdentityRead{}, witness.Reads...), Findings: append([]string{}, witness.Findings...),
		}
		data, err := json.Marshal(report)
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("REGISTERED_CHECK_OBSERVATION %s", data)
	})
}

// Хеш всех путей, режимов git и содержимого проверяет весь фактический вход
// обхода. По окончании custodian независимо вычисляет обе суммы из checkout.
type callerCheckFixture struct {
	tree, table, otherFiles, tableWithoutCheck string
}

func callerCheckFixtureDigest(t *testing.T, root string) callerCheckFixture {
	t.Helper()
	var rows []string
	var fixture callerCheckFixture
	err := fs.WalkDir(os.DirFS(root), ".", func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if path == ".git" {
			if entry.IsDir() {
				return fs.SkipDir
			}
			return nil
		}
		if entry.IsDir() {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		name := filepath.Join(root, filepath.FromSlash(path))
		mode := "100644"
		var data []byte
		switch {
		case info.Mode()&fs.ModeSymlink != 0:
			mode = "120000"
			target, err := os.Readlink(name)
			if err != nil {
				return err
			}
			data = []byte(target)
		case info.Mode().IsRegular():
			if info.Mode()&0100 != 0 {
				mode = "100755"
			}
			data, err = os.ReadFile(name)
			if err != nil {
				return err
			}
		default:
			return fmt.Errorf("неподдерживаемый тип входа %s", path)
		}
		sum := fmt.Sprintf("%x", sha256.Sum256(data))
		if path == narrowingTable {
			fixture.table = sum
			row := []byte(narrowingCheckRow)
			if bytes.Count(data, row) == 1 {
				fixture.tableWithoutCheck = fmt.Sprintf("%x", sha256.Sum256(bytes.Replace(data, row, nil, 1)))
			}
		}
		rows = append(rows, path+"\x00"+mode+"\x00"+sum+"\n")
		return nil
	})
	if err != nil || fixture.table == "" {
		t.Fatalf("проверка дерева близнеца: %v, таблица %q", err, fixture.table)
	}
	slices.Sort(rows)
	fixture.tree = fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(rows, ""))))
	otherFiles := slices.DeleteFunc(rows, func(row string) bool { return strings.HasPrefix(row, narrowingTable+"\x00") })
	fixture.otherFiles = fmt.Sprintf("%x", sha256.Sum256([]byte(strings.Join(otherFiles, ""))))
	return fixture
}

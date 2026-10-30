// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migration_version_monotonic_base_injection_test.go — доказательство, что гейт
// монотонности сравнивает добавленное с БАЗОЙ ЗАПРОСА, а не только со стволом
// (задача PRO-Robotech/kaname#618).
//
// # Предмет
//
// Волна вливается в ветку эпика, полоса — в ветку волны, и только эпик — в
// ствол. Миграция полосы, чей номер ниже уже лежащей в базе запроса, на стволе
// не видна: там старшей ещё нет. Замер волны-4 (kaname#538): версия
// `20261005024608` ветки #344 ниже `…032942` и `…040457` ветки эпика, а гейт
// на #344 был зелёным.
//
// Вторая слепота той же природы — ВЕРШИНА базы. Состав рабочего дерева взят на
// точке ответвления, а база с тех пор ушла вперёд: старшая, легшая в базу ПОСЛЕ
// ответвления, в дереве самой ветки не лежит вовсе (а хук отправки и локальный
// прогон судят именно её). Поэтому база читается по её ВЕРШИНЕ, а не по
// общему предку.
//
// # Как построена проба
//
// Синтетический репозиторий во временном каталоге повторяет форму, в которой
// живой гейт видит ветку на конвейере: ствол `origin/main`, база запроса
// `origin/<ветка>`, рабочая вершина — ветка полосы, ответвлённая от базы ДО того,
// как в базу легла старшая. Проба зовёт ТОТ ЖЕ путь, что живой гейт
// (runMonotonicGate), с подменённым окружением — без своей копии выбора базы.
//
// Пары однофактные:
//
//	номер полосы  · N-1 против N+1 при одной и той же базе — красное и молчание;
//	база названа  · та же полоса N-1 с названной базой и без неё — красное и
//	                молчание; молчание без базы и есть прежняя слепота, и оно
//	                печатает, что база не названа;
//	база в клоне  · названная база, которой в клоне нет, против разрешимой —
//	                отказ предпосылки против вердикта, а не откат на ствол;
//	вершина ствола· номер ниже легшей в ствол после ответвления против номера
//	                выше неё — красное и молчание.
package check_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/gitenv"
	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/check"
)

const (
	// injBaseNeighbour — старшая базы запроса: легла в ветку эпика ПОСЛЕ того,
	// как от неё ответвилась полоса. Номер — из замера волны-4.
	injBaseNeighbour = "20261005032942_neighbour_lane_landed_in_the_epic.sql"
	// injBaseLaneBelow и injBaseLaneAbove отличаются РОВНО ОДНИМ фактом —
	// секундой метки: N-1 и N+1 относительно старшей базы.
	injBaseLaneBelow = "20261005032941_lane_migration.sql"
	injBaseLaneAbove = "20261005032943_lane_migration.sql"
	// injTrunkAhead — легла в ствол после ответвления эпика; выше старшей базы.
	injTrunkAhead       = "20261005050000_trunk_moved_ahead.sql"
	injTrunkLaneBelow   = "20261005045959_lane_migration.sql"
	injTrunkLaneAbove   = "20261005050001_lane_migration.sql"
	injBaseRequestName  = "epic"
	injBaseApplied      = "20261005010000_applied_everywhere.sql"
	injBaseBaselineName = "0001_initial.sql"
)

// injEnv — окружение прогона, в котором база запроса названа значением value;
// пустое value — база не названа (отправка в ствол, ручной запуск).
func injEnv(value string) func(string) string {
	return func(k string) string {
		if k == "GITHUB_BASE_REF" {
			return value
		}
		return ""
	}
}

// buildWaveRepo — синтетический репозиторий формы конвейера. laneMigration —
// миграция, которую добавляет полоса; trunkAhead — миграция, легшая в ствол
// после ответвления эпика (пустая — ствол стоит).
func buildWaveRepo(t *testing.T, laneMigration, trunkAhead string) (string, []string) {
	t.Helper()
	dir := t.TempDir()
	env := append(gitenv.Env(),
		"GIT_AUTHOR_NAME=probe", "GIT_AUTHOR_EMAIL=probe@invalid",
		"GIT_COMMITTER_NAME=probe", "GIT_COMMITTER_EMAIL=probe@invalid")
	git := func(args ...string) {
		t.Helper()
		c := gitenv.Command(dir, args...)
		c.Env = env
		if out, err := c.CombinedOutput(); err != nil {
			t.Fatalf("проба НЕ ИСПОЛНЯЛАСЬ: git %v: %v\n%s", args, err, out)
		}
	}
	write := func(name string) {
		t.Helper()
		rel := check.MigrationsDirRel + "/" + name
		abs := filepath.Join(dir, filepath.FromSlash(rel))
		require.NoError(t, os.MkdirAll(filepath.Dir(abs), 0o750))
		require.NoError(t, os.WriteFile(abs, []byte("-- "+name+"\n"), 0o600))
		git("add", rel)
	}

	git("init", "--quiet", "-b", "main", ".")
	write(injBaseBaselineName)
	write(injBaseApplied)
	git("commit", "--quiet", "-m", "ствол")

	git("checkout", "--quiet", "-b", injBaseRequestName)
	git("checkout", "--quiet", "-b", "lane")
	write(laneMigration)
	git("commit", "--quiet", "-m", "полоса")

	git("checkout", "--quiet", injBaseRequestName)
	write(injBaseNeighbour)
	git("commit", "--quiet", "-m", "соседняя полоса легла в эпик")

	if trunkAhead != "" {
		git("checkout", "--quiet", "main")
		write(trunkAhead)
		git("commit", "--quiet", "-m", "ствол ушёл вперёд")
	}

	// Ссылки — той же формы, что у клона конвейера с полной выборкой.
	git("update-ref", "refs/remotes/origin/main", "main")
	git("update-ref", "refs/remotes/origin/"+injBaseRequestName, injBaseRequestName)
	git("checkout", "--quiet", "lane")

	var dirFiles []string
	for _, rel := range gateTree(t, dir).tree.SortedFiles() {
		if strings.HasPrefix(rel, check.MigrationsDirRel+"/") {
			dirFiles = append(dirFiles, rel)
		}
	}
	require.NotEmptyf(t, dirFiles, "проба НЕ ИСПОЛНЯЛАСЬ: индекс синтетического дерева пуст")
	return dir, dirFiles
}

// runInjected — путь живого гейта на синтетическом дереве; отказ предпосылки
// и «условие не создано» возвращаются как есть.
func runInjected(t *testing.T, laneMigration, trunkAhead, baseRef string) (monotonicRun, string, error) {
	t.Helper()
	dir, dirFiles := buildWaveRepo(t, laneMigration, trunkAhead)
	return runMonotonicGate(t, dir, dirFiles, injEnv(baseRef))
}

func TestMigrationMonotonicBase_LaneBelowTheRequestBaseIsRed(t *testing.T) {
	t.Parallel()
	run, notCreated, premise := runInjected(t, injBaseLaneBelow, "", injBaseRequestName)
	require.NoError(t, premise)
	require.Empty(t, notCreated)

	require.Lenf(t, run.audit.Findings, 1,
		"полоса добавила N-1 при старшей N в базе запроса — находка обязана быть одна; "+
			"перепись: %s; база: %s", run.audit.Census, run.said)
	finding := run.audit.Findings[0]
	// Обе координаты: добавленное полосой и старшая базы вместе с её ссылкой.
	require.Contains(t, finding, check.MigrationsDirRel+"/"+injBaseLaneBelow)
	require.Contains(t, finding, injBaseNeighbour)
	require.Contains(t, finding, "origin/"+injBaseRequestName)
	require.Contains(t, run.said, "origin/"+injBaseRequestName,
		"перепись обязана назвать, с какой базой сравнивали")
}

func TestMigrationMonotonicBase_LaneAboveTheRequestBaseIsSilent(t *testing.T) {
	t.Parallel()
	run, notCreated, premise := runInjected(t, injBaseLaneAbove, "", injBaseRequestName)
	require.NoError(t, premise)
	require.Empty(t, notCreated)

	require.Emptyf(t, run.audit.Findings, "законный близнец N+1 обязан молчать; перепись: %s",
		run.audit.Census)
	// Молчание — ВЕРДИКТ, а не «сравнивать не с чем».
	require.Equal(t, check.MigrationVersionJudged, run.audit.Outcome)
	require.Equal(t, 1, run.audit.Census.Compared)
	require.Contains(t, run.said, "origin/"+injBaseRequestName)
}

func TestMigrationMonotonicBase_UnnamedBaseIsTheTrunkAndSaysSo(t *testing.T) {
	t.Parallel()
	// Та же полоса N-1, что у красной пробы; отличается ОДНИМ фактом — база
	// запроса не названа. На стволе старшей эпика нет, и молчание здесь верно:
	// гейт судит то, что ему назвали, и ГОВОРИТ, что назвали ствол.
	run, notCreated, premise := runInjected(t, injBaseLaneBelow, "", "")
	require.NoError(t, premise)
	require.Empty(t, notCreated)

	require.Empty(t, run.audit.Findings)
	require.Contains(t, run.said, trunkRefName)
	require.Contains(t, run.said, "не названа")
}

func TestMigrationMonotonicBase_NamedBaseAbsentIsARefusalNotTheTrunk(t *testing.T) {
	t.Parallel()
	// Отличается от красной пробы ОДНИМ фактом — названа ветка, которой в
	// клоне нет. Откат на ствол дал бы здесь молчание (старшей на стволе нет) —
	// ровно то, что задача запрещает.
	run, notCreated, premise := runInjected(t, injBaseLaneBelow, "", "absent-line")
	require.Errorf(t, premise, "названная база, которой в клоне нет, — отказ предпосылки; "+
		"получено: условие=%q, база=%q, находок %d", notCreated, run.said, len(run.audit.Findings))
	require.Contains(t, premise.Error(), "origin/absent-line")
	require.Empty(t, run.audit.Findings)
	require.Empty(t, run.said, "вердикта при отказе предпосылки нет — и базы у него тоже")
}

func TestMigrationMonotonicBase_LaneBelowTheTrunkTipIsRed(t *testing.T) {
	t.Parallel()
	// Ствол ушёл вперёд после ответвления эпика. Полоса в эпик добавляет номер
	// ниже легшей в ствол: после посадки эпика она встанет раньше неё.
	run, _, premise := runInjected(t, injTrunkLaneBelow, injTrunkAhead, injBaseRequestName)
	require.NoError(t, premise)
	require.Lenf(t, run.audit.Findings, 1, "перепись: %s; база: %s", run.audit.Census, run.said)
	require.Contains(t, run.audit.Findings[0], check.MigrationsDirRel+"/"+injTrunkLaneBelow)
	require.Contains(t, run.audit.Findings[0], injTrunkAhead)
	require.Contains(t, run.audit.Findings[0], trunkRefName)

	twin, _, premise := runInjected(t, injTrunkLaneAbove, injTrunkAhead, injBaseRequestName)
	require.NoError(t, premise)
	require.Emptyf(t, twin.audit.Findings, "законный близнец выше вершины ствола обязан "+
		"молчать; перепись: %s", twin.audit.Census)
	require.Equal(t, check.MigrationVersionJudged, twin.audit.Outcome)
}

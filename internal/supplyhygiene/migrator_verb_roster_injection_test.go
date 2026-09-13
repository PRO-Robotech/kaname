// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// migrator_verb_roster_injection_test.go — доказательство того, что ось
// перечня СПОСОБНА упасть, и того, что она молчит на законных близнецах.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОДИН ФАКТ ПРОТИВ БЛИЗНЕЦА
//
// Годное дерево собрано один раз; каждая проба меняет в нём РОВНО ОДИН факт —
// одну строку прозы либо одну строку производителя. Инъекция вида «завести ещё
// один файл с перечнем» здесь не годится: новый файл менял бы и перепись, и
// набор координат разом. Контроль («всё сходится — находок ноль») стоит первым.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОБЕ СТОРОНЫ РАСХОЖДЕНИЯ
//
// Множества сверяются в обе стороны, и проверяется это тоже в обе: лишний
// глагол в прозе (оператор позовёт несуществующее) и недостающий (оператор не
// узнает о существующем). Односторонняя ось молчала бы ровно на половине класса.
//
// ─────────────────────────────────────────────────────────────────────────────
// ДВА ЗАКОННЫХ БЛИЗНЕЦА, И ОБА БЫЛИ БЫ КРАСНЫМИ У НАИВНОГО ПРЕДИКАТА
//
//  1. ПУТЬ к двоичному файлу (`$TMP/mig-ok/kaname-migrator`) — тот же набор слов
//     через косую черту. Строк такой формы в сборочном скрипте службы полтора
//     десятка; ось обязана на них молчать, иначе её отключат первой же правкой.
//  2. КОНСТРУКТОР БЕЗ РЕГИСТРАЦИИ. Функция, объявляющая команду и не отданная
//     `AddCommand`, подкомандой не является — оператор её не позовёт. Ось,
//     считающая литералы `cobra.Command`, потребовала бы назвать её в прозе, то
//     есть требовала бы обещать несуществующее.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/PRO-Robotech/corelib/treecorpus"
	"github.com/stretchr/testify/require"
)

// rosterGoodProducer — производитель: корневая команда и три зарегистрированных
// подкоманды.
const rosterGoodProducer = `package main

import "github.com/spf13/cobra"

func newRootCmd() *cobra.Command {
	root := &cobra.Command{Use: "kaname-migrator"}
	root.AddCommand(newUpCmd(), newDownCmd(), newStatusCmd())
	return root
}

func newUpCmd() *cobra.Command     { return &cobra.Command{Use: "up [--target]"} }
func newDownCmd() *cobra.Command   { return &cobra.Command{Use: "down"} }
func newStatusCmd() *cobra.Command { return &cobra.Command{Use: "status"} }
`

// rosterGoodDockerfile — перечень в сборке: форма через вертикальную черту.
const rosterGoodDockerfile = `FROM alpine:3.24
# kaname-migrator — CLI миграций (cobra: up|down|status), init-контейнер.
COPY --from=builder /kaname-migrator /usr/local/bin/kaname-migrator
`

// rosterGoodDocs — перечень в справке: форма через косую черту и обратные кавычки.
const rosterGoodDocs = "| `kaname-migrator` | CLI миграций БД (`up`/`down`/`status`), init-контейнер |\n"

// rosterGoodScript — ЗАКОННЫЙ БЛИЗНЕЦ: те же слова через косую черту, но это
// пути к двоичному файлу, а не перечень подкоманд.
const rosterGoodScript = `#!/usr/bin/env bash
cp "$TMP/mig-ok/kaname-migrator" "$TMP/chain-ok/kaname-migrator"
go build -o "$BIN/kaname-migrator" ./cmd/migrator
/usr/local/bin/kaname-migrator up
`

// syntheticRosterTree — дерево: производитель, сборка, справка и скрипт.
// Всякая проба ниже строит СВОЁ и меняет ровно один факт.
func syntheticRosterTree(t *testing.T, producer, dockerfile, docs, script string) *treecorpus.Tree {
	t.Helper()

	root := t.TempDir()
	require.NoError(t, os.MkdirAll(filepath.Join(root, "cmd", "migrator"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(root, migratorCommandFile), []byte(producer), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(root, "Dockerfile"), []byte(dockerfile), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "docs"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(root, "docs", "deployment.md"), []byte(docs), 0o600))
	require.NoError(t, os.MkdirAll(filepath.Join(root, "scripts"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(root, "scripts", "stand.sh"), []byte(script), 0o600))

	tree, err := treecorpus.SyntheticTree(root)
	require.NoError(t, err)
	return tree
}

// requireRosterFinding — находка с названной подстрокой есть, и перепись непуста.
func requireRosterFinding(t *testing.T, tree *treecorpus.Tree, wantCoordinate, wantDelta string) {
	t.Helper()
	census, findings, err := scanMigratorRosters(tree)
	require.NoError(t, err)
	require.NotZero(t, census.rostersSeen, "инъекция беспредметна: перечней не распознано ни одного")

	var rendered []string
	for _, f := range findings {
		rendered = append(rendered, f.file+":"+itoa(f.line)+
			" сверх=["+strings.Join(f.extra, ",")+"] умолчано=["+strings.Join(f.missing, ",")+"]")
	}
	joined := strings.Join(rendered, "\n")
	require.Containsf(t, joined, wantCoordinate,
		"ось НЕ назвала координату внесённого дефекта.\nнаходки:\n%s", joined)
	require.Containsf(t, joined, wantDelta,
		"ось НЕ назвала расхождение множеств.\nнаходки:\n%s", joined)
}

// TestMigratorRosterInjection_ControlIsSilent — КОНТРОЛЬ: перечни сходятся с
// деревом команд, находок ноль. Без него всякое красное ниже могло бы приходить
// от соседа.
func TestMigratorRosterInjection_ControlIsSilent(t *testing.T) {
	t.Parallel()
	tree := syntheticRosterTree(t, rosterGoodProducer, rosterGoodDockerfile, rosterGoodDocs, rosterGoodScript)

	binary, verbs, producer, err := parseMigratorCommands(tree.Root())
	require.NoError(t, err)
	require.Equal(t, "kaname-migrator", binary, "имя двоичного файла прочитано у производителя")
	require.Equal(t, []string{"down", "status", "up"}, verbs, "набор подкоманд прочитан по узлу регистрации")
	require.Equal(t, 1, producer.registrations, "узел регистрации один")

	census, findings, err := scanMigratorRosters(tree)
	require.NoError(t, err)
	require.Equal(t, 2, census.rostersSeen, "распознаны оба перечня — через черту и через косую")
	require.Empty(t, findings, "на сходящемся входе находок быть не должно")
}

// TestMigratorRosterInjection_ProseOversPromises — ДЕФЕКТ, ради которого ось
// заведена: проза называет глагол, которого в дереве команд нет.
func TestMigratorRosterInjection_ProseOversPromises(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(rosterGoodDockerfile, "up|down|status", "up|down|status|create", 1)
	require.NotEqual(t, rosterGoodDockerfile, broken, "инъекция не внесена: вход не изменился")

	tree := syntheticRosterTree(t, rosterGoodProducer, broken, rosterGoodDocs, rosterGoodScript)
	requireRosterFinding(t, tree, "Dockerfile:2", "сверх=[create] умолчано=[]")
}

// TestMigratorRosterInjection_ProseUndersells — ЗЕРКАЛО: проза умалчивает о
// существующей подкоманде. Односторонняя ось молчала бы на этой половине класса.
func TestMigratorRosterInjection_ProseUndersells(t *testing.T) {
	t.Parallel()
	broken := strings.Replace(rosterGoodDocs, "(`up`/`down`/`status`)", "(`up`/`down`)", 1)
	require.NotEqual(t, rosterGoodDocs, broken, "инъекция не внесена: вход не изменился")

	tree := syntheticRosterTree(t, rosterGoodProducer, rosterGoodDockerfile, broken, rosterGoodScript)
	requireRosterFinding(t, tree, "docs/deployment.md:1", "сверх=[] умолчано=[status]")
}

// TestMigratorRosterInjection_PathIsNotARoster — ЗАКОННЫЙ БЛИЗНЕЦ: путь к
// двоичному файлу через косую черту перечнем не является. Наивный предикат
// краснел бы на полутора десятках строк сборочного скрипта службы.
func TestMigratorRosterInjection_PathIsNotARoster(t *testing.T) {
	t.Parallel()
	tree := syntheticRosterTree(t, rosterGoodProducer, rosterGoodDockerfile, rosterGoodDocs, rosterGoodScript)

	census, findings, err := scanMigratorRosters(tree)
	require.NoError(t, err)
	require.GreaterOrEqual(t, census.namingLines, 4, "строки скрипта, называющие накатчик, прочитаны")
	require.Empty(t, findings, "путь к двоичному файлу перечнем не является")
}

// TestMigratorRosterInjection_UnregisteredConstructorIsNotASubcommand —
// ЗАКОННЫЙ БЛИЗНЕЦ второй: команда объявлена и НЕ зарегистрирована. Оператор её
// не позовёт, значит проза о ней молчать обязана, а ось — не требовать.
func TestMigratorRosterInjection_UnregisteredConstructorIsNotASubcommand(t *testing.T) {
	t.Parallel()
	producer := rosterGoodProducer +
		"\nfunc newCreateCmd() *cobra.Command { return &cobra.Command{Use: \"create\"} }\n"
	require.NotEqual(t, rosterGoodProducer, producer, "инъекция не внесена: вход не изменился")

	tree := syntheticRosterTree(t, producer, rosterGoodDockerfile, rosterGoodDocs, rosterGoodScript)

	_, verbs, census, err := parseMigratorCommands(tree.Root())
	require.NoError(t, err)
	require.Equal(t, 5, census.commandLiterals, "литералов команд в файле пять")
	require.Equal(t, []string{"down", "status", "up"}, verbs,
		"подкомандой считается ЗАРЕГИСТРИРОВАННАЯ, а не всякая объявленная")

	_, findings, err := scanMigratorRosters(tree)
	require.NoError(t, err)
	require.Empty(t, findings, "незарегистрированная команда прозой называться не обязана")
}

// TestMigratorRosterInjection_ProducerWithoutRegistrationIsVoid — ПУСТОЙ
// ПРОИЗВОДИТЕЛЬ: регистраций нет, набор подкоманд пуст. Разбор отказывает, а не
// объявляет дерево чистым: «ноль находок» отличимо от «ноль прочитанного».
func TestMigratorRosterInjection_ProducerWithoutRegistrationIsVoid(t *testing.T) {
	t.Parallel()
	producer := `package main

import "github.com/spf13/cobra"

func newRootCmd() *cobra.Command { return &cobra.Command{Use: "kaname-migrator"} }
`
	tree := syntheticRosterTree(t, producer, rosterGoodDockerfile, rosterGoodDocs, rosterGoodScript)

	_, findings, err := scanMigratorRosters(tree)
	require.ErrorIs(t, err, errNoMigratorProducer,
		"без зарегистрированных подкоманд разбор обязан ОТКАЗАТЬ, а не молчать")
	require.Empty(t, findings)
}

// TestMigratorRosterInjection_TreeWithoutRostersIsVoidNotGreen — ПУСТОЙ ОБХОД:
// перечней в дереве нет. Главный тест на такой переписи падает своим стражем.
func TestMigratorRosterInjection_TreeWithoutRostersIsVoidNotGreen(t *testing.T) {
	t.Parallel()
	tree := syntheticRosterTree(t, rosterGoodProducer,
		"FROM alpine:3.24\nCOPY /kaname-migrator /usr/local/bin/kaname-migrator\n",
		"| `kaname-migrator` | CLI миграций БД |\n", rosterGoodScript)

	census, findings, err := scanMigratorRosters(tree)
	require.NoError(t, err)
	require.Empty(t, findings)
	require.Zero(t, census.rostersSeen,
		"перечней нет — на этой переписи главный тест обязан падать стражем, а не зеленеть")
}

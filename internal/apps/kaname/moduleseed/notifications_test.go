// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package moduleseed_test

// notifications_test.go — применитель строки `notifications` (приёмка NTF-1,
// сценарии NTF1-F01…F03, F21; замысел З17, условие УК1).
//
// Применитель — последний рубеж: форму строки уже осудил разбор, но документ,
// дошедший до применителя в обход разбора, он не применяет. Поэтому отрицания
// здесь подают манифест СТРУКТУРОЙ, минуя загрузчик, а положительный близнец —
// тем же загрузчиком, которым его подаёт композиционный корень.

import (
	"context"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/corelib/authz"
	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/moduleseed"
	"github.com/PRO-Robotech/kaname/internal/manifest"
)

// probeWithNotifications — фикстурный модуль `probe` со строкой F01.
const probeWithNotifications = `
apiVersion: iam/v1
module: probe
resources: []
notifications: {namespace: probe, readers: [notify]}
`

// bypassed — манифест модуля `probe`, собранный структурой в обход разбора.
func bypassed(namespace string, readers ...string) *manifest.Manifest {
	return &manifest.Manifest{
		APIVersion:    "iam/v1",
		Module:        "probe",
		Notifications: &manifest.Notifications{Namespace: namespace, Readers: readers},
	}
}

func tupleCalls(calls []string) []string {
	var out []string
	for _, c := range calls {
		if strings.HasPrefix(c, "tuple ") {
			out = append(out, c)
		}
	}
	return out
}

// TestNTF1F01_ApplierWritesTheFeedReaderTuple — положительный близнец: строка
// своего модуля с читателем notify заводит `service:notify reader
// notification_feed:probe`, и перепись говорит это числом.
func TestNTF1F01_ApplierWritesTheFeedReaderTuple(t *testing.T) {
	w := &recordingWriter{changed: true}
	census, err := moduleseed.NewApplier(&recordingTx{w: w}).Apply(context.Background(), nil,
		[]*manifest.Manifest{load(t, probeWithNotifications)})
	require.NoError(t, err)
	t.Logf("перепись: %s\nвызовы: %s", census, strings.Join(w.calls, " · "))

	// Р5: строка модуля заводит читателя ленты и — вместе с записью выдачи
	// пространства — её проекцию `sender`.
	require.Equal(t, []string{
		"tuple service:notify reader notification_feed:probe",
		"tuple service:probe sender notification_namespace:probe",
	}, tupleCalls(w.calls))
	require.Contains(t, w.calls, "grant probe", "запись выдачи пространства не заведена")
	require.Equal(t, 1, census.Seeding, "манифест со строкой notifications — предмет посева")
	require.Len(t, census.Reports, 1)
	require.Equal(t, 2, census.Reports[0].DeclaredServiceTuples)
	require.Equal(t, 2, census.Reports[0].WrittenServiceTuples)
	require.Contains(t, census.Reports[0].String(), "служебных кортежей 2/2")
}

// TestNTF1F08_ApplierWritesNoSenderForAnExistingGrant — запись выдачи уже есть
// (в том числе с надгробием): посев её не трогает и проекцию `sender` не
// пишет — отозванное перезапуском не оживает. Близнец — F01 выше.
func TestNTF1F08_ApplierWritesNoSenderForAnExistingGrant(t *testing.T) {
	w := &recordingWriter{changed: false}
	census, err := moduleseed.NewApplier(&recordingTx{w: w}).Apply(context.Background(), nil,
		[]*manifest.Manifest{load(t, probeWithNotifications)})
	require.NoError(t, err)
	t.Logf("перепись: %s\nвызовы: %s", census, strings.Join(w.calls, " · "))
	require.Contains(t, w.calls, "grant probe")
	require.Equal(t, []string{"tuple service:notify reader notification_feed:probe"}, tupleCalls(w.calls),
		"проекция sender написана поверх существующей записи выдачи")
}

// TestNTF1F02_ApplierRefusesAForeignNamespace — `namespace: vpc` у модуля
// `probe`: отказ посева, кортежей по `vpc` ноль.
func TestNTF1F02_ApplierRefusesAForeignNamespace(t *testing.T) {
	for name, m := range map[string]*manifest.Manifest{
		"чужое":      bypassed("vpc", "notify"),
		"не названо": bypassed("", "notify"),
	} {
		t.Run(name, func(t *testing.T) {
			w := &recordingWriter{changed: true}
			_, err := moduleseed.NewApplier(&recordingTx{w: w}).Apply(context.Background(), nil, []*manifest.Manifest{m})
			require.ErrorIs(t, err, manifest.ErrNotificationNamespaceForeign)
			require.Contains(t, err.Error(), "пространство не своего модуля")
			require.Contains(t, err.Error(), `"probe"`)
			require.Empty(t, tupleCalls(w.calls), "при отказе строки заведены кортежи")
		})
	}
}

// TestNTF1F03_ApplierRefusesAReaderOtherThanNotify — читатель вне notify: отказ
// посева, кортежа `service:compute reader notification_feed:probe` нет.
func TestNTF1F03_ApplierRefusesAReaderOtherThanNotify(t *testing.T) {
	for name, m := range map[string]*manifest.Manifest{
		"compute":          bypassed("probe", "compute"),
		"notify и compute": bypassed("probe", "notify", "compute"),
	} {
		t.Run(name, func(t *testing.T) {
			w := &recordingWriter{changed: true}
			_, err := moduleseed.NewApplier(&recordingTx{w: w}).Apply(context.Background(), nil, []*manifest.Manifest{m})
			require.ErrorIs(t, err, manifest.ErrNotificationReaderNotNotify)
			require.Contains(t, err.Error(), "reader ленты — только notify")
			require.Empty(t, tupleCalls(w.calls),
				"при отказе строки заведён кортеж — в том числе законный notify рядом с чужим")
		})
	}
}

// TestUK1_ServiceTupleSubjectComesFromTheFoundation — субъект служебного
// кортежа — ровно строка единственного производителя фундамента
// `authz.ServiceSubject`, а не своя сборка.
func TestUK1_ServiceTupleSubjectComesFromTheFoundation(t *testing.T) {
	w := &recordingWriter{changed: true}
	_, err := moduleseed.NewApplier(&recordingTx{w: w}).Apply(context.Background(), nil,
		[]*manifest.Manifest{load(t, probeWithNotifications)})
	require.NoError(t, err)
	want := authz.ServiceSubject(grpcsrv.ServiceName("notify"))
	require.NotEmpty(t, want, "производитель фундамента не дал строки — сравнивать не с чем")
	sender := authz.ServiceSubject(grpcsrv.ServiceName("probe"))
	require.NotEmpty(t, sender, "производитель фундамента не дал строки — сравнивать не с чем")
	require.Equal(t, []string{
		"tuple " + want + " reader notification_feed:probe",
		"tuple " + sender + " sender notification_namespace:probe",
	}, tupleCalls(w.calls))
}

// TestUK1_ServiceTuplePathNeverCallsFGASubjectRef — путь служебного кортежа —
// конструктор применителя и глагол писателя `WriteServiceTuple` — не зовёт
// тенантский кодек `domain.FGASubjectRef` (УК1: он и его 4 вызывающих не
// меняются, а служебный субъект строится фундаментом).
//
// Суд идёт по узлам разбора: вызов — узел `CallExpr` с селектором
// `FGASubjectRef`; упоминание в комментарии вызовом не является.
func TestUK1_ServiceTuplePathNeverCallsFGASubjectRef(t *testing.T) {
	_, self, _, ok := runtime.Caller(0)
	require.True(t, ok)
	dir := filepath.Dir(self)
	sites := map[string]string{ // файл → функция, чьё тело судится ("" — весь файл)
		filepath.Join(dir, "service_tuple.go"):                              "",
		filepath.Join(dir, "../../../repo/kaname/pg/module_seed_writer.go"): "WriteServiceTuple",
	}
	for path, fn := range sites {
		calls, bodies := fgaSubjectRefCalls(t, path, fn)
		require.NotZerof(t, bodies, "%s: судимое тело (%q) не найдено — проверка ни о чём", path, fn)
		require.Zerof(t, calls, "%s: путь служебного кортежа зовёт FGASubjectRef (%d вызовов)", path, calls)
	}

	// Инъекция: то же тело С вызовом — находка; без — молчание.
	inj := filepath.Join(t.TempDir(), "inj.go")
	require.NoError(t, os.WriteFile(inj, []byte(`package pg
func (w x) WriteServiceTuple() string { return domain.FGASubjectRef("service", "notify") }
func other() string { return domain.FGASubjectRef("user", "u") }
`), 0o600))
	calls, bodies := fgaSubjectRefCalls(t, inj, "WriteServiceTuple")
	require.Equal(t, 1, bodies)
	require.Equal(t, 1, calls, "инъекция вызова в тело не найдена — проверка слепа")
}

func fgaSubjectRefCalls(t *testing.T, path, fn string) (calls, bodies int) {
	t.Helper()
	f, err := parser.ParseFile(token.NewFileSet(), path, nil, 0)
	require.NoError(t, err)
	for _, d := range f.Decls {
		fd, ok := d.(*ast.FuncDecl)
		if !ok || fd.Body == nil || (fn != "" && fd.Name.Name != fn) {
			continue
		}
		bodies++
		ast.Inspect(fd.Body, func(n ast.Node) bool {
			if c, ok := n.(*ast.CallExpr); ok {
				if sel, ok := c.Fun.(*ast.SelectorExpr); ok && sel.Sel.Name == "FGASubjectRef" {
					calls++
				}
			}
			return true
		})
	}
	return calls, bodies
}

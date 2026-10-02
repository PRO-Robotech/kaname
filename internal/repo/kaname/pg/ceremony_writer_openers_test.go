// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package pg_test

// ceremony_writer_openers_test.go — ПЕРЕПИСЬ ОТКРЫТИЙ транзакций, в которых
// исполняются писатели церемонии (задача PRO-Robotech/kaname#316).
//
// Уровень изоляции писателей назван одним местом (`ceremonyWriterTx()`), но
// исход пары «выдача против снятия сессии» решает уровень ОБЕИХ транзакций:
// снятие отзывает семейства оператором `revokeFamiliesOfSessionsTx` в
// транзакции писателя СЕССИИ, а не порта церемонии. Открытий этой транзакции
// в дереве было четыре, и каждое наследовало уровень от умолчания сессии.
// Перепись держит, что это непредставимо:
//
//   - R1 писатель сессии строится ТОЛЬКО открытием `beginHumanSessionWriter`;
//     формы построения — составной литерал (и под `&`), `new(…)` и объявление
//     переменной значения;
//   - R2 открытие писателя сессии и открытие писателя порта (`beginWriter`)
//     идут через `BeginTx` с уровнем `ceremonyWriterTx()`, и никак иначе;
//   - R3 отзыв семейств снятием (`revokeFamiliesOfSessionsTx`,
//     `endSessionsAndRevokeWhatTheyHold`) зовут только методы писателя сессии
//     и сама дверь снятия — то есть на транзакции, открытой по R1;
//   - R4 метод порта церемонии обращается к пулу только читающими методами
//     (`QueryRow`, `Query`); открытие — только в `beginWriter`;
//   - R5 каждая функция, зовущая открытие писателя сессии, — дверь с обратной
//     сценой в `sessionEnderDoors`, и каждая сцена — дверь в дереве.
//
// # Чего перепись НЕ различает
//
//   - писателя, пишущего через `QueryRow`/`Query` (`UPDATE … RETURNING`): R4
//     судит имя метода пула, а не текст оператора;
//   - транзакцию, подменённую у построенного писателя присваиванием поля
//     (`w.tx = …`): разбор без типов не отличает поле `tx` писателя сессии от
//     одноимённых полей других писателей пакета;
//   - обращение порта к пулу не через поле `pool`.

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const (
	sessionWriterType   = "humanSessionWriter"
	sessionWriterOpener = "beginHumanSessionWriter"
	ceremonyPortType    = "OAuthCeremonyRepo"
	ceremonyPortOpener  = "OAuthCeremonyRepo.beginWriter"
	ceremonyNamedLevel  = "ceremonyWriterTx"
	sessionEndDoorFunc  = "endSessionsAndRevokeWhatTheyHold"
)

// sessionEndRevocations — операторы отзыва семейств снятием сессии.
var sessionEndRevocations = map[string]bool{
	"revokeFamiliesOfSessionsTx": true,
	sessionEndDoorFunc:           true,
}

// ceremonyPortPoolReaders — методы пула, которыми порту разрешено читать мимо
// транзакции писателя.
var ceremonyPortPoolReaders = map[string]bool{"QueryRow": true, "Query": true}

// writerOpenerCensus — объём осмотренного. «Находок ноль» без него неотличимо
// от «прочитано ноль».
type writerOpenerCensus struct {
	files, funcs    int
	writerBuilds    int
	revocationCalls int
	portPoolCalls   int
	doors           []string
}

func isIdentNamed(e ast.Expr, name string) bool {
	id, ok := e.(*ast.Ident)
	return ok && id.Name == name
}

// isNamedLevelCall — аргумент уровня есть ВЫЗОВ `ceremonyWriterTx()`.
func isNamedLevelCall(e ast.Expr) bool {
	c, ok := e.(*ast.CallExpr)
	return ok && len(c.Args) == 0 && isIdentNamed(c.Fun, ceremonyNamedLevel)
}

// declName — «Тип.Метод» у метода и имя у функции.
func declName(fd *ast.FuncDecl) (recv, name string) {
	if fd.Recv == nil || len(fd.Recv.List) == 0 {
		return "", fd.Name.Name
	}
	t := fd.Recv.List[0].Type
	if s, ok := t.(*ast.StarExpr); ok {
		t = s.X
	}
	if id, ok := t.(*ast.Ident); ok {
		return id.Name, id.Name + "." + fd.Name.Name
	}
	return "?", "?." + fd.Name.Name
}

// censusCeremonyWriterOpeners — перепись по исходникам пакета (имя файла →
// текст) и именам дверей, у которых есть обратная сцена.
func censusCeremonyWriterOpeners(srcs map[string]string, scenes []string) (writerOpenerCensus, []string, error) {
	var (
		c        writerOpenerCensus
		findings []string
	)
	fset := token.NewFileSet()
	files := make([]string, 0, len(srcs))
	for name := range srcs {
		files = append(files, name)
	}
	sort.Strings(files)

	doors := map[string]bool{}
	openerFound, portOpenerFound := false, false

	for _, file := range files {
		f, err := parser.ParseFile(fset, file, srcs[file], 0)
		if err != nil {
			return c, nil, fmt.Errorf("разбор %s: %w", file, err)
		}
		c.files++
		for _, decl := range f.Decls {
			recv, fn := "", "<уровень пакета>"
			var body ast.Node = decl
			if fd, ok := decl.(*ast.FuncDecl); ok {
				if fd.Body == nil {
					continue
				}
				c.funcs++
				recv, fn = declName(fd)
				body = fd.Body
			}
			isOpener := fn == sessionWriterOpener
			isPortOpener := fn == ceremonyPortOpener
			namedOpen, wrongOpen := 0, 0
			at := func(n ast.Node) string {
				p := fset.Position(n.Pos())
				return fmt.Sprintf("%s:%d %s", p.Filename, p.Line, fn)
			}
			built := func(n ast.Node, form string) {
				c.writerBuilds++
				if !isOpener {
					findings = append(findings, fmt.Sprintf(
						"R1 %s — писатель сессии построен (%s) мимо открытия %s: его транзакция "+
							"открыта не на названном уровне", at(n), form, sessionWriterOpener))
				}
			}
			ast.Inspect(body, func(n ast.Node) bool {
				switch x := n.(type) {
				case *ast.CompositeLit:
					if isIdentNamed(x.Type, sessionWriterType) {
						built(x, "составной литерал")
					}
				case *ast.ValueSpec:
					if isIdentNamed(x.Type, sessionWriterType) {
						built(x, "объявление переменной")
					}
				case *ast.CallExpr:
					if id, ok := x.Fun.(*ast.Ident); ok {
						switch {
						case id.Name == "new" && len(x.Args) == 1 && isIdentNamed(x.Args[0], sessionWriterType):
							built(x, "new")
						case id.Name == sessionWriterOpener:
							doors[fn] = true
						case sessionEndRevocations[id.Name]:
							c.revocationCalls++
							if recv != sessionWriterType && fn != sessionEndDoorFunc {
								findings = append(findings, fmt.Sprintf(
									"R3 %s — отзыв семейств снятием (%s) на транзакции, открытой не "+
										"писателем сессии", at(x), id.Name))
							}
						}
					}
					sel, ok := x.Fun.(*ast.SelectorExpr)
					if !ok {
						return true
					}
					if (isOpener || isPortOpener) && (sel.Sel.Name == "BeginTx" || sel.Sel.Name == "Begin") {
						if sel.Sel.Name == "BeginTx" && len(x.Args) == 2 && isNamedLevelCall(x.Args[1]) {
							namedOpen++
						} else {
							wrongOpen++
							findings = append(findings, fmt.Sprintf(
								"R2 %s — открытие транзакции писателя не на %s()", at(x), ceremonyNamedLevel))
						}
					}
					if recv == ceremonyPortType {
						if inner, ok := sel.X.(*ast.SelectorExpr); ok && inner.Sel.Name == "pool" {
							c.portPoolCalls++
							lawful := ceremonyPortPoolReaders[sel.Sel.Name] ||
								(isPortOpener && sel.Sel.Name == "BeginTx")
							if !lawful {
								findings = append(findings, fmt.Sprintf(
									"R4 %s — метод порта пишет пулом (%s) мимо %s: уровень унаследован "+
										"от умолчания сессии", at(x), sel.Sel.Name, ceremonyPortOpener))
							}
						}
					}
				}
				return true
			})
			if isOpener {
				openerFound = true
			}
			if isPortOpener {
				portOpenerFound = true
			}
			if (isOpener || isPortOpener) && namedOpen == 0 && wrongOpen == 0 {
				findings = append(findings, fmt.Sprintf(
					"R2 %s — открытие писателя не открывает транзакцию на %s()", at(decl), ceremonyNamedLevel))
			}
		}
	}
	if !openerFound {
		findings = append(findings, fmt.Sprintf(
			"R2 открытие писателя сессии %s в пакете не найдено", sessionWriterOpener))
	}
	if !portOpenerFound {
		findings = append(findings, fmt.Sprintf(
			"R2 открытие писателя порта %s в пакете не найдено", ceremonyPortOpener))
	}

	sceneSet := map[string]bool{}
	for _, s := range scenes {
		sceneSet[s] = true
	}
	for door := range doors {
		c.doors = append(c.doors, door)
		if !sceneSet[door] {
			findings = append(findings, fmt.Sprintf(
				"R5 %s — дверь писателя сессии без обратной сцены в sessionEnderDoors", door))
		}
	}
	sort.Strings(c.doors)
	for _, s := range scenes {
		if !doors[s] {
			findings = append(findings, fmt.Sprintf(
				"R5 %s — сцена в sessionEnderDoors называет дверь, которой в дереве нет", s))
		}
	}
	sort.Strings(findings)
	return c, findings, nil
}

// packageSources — прод-исходники этого пакета.
func packageSources(t *testing.T) map[string]string {
	t.Helper()
	entries, err := os.ReadDir(".")
	require.NoError(t, err)
	srcs := map[string]string{}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		b, rerr := os.ReadFile(name) // #nosec G304 -- имя из состава каталога пакета
		require.NoError(t, rerr)
		srcs[name] = string(b)
	}
	return srcs
}

func sessionEnderSceneNames() []string {
	names := make([]string, 0, len(sessionEnderDoors))
	for _, d := range sessionEnderDoors {
		names = append(names, d.name)
	}
	return names
}

// TestCeremonyWriterTransactionsOpenOnTheNamedLevel — перепись дерева. Базы не
// требует.
func TestCeremonyWriterTransactionsOpenOnTheNamedLevel(t *testing.T) {
	scenes := sessionEnderSceneNames()
	c, findings, err := censusCeremonyWriterOpeners(packageSources(t), scenes)
	require.NoError(t, err)
	t.Logf("перепись: прод-файлов пакета %d · функций с телом %d · построений писателя сессии %d · "+
		"дверей %d %v · сцен %d · вызовов отзыва снятием %d · обращений порта к пулу %d · "+
		"находок %d (потолок 0)",
		c.files, c.funcs, c.writerBuilds, len(c.doors), c.doors, len(scenes),
		c.revocationCalls, c.portPoolCalls, len(findings))

	// ПРЕДПОСЫЛКИ: предмет в дереве есть. Иначе «находок ноль» — «прочитано ноль».
	require.NotZero(t, c.files, "НЕ ВЫПОЛНИЛОСЬ: обход не прочёл ни одного файла пакета")
	require.NotZero(t, c.writerBuilds,
		"построений писателя сессии не найдено: предмет снят или переименован — перепись "+
			"обязана уйти вместе с ним")
	require.NotZero(t, c.revocationCalls,
		"вызовов отзыва семейств снятием не найдено: R3 судит пустое множество")
	require.NotZero(t, c.portPoolCalls,
		"обращений порта к пулу не найдено: R4 судит пустое множество")

	assert.Empty(t, findings, "транзакция писателя церемонии открыта не на названном уровне:\n  %s",
		strings.Join(findings, "\n  "))
}

// lawfulOpenersSrc — законная форма всех пяти правил в одном файле.
const lawfulOpenersSrc = `package pg

func ceremonyWriterTx() pgx.TxOptions { return pgx.TxOptions{IsoLevel: pgx.ReadCommitted} }

func (r *OAuthCeremonyRepo) beginWriter(ctx context.Context) (pgx.Tx, error) {
	return r.pool.BeginTx(ctx, ceremonyWriterTx())
}

func (r *OAuthCeremonyRepo) refuse(ctx context.Context) error {
	return r.pool.QueryRow(ctx, "SELECT 1").Scan()
}

func beginHumanSessionWriter(ctx context.Context, pool *pgxpool.Pool) (*humanSessionWriter, error) {
	tx, err := pool.BeginTx(ctx, ceremonyWriterTx())
	if err != nil {
		return nil, err
	}
	return &humanSessionWriter{tx: tx}, nil
}

func (r *HumanSessionRepo) Writer(ctx context.Context) (*humanSessionWriter, error) {
	return beginHumanSessionWriter(ctx, r.pool)
}

func (w *humanSessionWriter) EndSession(ctx context.Context) error {
	_, err := revokeFamiliesOfSessionsTx(ctx, w.tx, nil, "x")
	return err
}

func (w *humanSessionWriter) EndOtherSessions(ctx context.Context) error {
	_, err := endSessionsAndRevokeWhatTheyHold(ctx, w.tx)
	return err
}

func endSessionsAndRevokeWhatTheyHold(ctx context.Context, tx pgx.Tx) (int, error) {
	return revokeFamiliesOfSessionsTx(ctx, tx, nil, "x")
}
`

// TestCeremonyWriterOpenerCensusInjection — перепись ловит каждый одно-фактный
// дефект и молчит на законном близнеце той же формы.
func TestCeremonyWriterOpenerCensusInjection(t *testing.T) {
	lawfulScenes := []string{"HumanSessionRepo.Writer"}
	cases := []struct {
		name   string
		mutate func(string) string
		scenes []string
		// want — подстрока находки; пусто — законный близнец, находок ноль.
		want string
	}{
		{name: "control", mutate: func(s string) string { return s }},
		{
			name: "R1-literal-outside-opener",
			mutate: func(s string) string {
				return s + `
func (s *RegistrationStore) Writer(ctx context.Context) *humanSessionWriter {
	tx, _ := s.pool.BeginTx(ctx, pgx.TxOptions{})
	return &humanSessionWriter{tx: tx}
}
`
			},
			want: "R1 inj.go:41 RegistrationStore.Writer — писатель сессии построен (составной литерал)",
		},
		{
			name: "R1-new-outside-opener",
			mutate: func(s string) string {
				return s + `
func buildWriter() *humanSessionWriter { return new(humanSessionWriter) }
`
			},
			want: "R1 inj.go:39 buildWriter — писатель сессии построен (new)",
		},
		{
			name: "R1-var-outside-opener",
			mutate: func(s string) string {
				return s + `
func buildWriter() humanSessionWriter {
	var w humanSessionWriter
	return w
}
`
			},
			want: "R1 inj.go:40 buildWriter — писатель сессии построен (объявление переменной)",
		},
		{
			// Законный близнец R1 и R5: та же дверь — через открытие и со сценой.
			name: "R1-twin-door-through-opener-with-scene",
			mutate: func(s string) string {
				return s + `
func (s *RegistrationStore) Writer(ctx context.Context) (*humanSessionWriter, error) {
	return beginHumanSessionWriter(ctx, s.pool)
}
`
			},
			scenes: []string{"HumanSessionRepo.Writer", "RegistrationStore.Writer"},
		},
		{
			name: "R2-opener-on-empty-options",
			mutate: func(s string) string {
				return strings.Replace(s, "tx, err := pool.BeginTx(ctx, ceremonyWriterTx())",
					"tx, err := pool.BeginTx(ctx, pgx.TxOptions{})", 1)
			},
			want: "R2 inj.go:14 beginHumanSessionWriter — открытие транзакции писателя не на ceremonyWriterTx()",
		},
		{
			name: "R2-opener-on-pool-begin",
			mutate: func(s string) string {
				return strings.Replace(s, "tx, err := pool.BeginTx(ctx, ceremonyWriterTx())",
					"tx, err := pool.Begin(ctx)", 1)
			},
			want: "R2 inj.go:14 beginHumanSessionWriter — открытие транзакции писателя не на ceremonyWriterTx()",
		},
		{
			name: "R2-port-opener-on-other-level",
			mutate: func(s string) string {
				return strings.Replace(s, "return r.pool.BeginTx(ctx, ceremonyWriterTx())",
					"return r.pool.BeginTx(ctx, pgx.TxOptions{IsoLevel: pgx.Serializable})", 1)
			},
			want: "R2 inj.go:6 OAuthCeremonyRepo.beginWriter — открытие транзакции писателя не на ceremonyWriterTx()",
		},
		{
			name: "R2-opener-gone",
			mutate: func(s string) string {
				i := strings.Index(s, "func beginHumanSessionWriter(")
				j := strings.Index(s, "func (r *HumanSessionRepo) Writer(")
				return s[:i] + s[j:]
			},
			want: "R2 открытие писателя сессии beginHumanSessionWriter в пакете не найдено",
		},
		{
			name: "R3-revocation-on-foreign-tx",
			mutate: func(s string) string {
				return s + `
func (r *HumanSessionRepo) Sweep(ctx context.Context) {
	tx, _ := r.pool.Begin(ctx)
	_, _ = revokeFamiliesOfSessionsTx(ctx, tx, nil, "x")
}
`
			},
			want: "R3 inj.go:41 HumanSessionRepo.Sweep — отзыв семейств снятием (revokeFamiliesOfSessionsTx)",
		},
		{
			name: "R4-port-writes-through-pool",
			mutate: func(s string) string {
				return s + `
func (r *OAuthCeremonyRepo) Noop(ctx context.Context) error {
	_, err := r.pool.Exec(ctx, "UPDATE kaname.token_families SET live = live")
	return err
}
`
			},
			want: "R4 inj.go:40 OAuthCeremonyRepo.Noop — метод порта пишет пулом (Exec)",
		},
		{
			// Законный близнец R4: тот же метод читает пулом.
			name: "R4-twin-port-reads-through-pool",
			mutate: func(s string) string {
				return s + `
func (r *OAuthCeremonyRepo) Noop(ctx context.Context) error {
	return r.pool.QueryRow(ctx, "SELECT 1").Scan()
}
`
			},
		},
		{
			name: "R5-door-without-scene",
			mutate: func(s string) string {
				return s + `
func (s *RegistrationStore) Writer(ctx context.Context) (*humanSessionWriter, error) {
	return beginHumanSessionWriter(ctx, s.pool)
}
`
			},
			want: "R5 RegistrationStore.Writer — дверь писателя сессии без обратной сцены",
		},
		{
			name:   "R5-scene-without-door",
			mutate: func(s string) string { return s },
			scenes: []string{"HumanSessionRepo.Writer", "HumanSessionRepo.Ghost"},
			want:   "R5 HumanSessionRepo.Ghost — сцена в sessionEnderDoors называет дверь, которой в дереве нет",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			src := tc.mutate(lawfulOpenersSrc)
			if tc.name != "control" && tc.name != "R5-scene-without-door" {
				require.NotEqual(t, lawfulOpenersSrc, src, "инъекция не легла")
			}
			scenes := tc.scenes
			if scenes == nil {
				scenes = lawfulScenes
			}
			c, findings, err := censusCeremonyWriterOpeners(map[string]string{"inj.go": src}, scenes)
			require.NoError(t, err)
			require.Equal(t, 1, c.files)
			if tc.want == "" {
				assert.Empty(t, findings, "законный близнец обязан молчать")
				return
			}
			require.Len(t, findings, 1, "инъекция роняет ровно одно правило: %v", findings)
			assert.Contains(t, findings[0], tc.want)
		})
	}

	t.Run("empty-walk", func(t *testing.T) {
		c, findings, err := censusCeremonyWriterOpeners(map[string]string{}, nil)
		require.NoError(t, err)
		assert.Zero(t, c.files)
		assert.Zero(t, c.writerBuilds)
		// Пустой обход — не «зелёное»: открытий нет, и перепись это называет.
		assert.Len(t, findings, 2, "пустой обход обязан называть отсутствие обоих открытий: %v", findings)
	})
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Доказательство, что ОБРАТНОЕ направление способно упасть и способно смолчать.
//
// Гоняется НАСТОЯЩИЙ сборщик (`collectServiceSeries`) на синтетических пакетах;
// оси проверяются по одной, у каждой инъекции — законный близнец, отличающийся
// ровно ОДНИМ фактом.
//
// ФОРМЫ ОБЪЯВЛЕНИЯ ИМЕНИ РЯДА ПЕРЕЧИСЛЕНЫ, И ПО КАЖДОЙ ЕСТЬ ПАРА. Форма, о
// которой сборщик не знает, даёт не красное и не зелёное, а МОЛЧАНИЕ: ряд без
// читателя остаётся невидимым, и проверка отчитывается чистой:
//
//	1 поле `Name:` литералом                              собирается
//	2 поле `Name:` склейкой с приставкой-константой        собирается
//	3 первый довод `prometheus.NewDesc`                    собирается
//	4 имя в тексте справки (`Help:`)             НЕ объявление — молчание
//	5 имя в комментарии                          НЕ объявление — молчание
//	6 имя в _test.go                             НЕ объявление — молчание
//	7 имя чужой приставки (не `kaname_`/`kacho_`) вне формы ряда — молчание
package supplyhygiene

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/stretchr/testify/require"
)

// synthPkg — синтетический пакет величин из перечня файлов.
func synthPkg(t *testing.T, files map[string]string) string {
	t.Helper()
	dir := t.TempDir()
	for name, body := range files {
		require.NoError(t, os.WriteFile(filepath.Join(dir, name), []byte(body), 0o600))
	}
	return dir
}

const synthHead = `package metrics

import "github.com/prometheus/client_golang/prometheus"

const Namespace = "kaname"

`

// TestReverseCollectorSeesEachDeclarationForm — ИНЪЕКЦИЯ по каждой форме.
func TestReverseCollectorSeesEachDeclarationForm(t *testing.T) {
	cases := map[string]struct{ body, want string }{
		"1 поле Name литералом": {
			body: synthHead + `var a = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "kaname_alpha_total",
	Help: "alpha",
})
`,
			want: "kaname_alpha_total",
		},
		"2 поле Name склейкой с приставкой": {
			body: synthHead + `var b = prometheus.NewCounter(prometheus.CounterOpts{
	Name: Namespace + "_beta_total",
	Help: "beta",
})
`,
			want: "kaname_beta_total",
		},
		"3 первый довод NewDesc": {
			body: synthHead + `var c = prometheus.NewDesc("kaname_gamma_total", "gamma", []string{"outcome"}, nil)
`,
			want: "kaname_gamma_total",
		},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			got, census, err := collectServiceSeries(synthPkg(t, map[string]string{"m.go": tc.body}))
			require.NoError(t, err)
			require.Equal(t, 1, census.filesRead, "обход не прочитал файл — ось беспредметна")
			require.Containsf(t, got, tc.want,
				"форма объявления вне сборщика: ряд %s не собран, значит его отсутствие "+
					"на странице никогда не покраснеет", tc.want)
			require.Equal(t, 1, census.declared)
		})
	}
}

// TestReverseCollectorIsSilentOnWhatIsNotADeclaration — ЗАКОННЫЕ БЛИЗНЕЦЫ.
//
// Имя ряда встречается в справке, в комментарии и в пробах. Принять их за
// объявление значило бы требовать строку на странице для того, чего служба не
// производит, — то есть красное на верном дереве, а такую проверку отключают
// первой.
func TestReverseCollectorIsSilentOnWhatIsNotADeclaration(t *testing.T) {
	body := synthHead + `// kaname_from_comment_total — имя ряда в КОММЕНТАРИИ, не объявление.
var d = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "kaname_real_total",
	Help: "см. также kaname_from_help_total — имя в СПРАВКЕ, не объявление",
})

var foreign = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "othersvc_delta_total",
	Help: "чужая приставка — не ряд этой службы",
})
`
	test := synthHead + `var inTest = prometheus.NewCounter(prometheus.CounterOpts{
	Name: "kaname_from_test_total",
	Help: "объявлен в пробе",
})
`
	got, census, err := collectServiceSeries(synthPkg(t, map[string]string{
		"m.go": body, "m_test.go": test,
	}))
	require.NoError(t, err)
	require.Equal(t, 1, census.filesRead, "файл проб попал в обход")
	require.Contains(t, got, "kaname_real_total")
	for _, silent := range []string{
		"kaname_from_comment_total",
		"kaname_from_help_total",
		"kaname_from_test_total",
		"othersvc_delta_total",
	} {
		require.NotContainsf(t, got, silent,
			"сборщик принял за ОБЪЯВЛЕНИЕ то, что им не является: %s", silent)
	}
	require.Equal(t, 1, census.declared)
}

// TestReverseCollectorRefusesAnEmptyWalk — пустой обход отличим от чистоты.
func TestReverseCollectorRefusesAnEmptyWalk(t *testing.T) {
	got, census, err := collectServiceSeries(synthPkg(t, map[string]string{}))
	require.NoError(t, err)
	require.Zero(t, census.filesRead,
		"пустой обход обязан быть НАЗВАН числом, а не выглядеть как чистое дерево")
	require.Empty(t, got)

	// Файл есть, а объявлений в нём нет — ВТОРОЕ пустое состояние, отличное от
	// первого: обход жив, предмета нет. Несущее утверждение проверки требует
	// ненулевого `declared` именно поэтому.
	got, census, err = collectServiceSeries(synthPkg(t, map[string]string{
		"m.go": synthHead + "var noop = 1\n",
	}))
	require.NoError(t, err)
	require.Equal(t, 1, census.filesRead)
	require.Zero(t, census.declared, "объявлений нет, а сборщик что-то собрал: %v", got)
}

// TestReverseGateJudgesOnlyTheServicePackage — ОСЬ, ради которой сборщик СВОЙ.
//
// Указатель производителей прямого направления пермиссивен и принимает имена
// ОБОИХ модулей. Взять его сюда значило бы потребовать описать на странице
// службы ряды ФУНДАМЕНТА, за чью страницу она не отвечает. Здесь это проверено
// поведением: корень обхода один, и ряд, объявленный ВНЕ его, не собирается.
func TestReverseGateJudgesOnlyTheServicePackage(t *testing.T) {
	base := t.TempDir()
	own := filepath.Join(base, "own")
	foundation := filepath.Join(base, "foundation")
	require.NoError(t, os.MkdirAll(own, 0o750))
	require.NoError(t, os.MkdirAll(foundation, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(own, "m.go"),
		[]byte(synthHead+`var a = prometheus.NewCounter(prometheus.CounterOpts{Name: "kaname_own_total"})
`), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(foundation, "m.go"),
		[]byte(synthHead+`var b = prometheus.NewCounter(prometheus.CounterOpts{Name: "kaname_foundation_total"})
`), 0o600))

	got, census, err := collectServiceSeries(own)
	require.NoError(t, err)
	require.Contains(t, got, "kaname_own_total")
	require.NotContains(t, got, "kaname_foundation_total",
		"обход вышел за пакет величин службы — страница обязана была бы описывать "+
			"чужие ряды, и проверка краснела бы на верном дереве")
	require.Equal(t, 1, census.declared)

	// ЗАКОННЫЙ БЛИЗНЕЦ: тот же ряд, названный СВОИМ корнем, — собирается.
	got, _, err = collectServiceSeries(foundation)
	require.NoError(t, err)
	require.Contains(t, got, "kaname_foundation_total")
}

// TestReverseCollectorNamesTheCoordinateOfEachDeclaration — находка обязана
// сказать, ГДЕ объявлен ряд: текст, называющий имя и не называющий места,
// посылает читателя искать по всему пакету.
func TestReverseCollectorNamesTheCoordinateOfEachDeclaration(t *testing.T) {
	got, _, err := collectServiceSeries(synthPkg(t, map[string]string{
		"m.go": synthHead + `var a = prometheus.NewCounter(prometheus.CounterOpts{Name: "kaname_alpha_total"})
`,
	}))
	require.NoError(t, err)
	require.Contains(t, got["kaname_alpha_total"], "m.go:",
		"координата объявления не названа: %q", got["kaname_alpha_total"])
}

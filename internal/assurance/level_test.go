// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// level_test.go — правило вывода уровня уверенности сессии по ВСЕЙ таблице
// (приёмка Ф11 `docs/engineering/acceptance/assurance-level-is-declared-by-our-session.md`,
// Р2, Р3, Р8, §8 группа «правило вывода»; задача kacho#1280).
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ УТВЕРЖДАЕТСЯ И ЧЕМ
//
// Правило Р2 переписано ЗДЕСЬ независимо от кода — предикатами над множеством
// предъявленного — и сверяется с производителем на КАЖДОМ подмножестве словаря
// (2^5) и на каждом сочетании флагов ключа (2^2). Проба по нескольким
// выбранным наборам зеленела бы на правиле, у которого снята строка, которой
// эти наборы не касаются; сплошной обход не оставляет строке места спрятаться,
// а расхождение называет НАБОР, на котором разошлись.
//
// Свойства правила проверяются отдельно, потому что у каждого свой отказ:
//
//   - монотонность (Р2): прибавленное предъявление уровень не понижает;
//   - закрытость словаря (Р8): способ вне словаря не собирается — у типа нет
//     экспортированного поля, и построить его снаружи пакета нечем;
//   - порядок строк — лестница: строка более высокого уровня стоит раньше;
//   - строка «3» различает ключ по флагам утверждения, а не по виду (Р3).
//
// Инъекция (§8): правило со снятой строкой краснеет ИМЕНЕМ НАБОРА — доказано
// подачей усечённой таблицы строк тому же сверщику, которым судится полная.
package assurance

import (
	"fmt"
	"reflect"
	"sort"
	"strings"
	"testing"
)

// oracleLevel — Р2, записанное ВТОРОЙ раз, независимо от строк производителя.
//
// Пустая строка означает «сессия не выдаётся». Таблица переписана дословно:
//
//	«3» — утверждение ключа с проверкой пользователя, ключом, не допускающим
//	      резервного копирования;
//	«2» — утверждение ключа (любое) · либо пароль И второй фактор (код по
//	      времени либо запасной код);
//	«1» — пароль · либо код восстановления.
func oracleLevel(ps []Presentation) string {
	has := func(m Method) bool {
		for _, p := range ps {
			if p.Method() == m {
				return true
			}
		}
		return false
	}
	deviceBoundVerifiedKey := false
	for _, p := range ps {
		if p.Method() == MethodWebAuthn && p.UserVerified() && !p.BackupEligible() {
			deviceBoundVerifiedKey = true
		}
	}
	switch {
	case deviceBoundVerifiedKey:
		return "3"
	case has(MethodWebAuthn):
		return "2"
	case has(MethodPassword) && (has(MethodTOTP) || has(MethodLookupSecret)):
		return "2"
	case has(MethodPassword), has(MethodRecoveryCode):
		return "1"
	default:
		return ""
	}
}

// keyFlags — все сочетания флагов утверждения ключа.
var keyFlags = []struct{ uv, backup bool }{
	{false, false}, {true, false}, {false, true}, {true, true},
}

// presentationOf — предъявление способа; ключ — с названными флагами.
func presentationOf(m Method, uv, backup bool) Presentation {
	switch m {
	case MethodPassword:
		return PasswordPresented()
	case MethodTOTP:
		return TOTPPresented()
	case MethodLookupSecret:
		return LookupSecretPresented()
	case MethodRecoveryCode:
		return RecoveryCodePresented()
	case MethodWebAuthn:
		return KeyAssertion(uv, backup)
	}
	panic(fmt.Sprintf("способ %q не имеет конструктора предъявления в пробе", m))
}

// wholeTable — каждое подмножество словаря × флаги ключа (когда он в наборе).
// Имя случая называет НАБОР: расхождение обязано быть адресуемым.
type tableCase struct {
	name      string
	presented []Presentation
}

func wholeTable() []tableCase {
	methods := Methods()
	var out []tableCase
	for mask := 0; mask < 1<<len(methods); mask++ {
		var chosen []Method
		for i, m := range methods {
			if mask&(1<<i) != 0 {
				chosen = append(chosen, m)
			}
		}
		hasKey := false
		for _, m := range chosen {
			if m == MethodWebAuthn {
				hasKey = true
			}
		}
		flags := keyFlags[:1]
		if hasKey {
			flags = keyFlags
		}
		for _, f := range flags {
			var ps []Presentation
			var names []string
			for _, m := range chosen {
				ps = append(ps, presentationOf(m, f.uv, f.backup))
				if m == MethodWebAuthn {
					names = append(names, fmt.Sprintf("%s(uv=%t,backup=%t)", m, f.uv, f.backup))
					continue
				}
				names = append(names, m.String())
			}
			name := "{" + strings.Join(names, ", ") + "}"
			out = append(out, tableCase{name: name, presented: ps})
		}
	}
	return out
}

// checkAgainstOracle — сверка производителя с оракулом по всей таблице.
// Возвращает расхождения, каждое — с именем набора.
func checkAgainstOracle(levelOf func([]Presentation) (Level, bool)) []string {
	var diffs []string
	for _, tc := range wholeTable() {
		want := oracleLevel(tc.presented)
		got, ok := levelOf(tc.presented)
		gotStr := ""
		if ok {
			gotStr = got.String()
		}
		if !ok && got != "" {
			diffs = append(diffs, fmt.Sprintf("%s: «не выдаётся» пришло с непустым уровнем %q", tc.name, got))
			continue
		}
		if gotStr != want {
			diffs = append(diffs, fmt.Sprintf("%s: правило даёт %q, оракул Р2 — %q", tc.name, gotStr, want))
		}
	}
	return diffs
}

// TestLevelOf_WholeTableMatchesRuleR2 — сплошная сверка: 2^5 наборов × флаги.
func TestLevelOf_WholeTableMatchesRuleR2(t *testing.T) {
	t.Parallel()
	table := wholeTable()
	if len(table) < 1<<len(Methods()) {
		t.Fatalf("таблица усечена: случаев %d при словаре из %d способов", len(table), len(Methods()))
	}
	diffs := checkAgainstOracle(LevelOf)
	t.Logf("перепись: наборов сверено %d, расхождений %d", len(table), len(diffs))
	for _, d := range diffs {
		t.Error(d)
	}
}

// TestLevelOf_IsMonotone — прибавленное предъявление уровень не понижает.
func TestLevelOf_IsMonotone(t *testing.T) {
	t.Parallel()
	rank := func(ps []Presentation) string {
		l, ok := LevelOf(ps)
		if !ok {
			return ""
		}
		return l.String()
	}
	table := wholeTable()
	checked := 0
	for _, small := range table {
		for _, big := range table {
			if !isSubset(small.presented, big.presented) {
				continue
			}
			checked++
			if rank(small.presented) > rank(big.presented) {
				t.Errorf("монотонность нарушена: %s даёт %q, надмножество %s — %q",
					small.name, rank(small.presented), big.name, rank(big.presented))
			}
		}
	}
	if checked == 0 {
		t.Fatal("ни одной пары «подмножество ⊆ надмножество» не сверено — проба ни о чём")
	}
	t.Logf("перепись: пар сверено %d", checked)
}

func isSubset(small, big []Presentation) bool {
	for _, s := range small {
		found := false
		for _, b := range big {
			if s == b {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}

// TestVocabulary_IsClosedByConstruction — способ вне словаря не собирается.
//
// У типа способа нет ни одного экспортированного поля, значит литерал
// `assurance.Method{...}` с именем снаружи пакета не компилируется; единственный
// способ получить значение — взять его из перечня. Перечень — ровно пять имён
// Р8, в устойчивом порядке.
func TestVocabulary_IsClosedByConstruction(t *testing.T) {
	t.Parallel()
	rt := reflect.TypeOf(Method{})
	if rt.Kind() != reflect.Struct {
		t.Fatalf("Method — %s, а не структура: значение вне словаря собирается преобразованием", rt.Kind())
	}
	for i := 0; i < rt.NumField(); i++ {
		if rt.Field(i).IsExported() {
			t.Errorf("поле %q экспортировано: литерал способа собирается снаружи пакета", rt.Field(i).Name)
		}
	}
	want := []string{"password", "totp", "lookup_secret", "webauthn", "recovery_code"}
	var got []string
	for _, m := range Methods() {
		got = append(got, m.String())
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("перечень словаря %v, ожидался %v (Р8)", got, want)
	}
	if (Method{}).String() != "" {
		t.Errorf("нулевой способ обязан быть безымянным, а он называется %q", (Method{}).String())
	}
	if rt2 := reflect.TypeOf(Presentation{}); rt2.NumField() == 0 {
		t.Fatal("предъявление без полей — флаги ключа негде нести")
	} else {
		for i := 0; i < rt2.NumField(); i++ {
			if rt2.Field(i).IsExported() {
				t.Errorf("поле предъявления %q экспортировано: флаги ставятся мимо конструкторов", rt2.Field(i).Name)
			}
		}
	}
}

// TestRule_RowsFollowTheLadder — строки правила стоят по убыванию уровня.
func TestRule_RowsFollowTheLadder(t *testing.T) {
	t.Parallel()
	if len(rows) == 0 {
		t.Fatal("таблица правила пуста")
	}
	for i := 1; i < len(rows); i++ {
		if rows[i].level.String() > rows[i-1].level.String() {
			t.Errorf("строка %d (%s, «%s») стоит после строки %d (%s, «%s»): лестница нарушена",
				i, rows[i].level, rows[i].name, i-1, rows[i-1].level, rows[i-1].name)
		}
	}
	seen := map[string]bool{}
	for _, r := range rows {
		if r.name == "" {
			t.Error("безымянная строка правила: находка не сможет её назвать")
		}
		if seen[r.name] {
			t.Errorf("имя строки %q объявлено дважды", r.name)
		}
		seen[r.name] = true
	}
}

// TestLevel3_TellsTheKeyByItsAssertionFlags — Р3: «3» только с проверкой
// пользователя и без допуска резервного копирования; остальные утверждения
// ключа — «2».
func TestLevel3_TellsTheKeyByItsAssertionFlags(t *testing.T) {
	t.Parallel()
	cases := []struct {
		uv, backup bool
		want       Level
	}{
		{true, false, Level3},
		{false, false, Level2},
		{true, true, Level2},
		{false, true, Level2},
	}
	for _, c := range cases {
		got, ok := LevelOf([]Presentation{KeyAssertion(c.uv, c.backup)})
		if !ok || got != c.want {
			t.Errorf("KeyAssertion(uv=%t, backup=%t) = %q,%t; ожидалось %q", c.uv, c.backup, got, ok, c.want)
		}
	}
}

// TestPresentableLevels_FollowsTheRuleOverWiredMethods — Р9: перечень
// предъявимых уровней выводится правилом из провязанных способов в ЛУЧШЕМ
// исходе их флагов. Поэтому один провязанный ключ даёт «3», а не «2, 3»: пол
// «2» такой полосе проходится через общую функцию ранжирования, и второй
// перечень «что ещё умеет ключ похуже» ничего бы не решал.
func TestPresentableLevels_FollowsTheRuleOverWiredMethods(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name  string
		wired []Method
		want  []string
	}{
		{"ничего не провязано", nil, nil},
		{"только пароль", []Method{MethodPassword}, []string{"1"}},
		{"пароль и код по времени", []Method{MethodPassword, MethodTOTP}, []string{"1", "2"}},
		{"пароль и запасной код", []Method{MethodPassword, MethodLookupSecret}, []string{"1", "2"}},
		{"только второй фактор", []Method{MethodTOTP}, nil},
		{"только ключ", []Method{MethodWebAuthn}, []string{"3"}},
		{"пароль и ключ", []Method{MethodPassword, MethodWebAuthn}, []string{"1", "3"}},
		{"только код восстановления", []Method{MethodRecoveryCode}, []string{"1"}},
		{"всё", Methods(), []string{"1", "2", "3"}},
		{"нулевой способ не считается", []Method{{}}, nil},
	}
	for _, c := range cases {
		got := PresentableLevels(c.wired).Strings()
		sort.Strings(got)
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s: PresentableLevels(%v) = %v, ожидалось %v", c.name, c.wired, got, c.want)
		}
	}
}

// TestInjection_RemovedRuleRowIsNamedByTheSet — снятая строка правила
// краснеет ИМЕНЕМ НАБОРА (§8, инъекция группы «правило вывода»).
//
// Тот же сверщик, что судит полную таблицу, получает таблицу без одной
// строки — и обязан назвать набор, на котором разошлись. Положительный
// контроль — полная таблица через тот же сверщик даёт ноль расхождений.
func TestInjection_RemovedRuleRowIsNamedByTheSet(t *testing.T) {
	t.Parallel()
	if diffs := checkAgainstOracle(func(ps []Presentation) (Level, bool) { return levelOf(rows, ps) }); len(diffs) != 0 {
		t.Fatalf("положительный контроль: полная таблица расходится с оракулом: %v", diffs)
	}
	for i, removed := range rows {
		cut := append(append([]row(nil), rows[:i]...), rows[i+1:]...)
		diffs := checkAgainstOracle(func(ps []Presentation) (Level, bool) { return levelOf(cut, ps) })
		if len(diffs) == 0 {
			t.Errorf("снятие строки «%s» (%s) не покраснело ни на одном наборе: строка мертва либо сверщик слеп",
				removed.name, removed.level)
			continue
		}
		if !strings.Contains(diffs[0], "{") {
			t.Errorf("расхождение не называет набор: %q", diffs[0])
		}
		t.Logf("снята строка «%s» (%s): расхождений %d, первое — %s", removed.name, removed.level, len(diffs), diffs[0])
	}
}

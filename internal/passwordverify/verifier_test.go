// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// verifier_test.go — проверяющий пароля следует за ХРАНИМЫМ значением
// (фаза Ф2, часть П2, задача `kacho#1268`; приёмка ID-PW-1, §5 PWV-01…07,
// PWV-11, PWV-14, PWV-15 в части Ф2).
//
// Полосы проверяющего — то, что производит ЭТА фаза; наружную половину каждого
// сценария (отказ входа, его код, тело и время) производит полоса входа Ф3, и
// здесь она не утверждается.
//
// Каждое отрицание стоит рядом с ПОЛОЖИТЕЛЬНЫМ контролем: «негодное не даёт
// совпадения» верно и о проверяющем, отвергающем всё.
package passwordverify_test

import (
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
)

const (
	rightPassword = "правильный пароль этого человека"
	wrongPassword = "не тот пароль"
)

// recordingObserver — приёмник исходов, считающий их по клеткам.
type recordingObserver struct {
	mu    sync.Mutex
	cells map[passwordverify.Outcome]int
}

func newRecordingObserver() *recordingObserver {
	o := &recordingObserver{cells: map[passwordverify.Outcome]int{}}
	// Клетка на КАЖДЫЙ объявленный исход заводится ДО первого события: ноль
	// событий обязан быть отличим от того, что клетки нет вовсе.
	for _, out := range passwordverify.Outcomes() {
		o.cells[out] = 0
	}
	return o
}

func (o *recordingObserver) VerificationObserved(outcome passwordverify.Outcome) {
	o.mu.Lock()
	defer o.mu.Unlock()
	o.cells[outcome]++
}

func (o *recordingObserver) count(outcome passwordverify.Outcome) int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.cells[outcome]
}

// newVerifier — проверяющий с названной ёмкостью и приёмником исходов.
func newVerifier(t *testing.T, capacity int, obs passwordverify.Observer) *passwordverify.Verifier {
	t.Helper()
	v, err := passwordverify.New(capacity, obs)
	require.NoErrorf(t, err, "проверяющий не построен при ёмкости %d", capacity)
	return v
}

// verifierOf — значение способа входа из строки материала.
func verifierOf(t *testing.T, material string) domain.LoginVerifier {
	t.Helper()
	lv, err := domain.NewLoginVerifier(material)
	require.NoError(t, err, "фикстура НЕ ПОСТРОЕНА: материал не обёрнут")
	return lv
}

// TestOutcomes_DictionaryIsClosedAndEveryOutcomeIsDistinct — исходов семь, и ни
// один не сводится к «не совпал» (Р3).
func TestOutcomes_DictionaryIsClosedAndEveryOutcomeIsDistinct(t *testing.T) {
	t.Parallel()

	outcomes := passwordverify.Outcomes()
	require.NotEmpty(t, outcomes, "словарь исходов пуст — «у каждого исхода свой счётчик» стало бы невыразимо")

	seen := map[passwordverify.Outcome]int{}
	for _, o := range outcomes {
		seen[o]++
		require.NotEmpty(t, string(o), "исход без имени не может иметь своего счётчика")
	}
	for o, n := range seen {
		require.Equalf(t, 1, n, "исход %q объявлен %d раза", o, n)
	}

	// Семь исходов Р3 названы поимённо: перечень, объявленный «не меньше
	// стольких-то», не заметил бы слияния двух в один.
	for _, want := range []passwordverify.Outcome{
		passwordverify.OutcomeMatched,
		passwordverify.OutcomeMismatched,
		passwordverify.OutcomeFormatNotInRegistry,
		passwordverify.OutcomeBodyNotParsable,
		passwordverify.OutcomeParamsAboveCeiling,
		passwordverify.OutcomeMaterialMissing,
		passwordverify.OutcomeCapacityExhausted,
	} {
		require.Containsf(t, outcomes, want, "исход %q не объявлен", want)
	}
	require.Len(t, outcomes, 7, "исходов не семь — перечень разошёлся с Р3")
	t.Logf("перепись: исходов в словаре %d", len(outcomes))
}

// TestOutcome_OurErrorsAreTerminalAndSayItThemselves — исход, названный НАШЕЙ
// ошибкой, терминален: повтор того же запроса не может дать иного (04.5).
func TestOutcome_OurErrorsAreTerminalAndSayItThemselves(t *testing.T) {
	t.Parallel()

	for _, o := range []passwordverify.Outcome{
		passwordverify.OutcomeFormatNotInRegistry,
		passwordverify.OutcomeBodyNotParsable,
		passwordverify.OutcomeParamsAboveCeiling,
	} {
		require.Truef(t, o.IsOurError(), "исход %q обязан быть назван нашей ошибкой", o)
		require.Truef(t, o.IsTerminal(), "исход %q обязан быть терминален: политики повтора у него нет", o)
	}

	// Положительный контроль: не всё подряд объявлено нашей ошибкой и
	// терминальным, иначе утверждения выше зеленели бы на предикате-константе.
	require.False(t, passwordverify.OutcomeMismatched.IsOurError(),
		"«не совпал» — не наша ошибка: это вход человека")
	require.False(t, passwordverify.OutcomeMaterialMissing.IsOurError(),
		"«материала нет» — законное состояние личности, а не повреждение")
	require.False(t, passwordverify.OutcomeCapacityExhausted.IsTerminal(),
		"исчерпание ёмкости преходяще: та же проверка после освобождения обязана пройти")
	require.False(t, passwordverify.OutcomeMatched.IsOurError())
}

// TestVerify_EachFormatOfTheRegistryIsReadByItsOwnVerifier — четыре клетки:
// формат × верность пароля (01.1, 02.1, 03.1, 03.7).
//
// Снятие любого из двух проверяющих роняет ровно свои две клетки, остальные
// молчат — это и есть доказательство того, что живы ОБЕ полосы.
func TestVerify_EachFormatOfTheRegistryIsReadByItsOwnVerifier(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name     string
		material string
		format   domain.PasswordHashFormat
	}{
		{"формат A — наследуемый, стоимость популяции", bcryptValue(t, rightPassword, 12), domain.PasswordHashFormatBcrypt},
		{"формат B — объявленный, параметры пола", argon2idValue(t, rightPassword, 65536, 3, 4, 32), domain.PasswordHashFormatArgon2id},
	}

	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			obs := newRecordingObserver()
			v := newVerifier(t, 4, obs)
			stored := verifierOf(t, c.material)

			got := v.Verify(stored, rightPassword)
			require.Equal(t, passwordverify.OutcomeMatched, got.Outcome,
				"верный пароль обязан давать «совпал» на своём формате")
			require.Equal(t, c.format, got.Format, "исход обязан называть формат, по которому читали")

			bad := v.Verify(stored, wrongPassword)
			require.Equal(t, passwordverify.OutcomeMismatched, bad.Outcome,
				"неверный пароль обязан давать «не совпал», а не иной исход")
			require.Equal(t, c.format, bad.Format)

			require.Equal(t, 1, obs.count(passwordverify.OutcomeMatched))
			require.Equal(t, 1, obs.count(passwordverify.OutcomeMismatched))
		})
	}
}

// TestVerify_FormatOutsideTheRegistryIsOurErrorWithAPositiveControl — признак
// формата вне перечня: терминальный отказ, названный нашей ошибкой (PWV-04).
func TestVerify_FormatOutsideTheRegistryIsOurErrorWithAPositiveControl(t *testing.T) {
	t.Parallel()

	obs := newRecordingObserver()
	v := newVerifier(t, 4, obs)

	// Соседние написания bcrypt и чужие функции: в перечень они не входят, и
	// хранилище материал не разбирает — такое значение в нём представимо.
	outside := []string{
		strings.Replace(bcryptValue(t, rightPassword, 10), "$2a$", "$2b$", 1),
		strings.Replace(bcryptValue(t, rightPassword, 10), "$2a$", "$2y$", 1),
		"$scrypt$ln=15,r=8,p=1$c2FsdA$aGFzaA",
		"$argon2i$v=19$m=65536,t=3,p=4$c2FsdA$aGFzaA",
		"$pbkdf2-sha256$29000$c2FsdA$aGFzaA",
		"нет разметки вовсе",
	}
	for _, material := range outside {
		got := v.Verify(verifierOf(t, material), rightPassword)
		require.Equalf(t, passwordverify.OutcomeFormatNotInRegistry, got.Outcome,
			"признак значения %.12q… обязан быть назван вне перечня, а не пропущен на успешный путь", material)
		require.Truef(t, got.Outcome.IsTerminal(), "исход обязан быть терминален")
	}

	// Положительный контроль: годное значение рядом даёт «совпал» верным
	// паролем — без него утверждения выше зеленели бы на проверяющем,
	// отвергающем всё.
	ok := v.Verify(verifierOf(t, bcryptValue(t, rightPassword, 10)), rightPassword)
	require.Equal(t, passwordverify.OutcomeMatched, ok.Outcome, "положительный контроль не прошёл")

	require.Equal(t, len(outside), obs.count(passwordverify.OutcomeFormatNotInRegistry),
		"счётчик исхода обязан расти на каждом событии")
}

// TestVerify_UnparsableBodyNeverMatches — признак известен, тело негодно
// (PWV-05, строки 05.1, 05.2, 05.5).
func TestVerify_UnparsableBodyNeverMatches(t *testing.T) {
	t.Parallel()

	good := bcryptValue(t, rightPassword, 10)
	goodArgon := argon2idValue(t, rightPassword, 65536, 3, 4, 32)

	broken := []struct{ name, material string }{
		{"формат A усечён", good[:20]},
		{"формат A без разделителя стоимости", strings.Replace(good, "$10$", "$10", 1)},
		{"формат A со стоимостью не числом", strings.Replace(good, "$10$", "$xx$", 1)},
		// Алфавит тела: длина цела, признак и стоимость разбираются, а символ
		// телу формата не принадлежит. Без разбора алфавита библиотека отвечает
		// отказом, НЕОТЛИЧИМЫМ от «не совпал», — и повреждение значения
		// читалось бы как поток неверных паролей.
		{"формат A с чужим символом в теле", good[:len(good)-1] + "!"},
		{"формат A с пробелом в теле", good[:len(good)-1] + " "},
		{"формат B усечён", goodArgon[:25]},
		{"формат B без сегмента параметров", strings.Replace(goodArgon, "m=65536,t=3,p=4", "", 1)},
		{"формат B с чужой версией разметки", strings.Replace(goodArgon, "v=19", "v=16", 1)},
		{"формат B с параметром не числом", strings.Replace(goodArgon, "t=3", "t=три", 1)},
		{"формат B без соли и тела", "$argon2id$v=19$m=65536,t=3,p=4"},
		{"формат B с солью не из base64", strings.Replace(goodArgon, "$argon2id$v=19$m=65536,t=3,p=4$", "$argon2id$v=19$m=65536,t=3,p=4$!!!$", 1)},
	}

	for _, c := range broken {
		t.Run(c.name, func(t *testing.T) {
			obs := newRecordingObserver()
			v := newVerifier(t, 4, obs)
			stored := verifierOf(t, c.material)

			// Ни при каком предъявленном значении — в том числе при ПУСТОМ.
			for _, presented := range []string{rightPassword, wrongPassword, ""} {
				got := v.Verify(stored, presented)
				require.Equalf(t, passwordverify.OutcomeBodyNotParsable, got.Outcome,
					"неразбираемое тело обязано давать «тело не разбирается» при предъявленном %q", presented)
				require.True(t, got.Outcome.IsOurError())
			}
			require.Equal(t, 3, obs.count(passwordverify.OutcomeBodyNotParsable))
			require.Zero(t, obs.count(passwordverify.OutcomeMatched), "«совпал» не даётся никогда")
		})
	}

	// Положительный контроль: годное значение того же формата даёт «совпал».
	obs := newRecordingObserver()
	v := newVerifier(t, 4, obs)
	require.Equal(t, passwordverify.OutcomeMatched, v.Verify(verifierOf(t, good), rightPassword).Outcome)
	require.Equal(t, passwordverify.OutcomeMatched, v.Verify(verifierOf(t, goodArgon), rightPassword).Outcome)
}

// TestVerify_ParametersOutsideAdmissibilityAreRefusedBeforeComputing — 05.6:
// значение, чья разметка цела, а параметр лежит за нижней границей
// допустимости либо за тем, что вмещает тип читателя, даёт «тело не
// разбирается» — без вычисления и без падения процесса.
func TestVerify_ParametersOutsideAdmissibilityAreRefusedBeforeComputing(t *testing.T) {
	t.Parallel()

	outside := []struct{ name, material string }{
		{"формат B: итераций ноль", argon2idValueWithParams(t, 65536, 0, 4)},
		{"формат B: параллельность ноль", argon2idValueWithParams(t, 65536, 3, 0)},
		{"формат B: память ниже 8·p", argon2idValueWithParams(t, 8, 3, 4)},
		{"формат B: параллельность 256 — тип читателя однобайтовый", argon2idValueWithParams(t, 65536, 3, 256)},
		{"формат B: длина ключа короче четырёх байт", "$argon2id$v=19$m=65536,t=3,p=4$c2FsdHNhbHRzYWx0c2E$YWJj"},
		{"формат A: стоимость ниже четырёх", "$2a$03$abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXY12"},
	}
	for _, c := range outside {
		t.Run(c.name, func(t *testing.T) {
			obs := newRecordingObserver()
			v := newVerifier(t, 4, obs)
			got := v.Verify(verifierOf(t, c.material), rightPassword)
			require.Equal(t, passwordverify.OutcomeBodyNotParsable, got.Outcome,
				"значение за границей допустимости обязано отвергаться разбором, а не вычисляться: "+
					"библиотека на части таких значений падает, а на памяти ниже 8·p молча считает иную функцию")
			require.Zero(t, obs.count(passwordverify.OutcomeMatched))
		})
	}

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ ровно на границе — каждый отличается от своего
	// отрицательного одним параметром.
	onTheEdge := []struct{ name, material string }{
		{"формат B: итераций 1, параллельность 1, память 8 КиБ, ключ 4 байта",
			argon2idValue(t, rightPassword, 8, 1, 1, 4)},
		{"формат A: стоимость 4", bcryptValue(t, rightPassword, 4)},
	}
	for _, c := range onTheEdge {
		t.Run("близнец: "+c.name, func(t *testing.T) {
			obs := newRecordingObserver()
			v := newVerifier(t, 4, obs)
			got := v.Verify(verifierOf(t, c.material), rightPassword)
			require.Equal(t, passwordverify.OutcomeMatched, got.Outcome,
				"значение РОВНО на границе допустимости обязано читаться: граница включена")
		})
	}

	// Близнец ВЕРХНЕЙ границы стоит отдельно, и его исход другой: параллельность
	// 255 читатель вмещает, поэтому разбор её ПРОПУСКАЕТ, а отвергает потолок
	// записи. Отличие от отрицательной полосы — один факт (255 против 256), и
	// разные исходы доказывают, что 256 отвергается именно РАЗБОРОМ: сойдись
	// оба к «выше потолка», проба не отличала бы разбор от сверки с потолком, а
	// приведённая к однобайтовому типу параллельность дала бы панику.
	obs := newRecordingObserver()
	v := newVerifier(t, 4, obs)
	got := v.Verify(verifierOf(t, argon2idValueWithParams(t, 65536, 1, 255)), rightPassword)
	require.Equal(t, passwordverify.OutcomeParamsAboveCeiling, got.Outcome,
		"параллельность 255 обязана дойти до сверки с потолком: тип читателя её вмещает")
}

// TestVerify_MissingMaterialIsNotAMismatch — PWV-06, строки 06.1…06.4.
func TestVerify_MissingMaterialIsNotAMismatch(t *testing.T) {
	t.Parallel()

	obs := newRecordingObserver()
	v := newVerifier(t, 4, obs)

	// Материала нет: нулевое значение типа. Отсутствие НЕ приводится к пустой
	// строке и не сравнивается с ней — сравнение пустого с пустым дало бы
	// «совпал» у человека, пароля не заводившего.
	for _, presented := range []string{rightPassword, wrongPassword, ""} {
		got := v.Verify(domain.LoginVerifier{}, presented)
		require.Equalf(t, passwordverify.OutcomeMaterialMissing, got.Outcome,
			"отсутствие материала обязано быть своим исходом при предъявленном %q", presented)
		require.NotEqual(t, passwordverify.OutcomeMismatched, got.Outcome,
			"«материала нет» и «не совпал» не имеют общего представления")
	}
	require.Equal(t, 3, obs.count(passwordverify.OutcomeMaterialMissing))
	require.Zero(t, obs.count(passwordverify.OutcomeMatched), "пустой пароль не даёт совпадения на пустом материале")

	// Положительный контроль: близнец, у которого материал заведён.
	twin := v.Verify(verifierOf(t, bcryptValue(t, rightPassword, 10)), rightPassword)
	require.Equal(t, passwordverify.OutcomeMatched, twin.Outcome, "близнец с материалом обязан входить")
}

// TestVerify_ParametersAboveTheCeilingAreRefusedWithoutComputing — PWV-14,
// строки 14.1 и 14.2: на КАЖДОМ формате и по КАЖДОМУ параметру.
func TestVerify_ParametersAboveTheCeilingAreRefusedWithoutComputing(t *testing.T) {
	t.Parallel()

	above := []struct{ name, material string }{
		{"формат A: стоимость выше потолка 14", bcryptValue(t, rightPassword, 15)},
		{"формат B: память выше потолка", argon2idValueWithParams(t, 131073, 10, 8)},
		{"формат B: итераций выше потолка", argon2idValueWithParams(t, 131072, 11, 8)},
		{"формат B: параллельность выше потолка", argon2idValueWithParams(t, 131072, 10, 9)},
	}
	for _, c := range above {
		t.Run(c.name, func(t *testing.T) {
			obs := newRecordingObserver()
			v := newVerifier(t, 4, obs)
			got := v.Verify(verifierOf(t, c.material), rightPassword)
			require.Equal(t, passwordverify.OutcomeParamsAboveCeiling, got.Outcome,
				"параметр выше потолка обязан давать свой исход, отличный и от «не совпал», и от «тело не разбирается»")
			require.True(t, got.Outcome.IsOurError())
			require.Equal(t, 1, obs.count(passwordverify.OutcomeParamsAboveCeiling))
		})
	}

	// Положительный контроль и ГРАНИЦА: ровно на потолке — «совпал».
	onCeiling := []struct{ name, material string }{
		{"формат A ровно на потолке", bcryptValue(t, rightPassword, 14)},
		{"формат B ровно на потолке", argon2idValue(t, rightPassword, 131072, 10, 8, 32)},
	}
	for _, c := range onCeiling {
		t.Run("близнец: "+c.name, func(t *testing.T) {
			obs := newRecordingObserver()
			v := newVerifier(t, 4, obs)
			got := v.Verify(verifierOf(t, c.material), rightPassword)
			require.Equal(t, passwordverify.OutcomeMatched, got.Outcome, "потолок включён")
		})
	}
}

// TestVerify_RefusalAboveTheCeilingDoesNotStartTheComputation — 14.3.
//
// Мерится РЕСУРС, который тратит параметр: у формата A это процессорное время
// (память bcrypt от стоимости не зависит), у формата B — память сверх того.
// Одно время по часам этого не различает: параллельность argon2id сокращает
// время по часам, но не работу.
func TestVerify_RefusalAboveTheCeilingDoesNotStartTheComputation(t *testing.T) {
	t.Parallel()

	obs := newRecordingObserver()
	v := newVerifier(t, 4, obs)

	// Формат A: процессорное время отказа против проверки НА ПОТОЛКЕ.
	onCeiling := verifierOf(t, bcryptValue(t, rightPassword, 14))
	aboveCeiling := verifierOf(t, bcryptValue(t, rightPassword, 15))

	start := time.Now()
	require.Equal(t, passwordverify.OutcomeMatched, v.Verify(onCeiling, rightPassword).Outcome)
	onCeilingTook := time.Since(start)

	start = time.Now()
	require.Equal(t, passwordverify.OutcomeParamsAboveCeiling, v.Verify(aboveCeiling, rightPassword).Outcome)
	refusalTook := time.Since(start)

	require.Lessf(t, refusalTook*10, onCeilingTook,
		"отказ выше потолка занял %s при проверке на потолке %s — вычисление началось до сверки с потолком",
		refusalTook, onCeilingTook)

	// Формат B: заявленной памяти процесс не выделяет.
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	require.Equal(t, passwordverify.OutcomeParamsAboveCeiling,
		v.Verify(verifierOf(t, argon2idValueWithParams(t, 1048576, 3, 4)), rightPassword).Outcome)
	runtime.ReadMemStats(&after)

	const claimed = uint64(1048576) * 1024 // 1 ГиБ — заявленная значением память
	allocated := after.TotalAlloc - before.TotalAlloc
	require.Lessf(t, allocated, claimed/4,
		"отказ выделил %d байт при заявленных значением %d — вычисление началось", allocated, claimed)
	t.Logf("перепись: отказ на потолке формата A %s против проверки %s; формат B выделил %d байт из заявленных %d",
		refusalTook, onCeilingTook, allocated, claimed)
}

// TestVerify_CapacityExhaustedIsItsOwnOutcome — PWV-15, строки 15.1, 15.2, 15.6.
func TestVerify_CapacityExhaustedIsItsOwnOutcome(t *testing.T) {
	t.Parallel()

	// Ёмкость — величина без умолчания: незаданная либо не положительная даёт
	// отказ построения, называющий её. Ноль означал бы отказ каждой проверки, а
	// не «без предела».
	for _, bad := range []int{0, -1, -100} {
		_, err := passwordverify.New(bad, newRecordingObserver())
		require.Errorf(t, err, "ёмкость %d обязана быть отвергнута", bad)
		require.Contains(t, err.Error(), "capacity", "отказ обязан называть ручку")
	}

	obs := newRecordingObserver()
	v := newVerifier(t, 1, obs)
	stored := verifierOf(t, bcryptValue(t, rightPassword, 10))

	// Ёмкость занята целиком: держим её, пока идёт вторая проверка.
	held := make(chan struct{})
	release := make(chan struct{})
	go func() {
		v.WithCapacity(func() {
			close(held)
			<-release
		})
	}()
	<-held

	got := v.Verify(stored, rightPassword)
	require.Equal(t, passwordverify.OutcomeCapacityExhausted, got.Outcome,
		"исчерпание обязано быть своим исходом, а не «не совпал» и не нашей ошибкой")
	require.False(t, got.Outcome.IsOurError())

	// Исчерпание не зависит ни от наличия материала: полоса «материала нет»
	// занимает ту же ёмкость (15.4) — иначе под нагрузкой отказ по ёмкости
	// сообщал бы, что у личности есть пароль.
	missing := v.Verify(domain.LoginVerifier{}, rightPassword)
	require.Equal(t, passwordverify.OutcomeCapacityExhausted, missing.Outcome,
		"полоса «материала нет» обязана занимать ту же ёмкость")

	close(release)

	// Положительный контроль: после освобождения та же проверка того же верного
	// пароля даёт «совпал».
	require.Eventually(t, func() bool {
		return v.Verify(stored, rightPassword).Outcome == passwordverify.OutcomeMatched
	}, 5*time.Second, 10*time.Millisecond, "после освобождения ёмкости проверка обязана проходить")

	require.GreaterOrEqual(t, obs.count(passwordverify.OutcomeCapacityExhausted), 2)
}

// TestVerify_CapacityIsTakenAtomically — «спросить» и «занять» не разнесены:
// под конкуренцией одновременных проверок не бывает больше ёмкости.
//
// Красное обязано быть ДЕТЕРМИНИРОВАННЫМ, а не выпадать в одном прогоне из
// десяти, поэтому проба не полагается на удачу планировщика: соискатели ждут
// общего сигнала и входят разом, а занявший место держит его, пока не вошли
// все, кто мог. На разнесённой паре «прочитать счётчик — увеличить счётчик»
// каждый соискатель видит свободное место и заходит; на атомарном захвате
// внутрь попадает ровно ёмкость.
func TestVerify_CapacityIsTakenAtomically(t *testing.T) {
	t.Parallel()

	const (
		capacity  = 3
		claimants = 256
	)
	v := newVerifier(t, capacity, newRecordingObserver())

	var mu sync.Mutex
	inside, peak, admitted := 0, 0, 0

	start := make(chan struct{})
	var ready, done sync.WaitGroup
	ready.Add(claimants)
	done.Add(claimants)
	for i := 0; i < claimants; i++ {
		go func() {
			defer done.Done()
			ready.Done()
			<-start
			v.WithCapacity(func() {
				mu.Lock()
				inside++
				admitted++
				if inside > peak {
					peak = inside
				}
				mu.Unlock()
				// Место держится, пока разом вошедшие соискатели не проявятся:
				// освободи его сразу — и пик замерил бы скорость планировщика,
				// а не ёмкость.
				time.Sleep(50 * time.Millisecond)
				mu.Lock()
				inside--
				mu.Unlock()
			})
		}()
	}
	ready.Wait()
	close(start)
	done.Wait()

	t.Logf("перепись: соискателей %d, внутрь допущено %d, пик одновременных %d при ёмкости %d",
		claimants, admitted, peak, capacity)
	require.LessOrEqual(t, peak, capacity,
		"одновременных проверок было %d при ёмкости %d — «есть ли место» и «занять место» разнесены во времени",
		peak, capacity)
	require.Positive(t, peak, "внутрь не зашёл никто — проба ничего не измерила")
}

// TestVerify_EveryOutcomeIsObserved — 04.4, 05.4, 06.7, 14.5, 15.5: у каждого
// исхода свой счётчик, и клетка заведена ДО первого события.
func TestVerify_EveryOutcomeIsObserved(t *testing.T) {
	t.Parallel()

	obs := newRecordingObserver()
	for _, o := range passwordverify.Outcomes() {
		require.Containsf(t, obs.cells, o, "клетка исхода %q не заведена до первого события", o)
		require.Zerof(t, obs.count(o), "клетка исхода %q заведена не нулём", o)
	}

	v := newVerifier(t, 1, obs)
	v.Verify(verifierOf(t, bcryptValue(t, rightPassword, 10)), rightPassword)
	v.Verify(verifierOf(t, bcryptValue(t, rightPassword, 10)), wrongPassword)
	v.Verify(verifierOf(t, "$scrypt$ln=15$c2FsdA$aGFzaA"), rightPassword)
	v.Verify(verifierOf(t, "$2a$xx$сломано"), rightPassword)
	v.Verify(verifierOf(t, bcryptValue(t, rightPassword, 15)), rightPassword)
	v.Verify(domain.LoginVerifier{}, rightPassword)

	for _, o := range []passwordverify.Outcome{
		passwordverify.OutcomeMatched,
		passwordverify.OutcomeMismatched,
		passwordverify.OutcomeFormatNotInRegistry,
		passwordverify.OutcomeBodyNotParsable,
		passwordverify.OutcomeParamsAboveCeiling,
		passwordverify.OutcomeMaterialMissing,
	} {
		require.Equalf(t, 1, obs.count(o), "исход %q не сосчитан своим счётчиком", o)
	}
}

// TestVerify_ChoiceOfVerifierFollowsTheStoredValue — Р1 и 07.1: исход лежащих
// значений не зависит ни от чего, кроме самого значения.
//
// Проверяющий настройки «что писать» не принимает ВОВСЕ — это и есть то, чем
// свойство держится в коде; здесь утверждается наблюдаемое следствие: два
// проверяющих, построенных одинаково, читают оба формата одинаково.
func TestVerify_ChoiceOfVerifierFollowsTheStoredValue(t *testing.T) {
	t.Parallel()

	first := newVerifier(t, 4, newRecordingObserver())
	second := newVerifier(t, 8, newRecordingObserver())

	for _, material := range []string{
		bcryptValue(t, rightPassword, 12),
		argon2idValue(t, rightPassword, 65536, 3, 4, 32),
		argon2idValue(t, rightPassword, 131072, 10, 8, 32),
	} {
		stored := verifierOf(t, material)
		require.Equal(t, first.Verify(stored, rightPassword).Outcome, second.Verify(stored, rightPassword).Outcome)
		require.Equal(t, passwordverify.OutcomeMatched, first.Verify(stored, rightPassword).Outcome)
	}
}

// TestVerifier_F3_31_AbsentMaterialIsComputedAgainstADecoy — с выравнивающим
// значением проверка «материала нет» ВЫЧИСЛЯЕТСЯ и стоит как настоящая, а исход
// остаётся «материала нет» даже тогда, когда предъявлен пароль самого
// выравнивающего значения (иначе ложное значение стало бы вторым паролем каждой
// личности без способа входа). Пустое и нечитаемое выравнивающее — отказ.
func TestVerifier_F3_31_AbsentMaterialIsComputedAgainstADecoy(t *testing.T) {
	obs := newRecordingObserver()
	v := newVerifier(t, 2, obs)
	require.Error(t, v.SetDecoy(domain.LoginVerifier{}), "пустое выравнивающее — отказ")
	require.Error(t, v.SetDecoy(verifierOf(t, "$unknown$format")), "нечитаемое выравнивающее — отказ")

	hasher, err := passwordverify.NewHasher(passwordverify.Declared{Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: 65536, domain.CostParamArgon2Iterations: 3, domain.CostParamArgon2Parallelism: 4}})
	require.NoError(t, err)
	decoy, err := hasher.Hash("decoy password of the day")
	require.NoError(t, err)
	require.NoError(t, v.SetDecoy(decoy))

	res := v.Verify(domain.LoginVerifier{}, "decoy password of the day")
	require.Equal(t, passwordverify.OutcomeMaterialMissing, res.Outcome, "пароль выравнивающего значения не открывает ничего")
	res = v.Verify(domain.LoginVerifier{}, "anything else")
	require.Equal(t, passwordverify.OutcomeMaterialMissing, res.Outcome)
	require.Equal(t, 2, obs.count(passwordverify.OutcomeMaterialMissing), "исход считается как «материала нет», не как «не совпал»")
	require.Zero(t, obs.count(passwordverify.OutcomeMismatched))
	require.Zero(t, obs.count(passwordverify.OutcomeMatched))

	// Стоимость: проверка против пустого с выравниванием стоит как настоящая
	// того же класса — не короче половины её (грубая граница, устойчивая к
	// шуму; точная полоса — измерительная проба Ф3-31 полосы входа).
	real, err := hasher.Hash("real password")
	require.NoError(t, err)
	start := time.Now()
	for i := 0; i < 3; i++ {
		v.Verify(real, "wrong")
	}
	realCost := time.Since(start) / 3
	start = time.Now()
	for i := 0; i < 3; i++ {
		v.Verify(domain.LoginVerifier{}, "wrong")
	}
	absentCost := time.Since(start) / 3
	t.Logf("стоимость: настоящая %v · «материала нет» с выравниванием %v", realCost, absentCost)
	require.Greater(t, absentCost, realCost/2, "полоса «материала нет» отвечает много быстрее настоящей — оракул существования")
}

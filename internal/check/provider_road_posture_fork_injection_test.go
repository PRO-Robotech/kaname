// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_road_posture_fork_injection_test.go — ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ для
// гейта «у каждого потребителя дороги своё решение о посадке» (задача kaname#338).
//
// ─────────────────────────────────────────────────────────────────────────────
// ДЕФЕКТ И БЛИЗНЕЦ ОТЛИЧАЮТСЯ РОВНО ОДНИМ ФАКТОМ
//
// Каждая пара — один и тот же потребитель одной формы записи; различает их один
// знак, названный у пары. Иначе красное могло бы прийти от соседа, и инъекция
// доказывала бы не то свойство.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРОВЕРКА НА ВАКУУМНОСТЬ — ОТДЕЛЬНОЕ УТВЕРЖДЕНИЕ
//
// Каждая инъекция сверх исхода утверждает ПЕРЕПИСЬ: развилок и строителей
// осмотрено ровно столько, сколько подано. Молчание на близнеце неотличимо от
// молчания на входе, которого разбор не увидел вовсе.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// roadForkConsumer — один потребитель через развилку. builtBody и absentArm —
// единственное, что меняется между дефектом и близнецом.
func roadForkConsumer(builtBody, absentArm string) []byte {
	return []byte(`package main

func buildKeys(cfg Config, obs Observer) (*Issue, *Revoke) {
	return ` + providerRoadFork + `(cfg, obs,
		func(road *adminRoad) (*Issue, *Revoke) {
			` + builtBody + `
		},
		` + absentArm + `)
}
`)
}

const roadForkAbsentLiteral = `func() (*Issue, *Revoke) { return NewIssue(), NewRevoke() }`

func scanRoadSynthetic(t *testing.T, src []byte, builders ...string) ([]check.ProviderRoadFinding, check.ProviderRoadConsumerCensus) {
	t.Helper()
	found, census, err := check.ScanProviderRoadConsumers("synthetic/root.go", src, providerRoadFork, builders)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if census.Funcs != 1 {
		t.Fatalf("функций осмотрено %d, подана 1 — вход не прочитан, и вердикт ниже беспредметен", census.Funcs)
	}
	return found, census
}

func roadFindingsOfKind(found []check.ProviderRoadFinding, kind string) []check.ProviderRoadFinding {
	var out []check.ProviderRoadFinding
	for _, f := range found {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

// ── ось 1: одно решение на двух потребителей (исходная форма задачи) ─────────
//
// Один факт: довод `road` у второго конструктора.

func TestRoadForkInjection_OneArmForTwoConsumersIsFound(t *testing.T) {
	t.Parallel()
	found, census := scanRoadSynthetic(t, roadForkConsumer(
		`return NewIssue(road), NewRevoke(road)`, roadForkAbsentLiteral))
	if census.ForkCalls != 1 {
		t.Fatalf("вставка не долетела: развилок осмотрено %d, подана 1", census.ForkCalls)
	}
	shared := roadFindingsOfKind(found, check.RoadFindingSharedDecision)
	if len(shared) != 1 {
		t.Fatalf("одно решение на двух потребителей НЕ поймано: %+v", found)
	}
	if !strings.Contains(shared[0].Detail, "NewIssue") || !strings.Contains(shared[0].Detail, "NewRevoke") {
		t.Errorf("находка не называет обоих принявших: %q", shared[0].Detail)
	}
	if shared[0].Func != "buildKeys" || shared[0].Line != 5 {
		t.Errorf("находка названа %s:%d, ветвь стоит в buildKeys:5", shared[0].Func, shared[0].Line)
	}
	if census.ArmReceptions != 2 {
		t.Errorf("приёмов из ветви засчитано %d, подано 2", census.ArmReceptions)
	}
}

func TestRoadForkInjection_OneArmForOneConsumerIsSilent(t *testing.T) {
	t.Parallel()
	found, census := scanRoadSynthetic(t, roadForkConsumer(
		`return NewIssue(road), NewRevoke()`, roadForkAbsentLiteral))
	if census.ForkCalls != 1 || census.ArmReceptions != 1 {
		t.Fatalf("вставка не долетела: развилок %d, приёмов %d, подано 1 и 1 — молчание "+
			"ниже ничего не доказывает", census.ForkCalls, census.ArmReceptions)
	}
	if len(found) != 0 {
		t.Fatalf("гейт краснеет на ЗАКОННОМ потребителе: %+v — он обязан молчать, "+
			"иначе всякая починка невозможна", found)
	}
}

// ── ось 2: ветвь другой посадки — nil ─────────────────────────────────────────
//
// Один факт: `nil` на месте литерала ветви. Компилятор такой вызов пропускает.

func TestRoadForkInjection_NilArmIsFound(t *testing.T) {
	t.Parallel()
	found, census := scanRoadSynthetic(t, roadForkConsumer(`return NewIssue(road), NewRevoke()`, `nil`))
	if census.ForkCalls != 1 {
		t.Fatalf("вставка не долетела: развилок осмотрено %d, подана 1", census.ForkCalls)
	}
	nilArm := roadFindingsOfKind(found, check.RoadFindingArmNil)
	if len(nilArm) != 1 {
		t.Fatalf("ветвь nil НЕ поймана: %+v", found)
	}
	if !strings.Contains(nilArm[0].Kind, "паникует") {
		t.Errorf("находка называет не причину: %q", nilArm[0].Kind)
	}
}

// Близнец оси 2 — `TestRoadForkInjection_OneArmForOneConsumerIsSilent`: тот же
// вход с литералом на месте `nil`.

// ── ось 3: ветвь не литералом ─────────────────────────────────────────────────
//
// Один факт: имя функции на месте литерала ветви построенной посадки.

func TestRoadForkInjection_NamedBuiltArmIsFound(t *testing.T) {
	t.Parallel()
	src := []byte(`package main

func buildKeys(cfg Config, obs Observer) (*Issue, *Revoke) {
	return ` + providerRoadFork + `(cfg, obs, keysOnRoad, ` + roadForkAbsentLiteral + `)
}
`)
	found, census := scanRoadSynthetic(t, src)
	if census.ForkCalls != 1 {
		t.Fatalf("вставка не долетела: развилок осмотрено %d, подана 1", census.ForkCalls)
	}
	named := roadFindingsOfKind(found, check.RoadFindingArmNotLiteral)
	if len(named) != 1 || !strings.Contains(named[0].Detail, "keysOnRoad") {
		t.Fatalf("ветвь, записанная именем, НЕ поймана либо не названа: %+v", found)
	}
}

// ── ось 4: дорога уходит формой, которой разбор не прослеживает ───────────────
//
// Один факт: `&` перед доводом.

func TestRoadForkInjection_RoadLeavingTheArmByAddressIsFound(t *testing.T) {
	t.Parallel()
	found, _ := scanRoadSynthetic(t, roadForkConsumer(`return NewIssue(&road), NewRevoke()`, roadForkAbsentLiteral))
	untracked := roadFindingsOfKind(found, check.RoadFindingUntrackedForm)
	if len(untracked) != 1 || !strings.Contains(untracked[0].Detail, "адреса") {
		t.Fatalf("дорога, ушедшая взятием адреса, НЕ поймана либо форма не названа: %+v", found)
	}
	if len(roadFindingsOfKind(found, check.RoadFindingNoReception)) != 1 {
		t.Errorf("ветвь, ни одному потребителю дорогу доводом не отдавшая, не названа: %+v", found)
	}
}

// Захват во вложенное замыкание — отдельная ось: он стоит в позиции довода,
// и без неё разбор засчитал бы его приёмом ветви.
func TestRoadForkInjection_RoadCapturedByANestedClosureIsFound(t *testing.T) {
	t.Parallel()
	found, census := scanRoadSynthetic(t, roadForkConsumer(
		`return NewIssue(road), Later(func() *Revoke { return NewRevoke(road) })`, roadForkAbsentLiteral))
	captured := roadFindingsOfKind(found, check.RoadFindingUntrackedForm)
	if len(captured) != 1 || !strings.Contains(captured[0].Detail, "замыкание") {
		t.Fatalf("захват дороги вложенным замыканием НЕ пойман: %+v", found)
	}
	if census.ArmReceptions != 1 {
		t.Errorf("захват засчитан приёмом ветви: приёмов %d, законный один", census.ArmReceptions)
	}
}

// ── ось 5: строитель мимо развилки ────────────────────────────────────────────
//
// Один факт — в ФАЙЛЕ СТРОИТЕЛЯ: читает он резолвер адреса либо его безопасного
// близнеца. Потребитель один и тот же, строители выводятся тем же производителем,
// что у гейта по дереву.

const roadUnforkedConsumer = `package main

func buildKeys(cfg Config, obs Observer) *Issue {
	road, built := mustRoad(cfg, obs)
	if !built {
		return NewIssue(nil)
	}
	return NewIssue(road)
}
`

func roadUnforkedBuilder(reads string) []byte {
	return []byte(`package main

func mustRoad(cfg Config, obs Observer) (*adminRoad, bool) {
	return newAdminRoad(cfg.AuthN.` + reads + `()), true
}
`)
}

func roadBuildersOf(t *testing.T, src []byte) ([]check.ProviderAddressRead, []string) {
	t.Helper()
	reads, _, err := check.ScanProviderAddressReads("synthetic/builder.go", src,
		providerAddressResolver, providerAddressTwin)
	if err != nil {
		t.Fatalf("разбор строителя: %v", err)
	}
	return reads, check.ProviderRoadBuilders(reads)
}

func TestRoadForkInjection_BuilderOutsideTheForkIsFound(t *testing.T) {
	t.Parallel()
	reads, builders := roadBuildersOf(t, roadUnforkedBuilder(providerAddressResolver))
	if len(builders) != 1 || builders[0] != "mustRoad" {
		t.Fatalf("вставка не долетела: строители %v, подан mustRoad", builders)
	}
	outside := check.ProviderRoadBuildersOutsideTheFork(reads, providerRoadFork)
	if len(outside) != 1 || outside[0].Func != "mustRoad" {
		t.Fatalf("строитель мимо развилки НЕ пойман: %+v", outside)
	}

	found, census := scanRoadSynthetic(t, []byte(roadUnforkedConsumer), builders...)
	if census.UnforkedCalls != 1 || census.ForkCalls != 0 {
		t.Fatalf("вставка не долетела: вызовов строителя мимо развилки %d, развилок %d; "+
			"подано 1 и 0", census.UnforkedCalls, census.ForkCalls)
	}
	if len(roadFindingsOfKind(found, check.RoadFindingUnforkedCall)) != 1 {
		t.Fatalf("потребитель первого рода мимо развилки НЕ пойман: %+v", found)
	}
	// Приём — `NewIssue(road)`: под ответом о посадке, и это не устройство.
	received := roadFindingsOfKind(found, check.RoadFindingUnforkedReception)
	if len(received) != 1 || !strings.Contains(received[0].Detail, "NewIssue") || received[0].Line != 8 {
		t.Fatalf("потребитель второго рода, принявший дорогу из строителя-ответа, НЕ пойман "+
			"либо назван не там: %+v", received)
	}
}

func TestRoadForkInjection_FunctionReadingTheTwinIsNoBuilder(t *testing.T) {
	t.Parallel()
	reads, builders := roadBuildersOf(t, roadUnforkedBuilder(providerAddressTwin))
	if len(reads) != 0 || len(builders) != 0 {
		t.Fatalf("близнец резолвера принят за строительство дороги: чтения %+v", reads)
	}
	found, census := scanRoadSynthetic(t, []byte(roadUnforkedConsumer), builders...)
	if census.UnforkedCalls != 0 {
		t.Fatalf("вызов функции, дороги не строящей, засчитан строителем: %+v", census)
	}
	if len(found) != 0 {
		t.Fatalf("гейт краснеет на функции, которая дороги не строит: %+v", found)
	}
}

// ── ось 6: развилка взята значением ───────────────────────────────────────────
//
// Один факт: вызов через переменную. Явная подстановка типов у близнеца —
// законная форма вызова, и разбор обязан её знать.

func TestRoadForkInjection_ForkTakenAsAValueIsFound(t *testing.T) {
	t.Parallel()
	src := []byte(`package main

func buildKeys(cfg Config, obs Observer) (*Issue, *Revoke) {
	fork := ` + providerRoadFork + `[*Issue, *Revoke]
	return fork(cfg, obs, func(road *adminRoad) (*Issue, *Revoke) { return NewIssue(road), NewRevoke() },
		` + roadForkAbsentLiteral + `)
}
`)
	found, _ := scanRoadSynthetic(t, src)
	if len(roadFindingsOfKind(found, check.RoadFindingForkAsValue)) != 1 {
		t.Fatalf("развилка, взятая значением, НЕ поймана: %+v", found)
	}
}

func TestRoadForkInjection_ExplicitInstantiationIsACall(t *testing.T) {
	t.Parallel()
	src := []byte(`package main

func buildKeys(cfg Config, obs Observer) (*Issue, *Revoke) {
	return ` + providerRoadFork + `[*Issue, *Revoke](cfg, obs,
		func(road *adminRoad) (*Issue, *Revoke) { return NewIssue(road), NewRevoke() },
		` + roadForkAbsentLiteral + `)
}
`)
	found, census := scanRoadSynthetic(t, src)
	if census.ForkCalls != 1 || census.ArmReceptions != 1 {
		t.Fatalf("вызов с явной подстановкой типов не признан развилкой: %+v", census)
	}
	if len(found) != 0 {
		t.Fatalf("законная форма вызова объявлена находкой: %+v", found)
	}
}

// ── предпосылка ───────────────────────────────────────────────────────────────

func TestRoadForkPremise_NoBuilderIsNotAVerdict(t *testing.T) {
	t.Parallel()
	live := check.ProviderRoadConsumerCensus{Funcs: 10, ForkCalls: 3, ArmReceptions: 3}

	err := check.ProviderRoadConsumerPremise(1000, providerRoadCensusFloor, nil, live, providerRoadFork)
	if err == nil {
		t.Fatal("обход без строителя дороги вынес вердикт: «находок ноль» здесь " +
			"означает «прочитано ноль»")
	}
	if !strings.Contains(err.Error(), providerRoadFork) {
		t.Errorf("отказ предпосылки не назвал развилку, которая уходит вместе с дорогой: %v", err)
	}

	noConsumers := check.ProviderRoadConsumerCensus{Funcs: 10}
	if err := check.ProviderRoadConsumerPremise(1000, providerRoadCensusFloor,
		[]string{providerRoadFork}, noConsumers, providerRoadFork); err == nil {
		t.Fatal("строитель есть, потребителей ноль — а вердикт вынесен")
	}

	if err := check.ProviderRoadConsumerPremise(1, providerRoadCensusFloor,
		[]string{providerRoadFork}, live, providerRoadFork); err == nil {
		t.Fatal("обход, разобравший 1 файл при пороге, вынес вердикт")
	}

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ: живой обход предпосылку проходит, иначе отказы
	// выше зеленели бы на предпосылке, отвергающей всё подряд.
	if err := check.ProviderRoadConsumerPremise(1000, providerRoadCensusFloor,
		[]string{providerRoadFork}, live, providerRoadFork); err != nil {
		t.Fatalf("предпосылка отвергает ЖИВОЙ обход: %v", err)
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_road_posture_answer_injection_test.go — ИНЪЕКЦИЯ В ОБЕ СТОРОНЫ для
// гейта «ответ о посадке принят» (задача kaname#313).
//
// ─────────────────────────────────────────────────────────────────────────────
// ДЕФЕКТ И БЛИЗНЕЦ ОТЛИЧАЮТСЯ РОВНО ОДНИМ ФАКТОМ
//
// Оба входа — один и тот же потребитель, одной формы записи, в одном
// синтаксическом положении. Различает их ОДИН знак: имя, с которым связан
// второй возвращаемый ответ, — `_` против `built`. Если бы входы отличались
// ещё чем-нибудь (числом вызовов, наличием функции, именем строителя), красное
// могло бы прийти от соседа, и инъекция доказывала бы не то свойство.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРОВЕРКА НА ВАКУУМНОСТЬ — ОТДЕЛЬНОЕ УТВЕРЖДЕНИЕ, А НЕ ПОБОЧНОЕ
//
// Прибор, чья вставка не долетает до предмета, печатает «находок ноль» с той же
// уверенностью, что и работающий: молчание на близнеце неотличимо от молчания
// на входе, которого разбор не увидел вовсе. Поэтому КАЖДАЯ инъекция сверх
// исхода утверждает ПЕРЕПИСЬ: вызовов осмотрено ровно столько, сколько подано.
// Без этого утверждения опечатка в синтетическом входе — или сузившийся
// разбор — обращала бы обе половины пары в зелёное.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// postureAnswerSubject — имя предмета в синтетике. ТО ЖЕ, что подаёт гейт:
// разойдись они, инъекция проверяла бы другой предмет и молчала бы законно.
const postureAnswerSubject = postureAnswerBuilder

// postureAnswerSource — один потребитель, записанный одной формой. `answer` —
// единственное, что меняется между дефектом и близнецом.
func postureAnswerSource(answer string) []byte {
	return []byte(`package main

func buildSomething(cfg Config, obs Observer) *Client {
	road, ` + answer + ` := ` + postureAnswerSubject + `(cfg, obs)
	return road
}
`)
}

// TestPostureAnswerInjection_DiscardedAnswerIsFound — ДЕФЕКТ ловится, и находка
// называет ПРИЧИНУ, а не только координату.
func TestPostureAnswerInjection_DiscardedAnswerIsFound(t *testing.T) {
	t.Parallel()
	calls, census, err := check.ScanProviderRoadCalls(
		"synthetic/defect.go", postureAnswerSource("_"), postureAnswerSubject)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}

	// ВАКУУМНОСТЬ: вход дошёл до разбора. Без этой строки «находка есть»
	// осталось бы верным и при разборе, читающем что-то другое.
	if census.Calls != 1 {
		t.Fatalf("вставка не долетела: вызовов осмотрено %d, подан 1 — "+
			"дальнейший вердикт беспредметен", census.Calls)
	}
	if census.Funcs != 1 {
		t.Fatalf("функций осмотрено %d, подана 1", census.Funcs)
	}

	found := check.ProviderRoadCallsIgnoringTheAnswer(calls)
	if len(found) != 1 {
		t.Fatalf("дефект НЕ пойман: находок %d, ожидалась 1 — гейт зеленеет на "+
			"потребителе, отбросившем ответ о посадке", len(found))
	}
	if found[0].Line != 4 {
		t.Errorf("находка названа строкой %d, вызов стоит на 4", found[0].Line)
	}
	if found[0].Func != "buildSomething" {
		t.Errorf("находка названа функцией %q, вызов стоит в buildSomething", found[0].Func)
	}
	if !strings.Contains(found[0].Form, "`_`") {
		t.Errorf("находка называет причину %q — она обязана называть ОТБРАСЫВАНИЕ "+
			"ответа, а не симптом", found[0].Form)
	}
}

// TestPostureAnswerInjection_BoundAnswerIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ молчит, и
// молчит ПРОЧИТАННЫМ, а не пропущенным.
func TestPostureAnswerInjection_BoundAnswerIsSilent(t *testing.T) {
	t.Parallel()
	calls, census, err := check.ScanProviderRoadCalls(
		"synthetic/twin.go", postureAnswerSource("built"), postureAnswerSubject)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}

	// ВАКУУМНОСТЬ, и здесь она НЕСУЩАЯ: молчание на непрочитанном входе
	// неотличимо от молчания на законном.
	if census.Calls != 1 {
		t.Fatalf("вставка не долетела: вызовов осмотрено %d, подан 1 — "+
			"молчание ниже ничего не доказывает", census.Calls)
	}
	if census.Bound != 1 {
		t.Fatalf("ответов принято %d, подан 1 — разбор не признал законную форму", census.Bound)
	}

	if found := check.ProviderRoadCallsIgnoringTheAnswer(calls); len(found) != 0 {
		t.Fatalf("гейт краснеет на ЗАКОННОМ потребителе: %+v — он обязан молчать, "+
			"иначе всякая починка невозможна", found)
	}
}

// TestPostureAnswerInjection_CallInsideAnExpressionIsFound — вызов, стоящий
// внутри выражения, ответу связать негде, и это находка.
//
// Отдельная ось: она отличается от дефекта выше ПОЛОЖЕНИЕМ вызова, а не именем
// слева, и без неё гейт молчал бы на самой распространённой форме — передаче
// построенного клиента прямо в конструктор потребителя.
func TestPostureAnswerInjection_CallInsideAnExpressionIsFound(t *testing.T) {
	t.Parallel()
	src := []byte(`package main

func buildSomething(cfg Config, obs Observer) *Consumer {
	return NewConsumer(` + postureAnswerSubject + `(cfg, obs))
}
`)
	calls, census, err := check.ScanProviderRoadCalls("synthetic/inexpr.go", src, postureAnswerSubject)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if census.Calls != 1 {
		t.Fatalf("вставка не долетела: вызовов осмотрено %d, подан 1", census.Calls)
	}
	found := check.ProviderRoadCallsIgnoringTheAnswer(calls)
	if len(found) != 1 {
		t.Fatalf("вызов внутри выражения НЕ пойман: находок %d, ожидалась 1", len(found))
	}
	if !strings.Contains(found[0].Form, "внутри выражения") {
		t.Errorf("находка называет причину %q — она обязана называть ПОЛОЖЕНИЕ вызова", found[0].Form)
	}
}

// TestPostureAnswerInjection_ForeignBuilderIsNotTheSubject — разбор судит
// ИМЕНОВАННЫЙ предмет и не расползается на соседа.
//
// Инъекция роняет ТОЛЬКО проверяемое: одноимённый по смыслу, но иначе названный
// строитель предметом этого гейта не является, и красное от него означало бы,
// что находки приходят не оттуда, откуда их читают.
func TestPostureAnswerInjection_ForeignBuilderIsNotTheSubject(t *testing.T) {
	t.Parallel()
	src := []byte(`package main

func buildSomething(cfg Config, obs Observer) *Client {
	road, _ := someOtherRoadBuilder(cfg, obs)
	return road
}
`)
	calls, census, err := check.ScanProviderRoadCalls("synthetic/foreign.go", src, postureAnswerSubject)
	if err != nil {
		t.Fatalf("разбор синтетики: %v", err)
	}
	if census.Funcs != 1 {
		t.Fatalf("функций осмотрено %d, подана 1 — вход не прочитан, и молчание "+
			"ниже ничего не доказывает", census.Funcs)
	}
	if census.Calls != 0 {
		t.Fatalf("вызовов предмета осмотрено %d, подано 0 — разбор расползся на соседа", census.Calls)
	}
	if found := check.ProviderRoadCallsIgnoringTheAnswer(calls); len(found) != 0 {
		t.Fatalf("гейт нашёл находку у ЧУЖОГО строителя: %+v", found)
	}
}

// TestPostureAnswerPremise_EmptyWalkIsNotAVerdict — обход, не нашедший
// предмета, вердикта не выносит.
//
// Предпосылка проверяется ВЫЗОВОМ на синтетике, а не чтением ветки глазами: на
// живой ведомости она истекала бы вместе с предметом и проверяла бы себя сама
// ровно до первого дня, когда предмета не станет.
func TestPostureAnswerPremise_EmptyWalkIsNotAVerdict(t *testing.T) {
	t.Parallel()
	empty := check.ProviderRoadCallCensus{Funcs: 10, Calls: 0}

	err := check.ProviderRoadCallPremise(1000, postureAnswerCensusFloor, empty, postureAnswerSubject)
	if err == nil {
		t.Fatal("обход без единого вызова строителя вынес вердикт: «находок ноль» " +
			"здесь означает «прочитано ноль»")
	}
	if !strings.Contains(err.Error(), postureAnswerSubject) {
		t.Errorf("отказ предпосылки не назвал предмет: %v", err)
	}

	// ПОЛОЖИТЕЛЬНЫЙ БЛИЗНЕЦ предпосылки: непустой обход её проходит, иначе
	// отказ выше зеленел бы на предпосылке, отвергающей всё подряд.
	live := check.ProviderRoadCallCensus{Funcs: 10, Calls: 1, Bound: 1}
	if err := check.ProviderRoadCallPremise(1000, postureAnswerCensusFloor, live, postureAnswerSubject); err != nil {
		t.Fatalf("предпосылка отвергает ЖИВОЙ обход: %v", err)
	}

	// Обход, не добравшийся до дерева, тоже вердикта не выносит.
	if err := check.ProviderRoadCallPremise(1, postureAnswerCensusFloor, live, postureAnswerSubject); err == nil {
		t.Fatal("обход, разобравший 1 файл при пороге, вынес вердикт")
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// service_link_collision_injection_test.go — способность меры упасть и смолчать
// доказывается ИНЪЕКЦИЕЙ, а не прочтением.
//
// Гейт класса опирается на две части, и у каждой инъекция своя:
//
//	РАСПОЗНАВАТЕЛЬ  ClusterServiceLinkForm — знает ли он ВСЕ восемь форм, которые
//	                подставляет кластер, и молчит ли на именах, которых кластер
//	                не производит;
//	ОТКАЗ           parsePortValue — краснеет ли он на подстановке кластера и
//	                молчит ли на законном близнеце — голом номере порта;
//	СУЖДЕНИЕ        flatKnobCollisionFindings — называет ли оно ручку, чьё имя
//	                совпало с формой кластера, а форма значения объявлена
//	                произвольной.
//
// Каждая инъекция меняет против близнеца РОВНО ОДИН факт. Иначе неизвестно,
// какой из двух дал красное, и вердикт недействителен, хотя выглядит как
// обычный зелёный.
package config

import (
	"strings"
	"testing"
)

// ─────────────────────────────────────────────────────────────────────────────
// РАСПОЗНАВАТЕЛЬ: ВСЕ ВОСЕМЬ ФОРМ

// TestInjection_RecogniserKnowsEveryFormTheClusterProduces — форма, о которой
// распознаватель не знает, не даёт ни красного, ни зелёного: он МОЛЧИТ, и всё
// записанное в ней оказывается вне наблюдения. Поэтому каждая форма предъявлена
// поимённо.
func TestInjection_RecogniserKnowsEveryFormTheClusterProduces(t *testing.T) {
	// Имена собраны по правилу самого кластера: верхний регистр имени службы,
	// дефис → подчёркивание. Служба здесь — `kaname-internal`, порт `grpc`.
	cases := map[string]string{
		"KANAME_INTERNAL_PORT":                "<СЛУЖБА>_PORT",
		"KANAME_PORT":                         "<СЛУЖБА>_PORT",
		"KANAME_INTERNAL_SERVICE_HOST":        "<СЛУЖБА>_SERVICE_HOST",
		"KANAME_INTERNAL_SERVICE_PORT":        "<СЛУЖБА>_SERVICE_PORT",
		"KANAME_INTERNAL_SERVICE_PORT_GRPC":   "<СЛУЖБА>_SERVICE_PORT_<ПОРТ>",
		"KANAME_INTERNAL_PORT_9091_TCP":       "<СЛУЖБА>_PORT_<N>_<ПРОТО>",
		"KANAME_INTERNAL_PORT_9091_TCP_PROTO": "<СЛУЖБА>_PORT_<N>_<ПРОТО>_PROTO",
		"KANAME_INTERNAL_PORT_9091_TCP_PORT":  "<СЛУЖБА>_PORT_<N>_<ПРОТО>_PORT",
		"KANAME_INTERNAL_PORT_9091_TCP_ADDR":  "<СЛУЖБА>_PORT_<N>_<ПРОТО>_ADDR",
		"KANAME_INTERNAL_PORT_9091_SCTP_ADDR": "<СЛУЖБА>_PORT_<N>_<ПРОТО>_ADDR",
		"KANAME_INTERNAL_PORT_53_UDP":         "<СЛУЖБА>_PORT_<N>_<ПРОТО>",
	}
	seenForms := map[string]int{}
	for name, wantForm := range cases {
		form, collides := ClusterServiceLinkForm(name)
		if !collides {
			t.Errorf("%s: распознаватель НЕ ВИДИТ имя, которое кластер производит — "+
				"всё записанное в этой форме оказывается вне наблюдения", name)
			continue
		}
		if form != wantForm {
			t.Errorf("%s: форма названа %q, ожидалась %q — имя, подходящее под "+
				"несколько форм, обязано назваться той, которая объясняет его точнее",
				name, form, wantForm)
		}
		seenForms[form]++
	}
	if got := len(seenForms); got != len(clusterServiceLinkForms) {
		t.Errorf("предъявлено форм %d из %d объявленных: форма без предъявления "+
			"инъекции доказательства не имеет", got, len(clusterServiceLinkForms))
	}
	t.Logf("перепись: имён предъявлено %d · форм объявлено %d · форм предъявлено %d",
		len(cases), len(clusterServiceLinkForms), len(seenForms))
}

// TestInjection_RecogniserIsSilentOnNamesTheClusterNeverProduces — ЗАКОННЫЕ
// БЛИЗНЕЦЫ.
//
// Без этой половины распознаватель ловил бы форму, а не существо: он объявил бы
// столкновением всякое имя службы, и первый же ложный срабат его отключил бы.
func TestInjection_RecogniserIsSilentOnNamesTheClusterNeverProduces(t *testing.T) {
	silent := []string{
		// Плоские ручки службы, не оканчивающиеся хвостом грамматики.
		"KANAME_DB_SSLMODE",
		"KANAME_DB_HOST", // кластер даёт `_SERVICE_HOST`, а не `_HOST`
		"KANAME_AUTH_MODE",
		"KANAME_CONFIG_PATH",
		"KANAME_SAKEY_MAX_TTL",
		// Имя, выведенное из пути ключа: `__` кластер не производит.
		"KANAME_API_SERVER__INTERNAL_ENDPOINT",
		// Хвост есть, но протокол не из словаря кластера.
		"KANAME_INTERNAL_PORT_9091_QUIC_ADDR",
		// Хвост есть, но номера порта нет.
		"KANAME_INTERNAL_PORT_GRPC_TCP",
		// Чужое пространство имён: наших ручек не касается.
		//
		// Приставка взята НЕЙТРАЛЬНАЯ, а не имя соседней службы платформы.
		// Предмет близнеца — «корневой сегмент не наш», и выражает его любая
		// чужая приставка; имя платформы здесь прибавляло бы её остаток в
		// ведомость дебрендинга — то есть заводило бы работу, которой нет.
		"OTHERAPP_VPC_SERVICE_HOST",
	}
	for _, name := range silent {
		if form, collides := ClusterServiceLinkForm(name); collides {
			t.Errorf("%s: распознаватель объявил столкновение формы %s там, где кластер "+
				"такого имени не производит — ложный срабат, после которого меру отключат",
				name, form)
		}
	}
	t.Logf("перепись: законных близнецов предъявлено %d, все молчат", len(silent))
}

// ─────────────────────────────────────────────────────────────────────────────
// ОТКАЗ: ОДИН ИЗМЕНЁННЫЙ ФАКТ

// TestInjection_RefusalNamesTheKnobAndTheValue — ДЕФЕКТ.
func TestInjection_RefusalNamesTheKnobAndTheValue(t *testing.T) {
	const env = "KANAME_INTERNAL_PORT"
	const injected = "tcp://10.96.66.181:9091"

	_, err := parsePortValue(env, injected)
	if err == nil {
		t.Fatalf("подстановка кластера принята как номер порта")
	}
	for _, want := range []string{env, injected, "enableServiceLinks"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("отказ не называет %q: %v — оператор не восстановит следующий шаг", want, err)
		}
	}
}

// TestInjection_RefusalIsSilentOnABarePort — ЗАКОННЫЙ БЛИЗНЕЦ отказа.
//
// Отличается от дефекта РОВНО ОДНИМ фактом — значением той же ручки.
func TestInjection_RefusalIsSilentOnABarePort(t *testing.T) {
	got, err := parsePortValue("KANAME_INTERNAL_PORT", "9091")
	if err != nil {
		t.Fatalf("голый номер порта отвергнут: %v — страж, отвергающий законное, "+
			"отменяет ручку, и проба отказа зеленела бы на сломанной ручке", err)
	}
	if got != "9091" {
		t.Errorf("значение искажено: %q", got)
	}
}

// TestInjection_RefusalRejectsOutOfRangeAndEmptyForms — спецификация
// ПОЛОЖИТЕЛЬНАЯ, а не список запрещённого: «не схема://…» оставляла бы годными и
// `abc`, и `0`, и пустую строку.
func TestInjection_RefusalRejectsOutOfRangeAndEmptyForms(t *testing.T) {
	for _, bad := range []string{"0", "65536", "-1", "abc", "9091abc", "тcp"} {
		if _, err := parsePortValue("KANAME_GRPC_PORT", bad); err == nil {
			t.Errorf("%q принято как номер порта", bad)
		}
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// СУЖДЕНИЕ ПО ПЕРЕЧНЮ: отделено от объявления службы

// TestInjection_JudgementNamesAnUnguardedCollidingKnob — ДЕФЕКТ: ручка, чьё имя
// совпало с формой кластера, объявлена с произвольной формой значения.
func TestInjection_JudgementNamesAnUnguardedCollidingKnob(t *testing.T) {
	findings := flatKnobCollisionFindings([]flatEnvKnob{
		{Env: "KANAME_SIDECAR_PORT", Key: "_legacy.sidecar-port"}, // формы значения НЕТ
	})
	if len(findings) != 1 {
		t.Fatalf("находок %d, ожидалась 1: суждение не видит ручку без формы значения", len(findings))
	}
	if !strings.Contains(findings[0], "KANAME_SIDECAR_PORT") {
		t.Errorf("находка не называет ручку: %s", findings[0])
	}
}

// TestInjection_JudgementIsSilentOnAGuardedTwin — ЗАКОННЫЙ БЛИЗНЕЦ: то же имя,
// изменён РОВНО ОДИН факт — объявлена форма значения.
func TestInjection_JudgementIsSilentOnAGuardedTwin(t *testing.T) {
	findings := flatKnobCollisionFindings([]flatEnvKnob{
		{Env: "KANAME_SIDECAR_PORT", Key: "_legacy.sidecar-port", Shape: shapePort},
	})
	if len(findings) != 0 {
		t.Errorf("находок %d при объявленной форме значения: %v", len(findings), findings)
	}
}

// TestInjection_JudgementIsSilentOnANonCollidingKnob — второй законный близнец:
// форма значения не объявлена, но имя кластер не производит.
func TestInjection_JudgementIsSilentOnANonCollidingKnob(t *testing.T) {
	findings := flatKnobCollisionFindings([]flatEnvKnob{
		{Env: "KANAME_SIDECAR_TIMEOUT", Key: "_legacy.sidecar-timeout"},
	})
	if len(findings) != 0 {
		t.Errorf("находок %d на имени, которого кластер не производит: %v", len(findings), findings)
	}
}

// TestInjection_JudgementOfTheServiceDeclarationIsClean — суждение по
// НАСТОЯЩЕМУ объявлению службы: находок ноль. Пустой перечень — находка, иначе
// «ноль находок» неотличимо от «ноль прочитанного».
func TestInjection_JudgementOfTheServiceDeclarationIsClean(t *testing.T) {
	if len(flatEnvKnobs) == 0 {
		t.Fatalf("объявление плоских ручек пусто: вердикт беспредметен")
	}
	if findings := flatKnobCollisionFindings(flatEnvKnobs); len(findings) != 0 {
		for _, f := range findings {
			t.Errorf("%s", f)
		}
	}
	t.Logf("перепись: плоских ручек объявлено %d · находок 0", len(flatEnvKnobs))
}

// ─────────────────────────────────────────────────────────────────────────────
// ЯКОРЬ К НАБЛЮДАВШЕМУСЯ ОТКАЗУ

// TestInjection_TheGuardedMechanismIsTheObservedOne — гейт стережёт НАБЛЮДАВШИЙСЯ
// механизм, а не синтетический.
//
// Без стража значение кластера уезжало в сборку адреса и давала она РОВНО тот
// адрес, на котором упала поставка. Здесь эта сборка воспроизводится напрямую —
// теми же двумя выражениями, что исполнял процесс, — и её исход сверяется
// дословно с текстом отказа прогона.
func TestInjection_TheGuardedMechanismIsTheObservedOne(t *testing.T) {
	const injected = "tcp://10.96.66.181:9091"
	// Ровно то, что делала сборка: `tcp://0.0.0.0:` + значение ручки, затем
	// приведение конечной точки к адресу слушателя.
	got := ListenAddressOf("tcp://0.0.0.0:" + injected)
	const observed = "0.0.0.0:tcp://10.96.66.181:9091"
	if got != observed {
		t.Fatalf("сборка даёт %q, а поставка упала на %q — гейт стережёт НЕ ТОТ "+
			"механизм, и его зелёный ничего не значит для наблюдавшегося отказа",
			got, observed)
	}
	// И та же ручка теперь до сборки не доходит.
	if _, err := parsePortValue("KANAME_INTERNAL_PORT", injected); err == nil {
		t.Errorf("значение доходит до сборки: страж не на пути")
	}
}

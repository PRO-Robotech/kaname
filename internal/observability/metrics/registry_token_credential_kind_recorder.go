// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package metrics

import (
	"github.com/prometheus/client_golang/prometheus"

	registrytoken "github.com/PRO-Robotech/kaname/internal/apps/kaname/api/registry_token"
)

// RegistryTokenCredentialKindOutcomes — ЗАКРЫТЫЙ набор клеток семейства.
//
// Собран из констант производителя (`registry_token.Outcome*`), а не выписан
// здесь: клетка окна перехода — ПРЕДИКАТ его закрытия, и разойдись набор с
// производителем, предикат отвечал бы «переведены все» на непереведённых.
var RegistryTokenCredentialKindOutcomes = []string{
	registrytoken.OutcomeBasicAccepted,
	registrytoken.OutcomeKeyMaterialAcceptedInWindow,
	registrytoken.OutcomeKeyMaterialRefused,
}

// RegistryTokenCredentialKindRecorder — исходы полос предъявленного
// удостоверения докерной полосы `/iam/token`.
//
// # Зачем счётчик, а не строка журнала
//
// Ломающее изменение #1143 сняло приём ключевого материала в поле пароля.
// Причина отказа уходила в предупреждение журнала — и на вопросы, которые
// оператор задаёт во время перехода, предупреждение не отвечает, потому что оба
// вопроса КОЛИЧЕСТВЕННЫЕ:
//
//	«скольких я сломаю (сломал), если окно закрыто» → key_material_refused;
//	«можно ли уже закрывать окно»                   → key_material_accepted_in_window.
//
// По строкам журнала это считают глазами и уже после того, как отказ истолкован;
// на прогоне из тысяч входов найти нужные строки нельзя.
//
// # Почему исходов ТРИ, а не один
//
// Счётчик одних отказов не отличает «отказов не было» от «входов не было
// вовсе»: и там и там ноль, и полоса, умершая целиком, выглядела бы здоровее
// всех (§Hardening-инварианты п.8 — «ноль за всю жизнь» обязано
// быть заметно). Поэтому знаменатель — basic_accepted — считается наравне с
// числителями.
//
// Принятое ОКНОМ считается отдельно от принятого штатно, потому что это разные
// вопросы: первое — предикат закрытия окна, второе — признак жизни полосы.
// Слив их, оператор получил бы величину, не отвечающую ни на один из них.
//
// # Кардинальность
//
// Набор меток ЗАКРЫТ: outcome приходит из констант use-case'а
// (registry_token.Outcome*), никогда из запроса, — поэтому кардинальность не
// растёт с трафиком. Ни имени предъявителя, ни идентификатора удостоверения
// здесь нет: в метрику не уходит то, чего не отдают клиенту.
type RegistryTokenCredentialKindRecorder struct {
	outcomes *prometheus.CounterVec
}

// NewRegistryTokenCredentialKindRecorder регистрирует коллектор в этом реестре.
// Звать один раз на старте.
func (r *Registry) NewRegistryTokenCredentialKindRecorder() *RegistryTokenCredentialKindRecorder {
	rec := &RegistryTokenCredentialKindRecorder{
		outcomes: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: Namespace + "_registry_token_credential_kind_total",
			Help: "Исходы докерной полосы /iam/token по виду предъявленного удостоверения. " +
				"basic_accepted — принят штатный вид (базовый токен доступа); это ЗНАМЕНАТЕЛЬ: " +
				"без него ноль по прочим исходам неотличим от полосы, не обслужившей ни одного " +
				"входа. key_material_refused — предъявлен ключевой материал, а окно перехода " +
				"#1143 закрыто либо истекло: величина отвечает на вопрос «скольких арендаторов " +
				"обновление уже ломает». key_material_accepted_in_window — ключевой материал " +
				"принят через ОТКРЫТОЕ окно перехода: это ПРЕДИКАТ ЗАКРЫТИЯ ОКНА — пока он " +
				"растёт, переведены не все, и ручку " +
				"api-server.registry-token.key-material-window-until снимать рано.",
		}, []string{"outcome"}),
	}
	// Клетки закрытого набора заводятся нулём ПРИ РЕГИСТРАЦИИ: вектор без детей
	// не отдаёт на провод ничего, и «механизм не провязан» становится неотличим
	// от «механизм провязан и ни разу не сработал».
	for _, outcome := range RegistryTokenCredentialKindOutcomes {
		rec.outcomes.WithLabelValues(outcome)
	}
	r.reg.MustRegister(rec.outcomes)
	return rec
}

// ObserveCredentialKind — один исход полосы. Реализует порт
// registry_token.CredentialKindObserver.
func (rec *RegistryTokenCredentialKindRecorder) ObserveCredentialKind(outcome string) {
	rec.outcomes.WithLabelValues(outcome).Inc()
}

// RegistryTokenCredentialKindRecorder возвращает ЕДИНСТВЕННЫЙ экземпляр
// счётчика этого реестра, создавая его при первом обращении.
//
// Экземпляр один, потому что prometheus.MustRegister падает на повторной
// регистрации, а полоса собирается в композиционном корне, где второй вызов
// стоит одной строки невнимательности и роняет старт процесса целиком.
func (r *Registry) RegistryTokenCredentialKindRecorder() *RegistryTokenCredentialKindRecorder {
	r.registryTokenKindOnce.Do(func() {
		r.registryTokenKind = r.NewRegistryTokenCredentialKindRecorder()
	})
	return r.registryTokenKind
}

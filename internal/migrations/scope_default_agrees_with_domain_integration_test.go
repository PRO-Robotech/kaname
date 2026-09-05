// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// scope_default_agrees_with_domain_integration_test.go — словарь «вид ↔ ярус»
// объявлен ДВАЖДЫ осознанно, и согласие двух объявлений проверяется
// (задача продукта #2057).
//
// # Почему мест два, а не одно
//
// Отношение «вид якоря → ярус» свёрнуто в домене в единственную карту
// (`domain.scopeVocabulary`, гейт `scope_tier_one_declaration_test.go`). Третье
// место — триггер `access_bindings_scope_default` на BEFORE INSERT — снять
// нельзя: он проставляет ярус, когда писатель его не назвал, и делает это НА
// УРОВНЕ БАЗЫ. Инвариант внутри сервиса держит база, а не программная проверка
// перед записью (ban #10), поэтому выбор из двух исходов задачи сделан в пользу
// ВТОРОГО: место объявлено осознанно, и рядом стоит проба согласия.
//
// # Проба судит ЖИВУЮ схему, а не текст миграций
//
// Текстовый предикат по каталогу считает объявлением и то, чей предмет снят
// более поздней миграцией. Здесь цепь проигрывается целиком, и спрашивается
// функция, ВИСЯЩАЯ на таблице сегодня.
//
// # Обе стороны сравнения обязательны
//
// «Каждая ветвь схемы известна домену» ловит лишний вид у схемы (ровно тот
// класс, что закрыт задачей #2060). «Каждый вид домена назван ветвью» ловит
// обратное — вид, который домен выводит, а схема потеряла. Половина сравнения
// пропускала бы свою сторону МОЛЧА: расхождение видно только при взгляде с обоих
// концов.
package migrations_test

import (
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kacho-iam/internal/domain"
)

// TestIntegration_ScopeDefaultAgreesWithTheDomainVocabulary — ветви живого
// триггера и карта домена совпадают в обе стороны.
func TestIntegration_ScopeDefaultAgreesWithTheDomainVocabulary(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	src := scopeDefaultLiveSource(t, db)
	require.NotEmpty(t, src,
		"функция %s не висит на kacho_iam.access_bindings: сверять нечего, "+
			"и «расхождений нет» означало бы «ничего не прочитано»", scopeDefaultFunc)

	arms, fallback, ok := scopeArmsOfBody(src)
	require.True(t, ok,
		"тело %s не разобрано: не найдено ни одной ветви `WHEN '<вид>' THEN <ярус>` "+
			"либо ветви умолчания. Разбор читает не то — вердикт был бы о пустоте.\nтело:\n%s",
		scopeDefaultFunc, src)

	vocab := domain.ScopeTierByKind()
	require.NotEmpty(t, vocab, "словарь домена пуст — вторая сторона сравнения отсутствует")

	t.Logf("перепись: ветвей у схемы %d (%s) · умолчание схемы %d · видов у домена %d · умолчание домена %d",
		len(arms), strings.Join(sortedKinds(arms), " "), fallback,
		len(vocab), int16(domain.DeriveFromResourceType("вид-вне-словаря")))

	findings := scopeAgreementFindings(arms, fallback, vocab)
	require.Empty(t, findings,
		"два объявления одного отношения разошлись:\n  %s\n"+
			"Схема и домен выводят РАЗНЫЙ ярус из одного вида — писатель, не назвавший ярус, "+
			"получит не тот, что предскажет домен.", strings.Join(findings, "\n  "))
}

// TestIntegration_ScopeAgreementCanSeeADivergenceInTheLiveSchema — тот же путь
// целиком (живая схема → разбор → сравнение) СПОСОБЕН найти расхождение.
//
// Инъекция идёт по ЖИВОЙ функции, а не по строке в памяти: без неё доказана была
// бы только чистая половина сравнения, а половина, читающая каталог, осталась бы
// недоказанной — и молчала бы одинаково на исправной схеме и на неразобранной.
func TestIntegration_ScopeAgreementCanSeeADivergenceInTheLiveSchema(t *testing.T) {
	if testing.Short() {
		t.Skip("пропуск интеграционной пробы (нужен Docker)")
	}
	db := freshIamSchema(t)

	// Контроль: до внесения расхождения путь молчит.
	src := scopeDefaultLiveSource(t, db)
	arms, fallback, ok := scopeArmsOfBody(src)
	require.True(t, ok)
	require.Empty(t, scopeAgreementFindings(arms, fallback, domain.ScopeTierByKind()),
		"контроль не прошёл: путь находит расхождение на СОГЛАСОВАННОЙ схеме — "+
			"тогда его находка ниже ничего не доказывает")

	// Внесён РОВНО ОДИН факт: у схемы появляется ветвь, которой домен не знает.
	_, err := db.Exec(`
		CREATE OR REPLACE FUNCTION kacho_iam.` + scopeDefaultFunc + `() RETURNS trigger
		    LANGUAGE plpgsql AS $$
		BEGIN
		    IF NEW.scope IS NULL THEN
		        NEW.scope := CASE NEW.resource_type
		            WHEN 'cluster' THEN 1::smallint
		            WHEN 'account' THEN 2::smallint
		            WHEN 'cloud'   THEN 2::smallint
		            WHEN 'project' THEN 3::smallint
		            WHEN 'folder'  THEN 3::smallint
		            WHEN 'tenancy' THEN 1::smallint
		            ELSE 3::smallint
		        END;
		    END IF;
		    RETURN NEW;
		END;
		$$;`)
	require.NoError(t, err, "инъекция не применилась — расхождение не внесено")

	src = scopeDefaultLiveSource(t, db)
	arms, fallback, ok = scopeArmsOfBody(src)
	require.True(t, ok)
	findings := scopeAgreementFindings(arms, fallback, domain.ScopeTierByKind())
	require.NotEmpty(t, findings,
		"расхождение внесено в ЖИВУЮ функцию, а путь молчит: он читает не каталог "+
			"либо сравнивает не то")
	require.Contains(t, strings.Join(findings, "\n"), "tenancy",
		"находка есть, но не называет виновника — читающий пойдёт искать не там")
}

// TestScopeAgreementComparator_ProvenByInjection — чистая половина сравнения
// падает по КАЖДОЙ своей оси и молчит на законном близнеце.
func TestScopeAgreementComparator_ProvenByInjection(t *testing.T) {
	vocab := map[string]domain.Scope{
		"cluster": domain.ScopeCluster,
		"account": domain.ScopeAccount,
		"project": domain.ScopeProject,
	}
	agreed := map[string]int16{"cluster": 1, "account": 2, "project": 3}

	cases := []struct {
		name     string
		arms     map[string]int16
		fallback int16
		wantHit  string // пусто ⇒ находок быть не должно
	}{
		{
			name: "законный близнец: объявления совпадают", arms: agreed, fallback: 3,
		},
		{
			name:    "у схемы лишний вид",
			arms:    map[string]int16{"cluster": 1, "account": 2, "project": 3, "tenancy": 1},
			wantHit: "tenancy", fallback: 3,
		},
		{
			name:    "схема потеряла вид домена",
			arms:    map[string]int16{"cluster": 1, "account": 2},
			wantHit: "project", fallback: 3,
		},
		{
			name:    "один вид, разные ярусы",
			arms:    map[string]int16{"cluster": 1, "account": 3, "project": 3},
			wantHit: "account", fallback: 3,
		},
		{
			name:    "умолчания разошлись",
			arms:    agreed,
			wantHit: "умолчание", fallback: 1,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := scopeAgreementFindings(tc.arms, tc.fallback, vocab)
			if tc.wantHit == "" {
				require.Empty(t, got,
					"сравнение нашло расхождение на СОГЛАСОВАННЫХ объявлениях: "+
						"оно краснеет на верном коде и будет отключено первым")
				return
			}
			require.NotEmpty(t, got, "ось не покрыта: расхождение внесено, находок ноль")
			require.Contains(t, strings.Join(got, "\n"), tc.wantHit,
				"находка не называет виновника")
		})
	}
}

// scopeAgreementFindings — расхождения двух объявлений, в ОБЕ стороны.
func scopeAgreementFindings(arms map[string]int16, fallback int16, vocab map[string]domain.Scope) []string {
	var out []string
	for _, kind := range sortedKinds(arms) {
		tier, known := vocab[kind]
		switch {
		case !known:
			out = append(out, "вид "+kind+": ветвь у схемы есть, домен вида не знает — "+
				"словарь схемы шире словаря домена")
		case int16(tier) != arms[kind]:
			out = append(out, "вид "+kind+": схема выводит ярус "+
				strconv.Itoa(int(arms[kind]))+", домен — "+strconv.Itoa(int(tier)))
		}
	}
	domainKinds := make([]string, 0, len(vocab))
	for kind := range vocab {
		domainKinds = append(domainKinds, kind)
	}
	sort.Strings(domainKinds)
	for _, kind := range domainKinds {
		if _, has := arms[kind]; !has {
			out = append(out, "вид "+kind+": домен выводит ярус "+
				strconv.Itoa(int(vocab[kind]))+", ветви у схемы нет")
		}
	}
	if want := int16(domain.DeriveFromResourceType("вид-вне-словаря")); fallback != want {
		out = append(out, "умолчание: схема даёт "+strconv.Itoa(int(fallback))+
			", домен — "+strconv.Itoa(int(want)))
	}
	return out
}

// scopeArmsOfBody — ветви `WHEN '<вид>' THEN <ярус>` и ветвь умолчания.
//
// ok=false означает «разобрать не удалось», а не «ветвей нет»: вызывающий обязан
// остановиться, а не выдать «расхождений ноль» на непрочитанном теле.
func scopeArmsOfBody(src string) (arms map[string]int16, fallback int16, ok bool) {
	arms = map[string]int16{}
	seenElse := false
	for _, line := range strings.Split(src, "\n") {
		if kind, tier, hit := scopeArmOfLine(line); hit {
			arms[kind] = tier
			continue
		}
		if tier, hit := scopeElseOfLine(line); hit {
			fallback, seenElse = tier, true
		}
	}
	return arms, fallback, len(arms) > 0 && seenElse
}

func scopeArmOfLine(line string) (kind string, tier int16, ok bool) {
	i := strings.Index(line, "WHEN '")
	if i < 0 {
		return "", 0, false
	}
	rest := line[i+len("WHEN '"):]
	j := strings.Index(rest, "'")
	if j < 0 {
		return "", 0, false
	}
	n, hit := firstSmallint(rest[j:])
	if !hit {
		return "", 0, false
	}
	return rest[:j], n, true
}

func scopeElseOfLine(line string) (tier int16, ok bool) {
	i := strings.Index(line, "ELSE ")
	if i < 0 {
		return 0, false
	}
	return firstSmallint(line[i:])
}

// firstSmallint — первое целое в отрезке.
func firstSmallint(s string) (int16, bool) {
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			continue
		}
		j := i
		for j < len(s) && s[j] >= '0' && s[j] <= '9' {
			j++
		}
		n, err := strconv.Atoi(s[i:j])
		if err != nil || n < 0 || n > 32767 {
			return 0, false
		}
		return int16(n), true
	}
	return 0, false
}

func sortedKinds(arms map[string]int16) []string {
	out := make([]string, 0, len(arms))
	for k := range arms {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

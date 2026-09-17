// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// login_method_cost_class_census_integration_test.go — ПЕРЕПИСЬ КЛАССОВ
// СТОИМОСТИ хранимых значений (решение kaname#188 по Ф3-31 / ID-PW-1 Р4):
// какие пары «формат, параметры» лежат в хранилище и сколько строк у каждой.
//
// # Что утверждают пробы
//
//   - перепись отдаёт КЛАСС, а не значение: префикс до соли — формат и числа
//     параметров; соль и тело в ответе не появляются ни в одной строке. Признак
//     вне перечня форматов отдаётся ПУСТЫМ префиксом: сегмент чужого признака
//     мог бы нести что угодно, а перепись выносит из колонки только то, что
//     читатель класса разберёт как числа;
//   - префикс, отданный переписью, разбирается в тот же класс, что и само
//     значение у проверяющего, — для ОБОИХ форматов перечня. Производитель
//     префикса (SQL) и его читатель (`passwordverify.ParseCostClassPrefix`)
//     живут в разных местах, и сходятся они этой пробой, а не соглашением;
//   - счёт по классу — число строк, а не число людей; вид способа — только
//     пароль: строка иного вида (Ф12) в перепись стоимости не входит.
package pg_test

import (
	"context"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/loginmethod"
	"github.com/PRO-Robotech/kaname/internal/domain"
	"github.com/PRO-Robotech/kaname/internal/passwordverify"
	"github.com/PRO-Robotech/kaname/internal/repo/kaname/pg"
)

// Адаптер обязан исполнять порт переписи — иначе порт есть обещание без
// исполнителя.
var _ loginmethod.CostClassCensus = (*pg.LoginMethodRepo)(nil)

// TestLoginMethodRepo_CostClassCensusCountsClassesNotValues — перепись даёт
// префикс класса и число строк; признак вне перечня — пустой префикс;
// материал (соль, тело) не покидает колонки.
func TestLoginMethodRepo_CostClassCensusCountsClassesNotValues(t *testing.T) {
	pool := lmPool(t)
	repo := pg.NewLoginMethodRepo(pool)
	ctx := context.Background()

	materials := []string{
		"$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW",
		"$2a$12$N9qo8uLOickgx2ZMRZoMyeIjZAgcfl7p92ldGxad68LJZdL17lhWy",
		"$2a$14$C6UzMDM.H6dfI/f/IKcEeO6kGzfBQz9j8hSpNCYzLFMkMmPU5YHtC",
		"$argon2id$v=19$m=65536,t=3,p=4$cHJvYmUtc2FsdC1mMnAx$cHJvYmUtaGFzaC1mMnAxLXJvdW5kdHJpcA",
		"$argon2id$v=19$m=65536,t=3,p=4$c2Vjb25kLXNhbHQtdmFsdWU$c2Vjb25kLWhhc2gtb2YtdGhlLXNhbWUtY2xhc3M",
		"$argon2id$v=19$m=32768,t=3,p=4$dGhpcmQtc2FsdC12YWx1ZQ$dHJhbnNmZXJyZWQtYmVsb3ctdGhlLWZsb29y",
		"$pbkdf2-sha256$29000$salt$body",
		"plaintext-that-somehow-got-here",
	}
	people := lmPeople(t, pool, "cens", len(materials))
	for i, m := range materials {
		_, err := repo.Create(ctx, domain.LoginMethod{UserID: people[i], Kind: domain.LoginMethodPassword, Verifier: lmVerifier(t, m), State: domain.LoginMethodStateActive})
		require.NoError(t, err, "посев %d", i)
	}

	rows, err := repo.PasswordCostClasses(ctx)
	require.NoError(t, err)

	got := map[string]int64{}
	for _, r := range rows {
		got[r.Prefix] = r.Rows
	}
	require.Equal(t, map[string]int64{
		"$2a$12":                         2,
		"$2a$14":                         1,
		"$argon2id$v=19$m=65536,t=3,p=4": 2,
		"$argon2id$v=19$m=32768,t=3,p=4": 1,
		"":                               2, // два признака вне перечня — ОДНА строка переписи: сегмент чужого признака наружу не выносится
	}, got)
	// Префикс кончается ПЕРЕД солью: у наследуемого формата это два сегмента
	// (признак, стоимость), у объявленного — три (признак, версия, параметры).
	for _, r := range rows {
		switch {
		case r.Prefix == "":
		case strings.HasPrefix(r.Prefix, "$2a$"):
			require.Equal(t, 2, strings.Count(r.Prefix, "$"), "префикс %q несёт больше двух сегментов — соль вынесена", r.Prefix)
		case strings.HasPrefix(r.Prefix, "$argon2id$"):
			require.Equal(t, 3, strings.Count(r.Prefix, "$"), "префикс %q несёт больше трёх сегментов — соль вынесена", r.Prefix)
		default:
			t.Fatalf("префикс %q — признак вне перечня обязан отдаваться пустым", r.Prefix)
		}
	}
}

// TestLoginMethodRepo_CostClassPrefixRoundTripsThroughTheParser — префикс из
// переписи разбирается в класс, равный классу самого значения у проверяющего:
// оба формата перечня, по одному значению каждого.
func TestLoginMethodRepo_CostClassPrefixRoundTripsThroughTheParser(t *testing.T) {
	pool := lmPool(t)
	repo := pg.NewLoginMethodRepo(pool)
	ctx := context.Background()

	hasher, err := passwordverify.NewHasher(passwordverify.Declared{Format: domain.PasswordHashFormatArgon2id,
		Params: map[domain.PasswordHashCostParam]uint32{
			domain.CostParamArgon2Memory: 65536, domain.CostParamArgon2Iterations: 3, domain.CostParamArgon2Parallelism: 4}})
	require.NoError(t, err)
	fresh, err := hasher.Hash("a password of the declared class")
	require.NoError(t, err)
	legacy := lmVerifier(t, "$2a$12$R9h/cIPz0gi.URNNX3kh2OPST9/PgBkqquzi.Ss7KIUgO2t0jWMUW")

	people := lmPeople(t, pool, "cert", 2)
	_, err = repo.Create(ctx, domain.LoginMethod{UserID: people[0], Kind: domain.LoginMethodPassword, Verifier: fresh, State: domain.LoginMethodStateActive})
	require.NoError(t, err)
	_, err = repo.Create(ctx, domain.LoginMethod{UserID: people[1], Kind: domain.LoginMethodPassword, Verifier: legacy, State: domain.LoginMethodStateActive})
	require.NoError(t, err)

	verifier, err := passwordverify.New(1, censusVerifyObserver{})
	require.NoError(t, err)
	want := map[string]int64{}
	for _, v := range []domain.LoginVerifier{fresh, legacy} {
		res := verifier.Verify(v, "not the password")
		require.Equal(t, passwordverify.OutcomeMismatched, res.Outcome)
		want[domain.PasswordCostClass{Format: res.Format, Params: res.Params}.Key()]++
	}

	rows, err := repo.PasswordCostClasses(ctx)
	require.NoError(t, err)
	got := map[string]int64{}
	for _, r := range rows {
		class, perr := passwordverify.ParseCostClassPrefix(r.Prefix)
		require.NoError(t, perr, "префикс %q не разобран читателем класса", r.Prefix)
		got[class.Key()] += r.Rows
	}
	require.Equal(t, want, got, "класс из переписи и класс из проверяющего расходятся")
}

type censusVerifyObserver struct{}

func (censusVerifyObserver) VerificationObserved(passwordverify.Outcome) {}

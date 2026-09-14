// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_road_address_single_reader_injection_test.go — доказательство
// падучести В ОБЕ СТОРОНЫ (задачи `kacho#2573`, `kaname#21`).
//
// Каждая ось несёт дефект И законного близнеца: без близнеца «находок нет»
// зеленело бы на распознавателе, который не находит НИЧЕГО.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

// TestProviderAddressRead_RedOnASecondResolverOutsideTheBuilder — ИНЪЕКЦИЯ:
// чтение резолвера вне строителя — находка, и она называет координату.
func TestProviderAddressRead_RedOnASecondResolverOutsideTheBuilder(t *testing.T) {
	t.Parallel()
	src := `package main

func buildSAKeysHandler(cfg config.Config) string {
	hydraAdminURL := cfg.AuthN.ResolveHydraAdminURL()
	return hydraAdminURL
}
`
	got, census, err := check.ScanProviderAddressReads("cmd/kaname/wiring.go", []byte(src),
		providerAddressResolver, providerAddressTwin)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("второе чтение резолвера НЕ стало находкой: %d", len(got))
	}
	if got[0].Func != "buildSAKeysHandler" {
		t.Errorf("находка не называет объемлющую функцию: %+v", got[0])
	}
	if got[0].Line != 4 {
		t.Errorf("находка не называет строку: %+v", got[0])
	}
	if census.ResolverReads != 1 {
		t.Errorf("перепись чтений резолвера разошлась с находками: %+v", census)
	}
}

// TestProviderAddressRead_SilentInsideTheBuilder — ЗАКОННЫЙ БЛИЗНЕЦ: то же самое
// чтение внутри строителя. Разбор обязан ОТНЕСТИ его строителю — иначе гейт не
// сможет отличить владельца от второго читателя, и отрицание выше краснело бы
// на верном коде.
func TestProviderAddressRead_SilentInsideTheBuilder(t *testing.T) {
	t.Parallel()
	src := `package main

func mustProviderAdminClient(cfg config.Config) string {
	return cfg.AuthN.ResolveHydraAdminURL()
}
`
	got, _, err := check.ScanProviderAddressReads("cmd/kaname/wiring.go", []byte(src),
		providerAddressResolver, providerAddressTwin)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("чтение у строителя не увидено вовсе: %d — тогда гейт зеленел бы "+
			"и на дереве, где строитель адрес не резолвит", len(got))
	}
	if got[0].Func != providerAddressOwner {
		t.Fatalf("чтение НЕ отнесено строителю (%s): %+v — гейт объявил бы владельца "+
			"вторым читателем", providerAddressOwner, got[0])
	}
}

// TestProviderAddressRead_SilentOnTheSafeTwin — ЗАКОННЫЙ БЛИЗНЕЦ: безопасный
// близнец пуст, когда никто ничего не объявлял, и читается стражем посадки
// намеренно. Находкой он не является, но СЧИТАЕТСЯ — «находок ноль» обязано
// быть отличимо от «распознаватель не видит здесь ничего про адрес».
func TestProviderAddressRead_SilentOnTheSafeTwin(t *testing.T) {
	t.Parallel()
	src := `package config

func requireProviderAdminCredentialPair(c AuthNConfig) bool {
	return c.DeclaredHydraAdminURL() != ""
}
`
	got, census, err := check.ScanProviderAddressReads("internal/config/guard.go", []byte(src),
		providerAddressResolver, providerAddressTwin)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("чтение безопасного близнеца объявлено находкой: %+v", got)
	}
	if census.TwinReads != 1 {
		t.Errorf("чтение близнеца не засчитано переписью: %+v", census)
	}
}

// TestProviderAddressRead_SilentOnProseAndStrings — ЗАКОННЫЙ БЛИЗНЕЦ: имя
// резолвера в КОММЕНТАРИИ и в строковом литерале.
//
// Ось несущая, а не декоративная: имя резолвера стоит в прозе трижды — в шапке
// самого резолвера, в шапке близнеца и в шапке стража посадки, который
// объясняет, почему читает НЕ его. Поиск по подстроке краснел бы на собственном
// объяснении проверяемого.
func TestProviderAddressRead_SilentOnProseAndStrings(t *testing.T) {
	t.Parallel()
	src := `package config

// ResolveHydraAdminURL пустого не возвращает никогда: страж читает не его,
// а DeclaredHydraAdminURL — см. разбор выше.
func why() string {
	return "boot guard reads DeclaredHydraAdminURL, never ResolveHydraAdminURL"
}
`
	got, census, err := check.ScanProviderAddressReads("internal/config/authn.go", []byte(src),
		providerAddressResolver, providerAddressTwin)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(got) != 0 {
		t.Errorf("имя в прозе/строке объявлено чтением: %+v — гейт краснел бы на "+
			"собственном объяснении проверяемого", got)
	}
	if census.TwinReads != 0 {
		t.Errorf("имя близнеца в прозе засчитано чтением: %+v", census)
	}
}

// TestProviderAddressRead_CensusCountsWhatItWalked — перепись растёт с обходом,
// а не остаётся нулём: без этого «вызовов осмотрено 0» было бы неотличимо от
// «файл разобран и в нём ничего нет».
func TestProviderAddressRead_CensusCountsWhatItWalked(t *testing.T) {
	t.Parallel()
	src := `package main

func build(cfg config.Config) {
	_ = other()
	_ = another()
}
`
	_, census, err := check.ScanProviderAddressReads("cmd/kaname/x.go", []byte(src),
		providerAddressResolver, providerAddressTwin)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if census.Calls != 2 {
		t.Fatalf("вызовов осмотрено %d при двух в файле: перепись не считает обход",
			census.Calls)
	}
	if census.ResolverReads != 0 || census.TwinReads != 0 {
		t.Errorf("посторонние вызовы засчитаны чтениями адреса: %+v", census)
	}
}

// TestProviderAddressRead_EmptyInputIsNotAVerdict — разбор пустого файла не
// выносит вердикта о дереве: ноль находок здесь означает ноль прочитанного, и
// именно поэтому у гейта стоит порог переписи.
func TestProviderAddressRead_EmptyInputIsNotAVerdict(t *testing.T) {
	t.Parallel()
	got, census, err := check.ScanProviderAddressReads("cmd/kaname/empty.go",
		[]byte("package main\n"), providerAddressResolver, providerAddressTwin)
	if err != nil {
		t.Fatalf("разбор: %v", err)
	}
	if len(got) != 0 || census.Calls != 0 {
		t.Fatalf("пустой файл дал непустой разбор: находок %d, перепись %+v", len(got), census)
	}
}

// TestProviderAddressPremise_EachBranchActuallyFires — ПРЕМИСА ОБХОДА
// доказывается ИСПОЛНЕНИЕМ, а не чтением.
//
// Четыре отказа и годный вход пятым: без последнего «премиса краснеет» зеленело
// бы на условии, отвергающем всё.
func TestProviderAddressPremise_EachBranchActuallyFires(t *testing.T) {
	t.Parallel()
	const floor = 300
	full := check.ProviderAddressCensus{Calls: 34795, ResolverReads: 1, TwinReads: 4}

	cases := []struct {
		name    string
		parsed  int
		census  check.ProviderAddressCensus
		atOwner int
		refuses bool
		says    string
	}{
		{
			name: "обход почти пуст", parsed: 3, census: full, atOwner: 1,
			refuses: true, says: "перепись обвалилась",
		},
		{
			name:   "ни одного вызова не осмотрено",
			parsed: 840, census: check.ProviderAddressCensus{}, atOwner: 1,
			refuses: true, says: "НИ ОДНОГО вызова",
		},
		{
			name:   "безопасный близнец исчез",
			parsed: 840, census: check.ProviderAddressCensus{Calls: 34795, ResolverReads: 1},
			atOwner: 1, refuses: true, says: "НОЛЬ",
		},
		{
			name: "строитель перестал читать резолвер", parsed: 840, census: full, atOwner: 0,
			refuses: true, says: "НЕ читает",
		},
		{
			name: "годный вход — премиса молчит", parsed: 840, census: full, atOwner: 1,
			refuses: false,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := check.ProviderAddressPremise(tc.parsed, floor, tc.census, tc.atOwner, 1,
				providerAddressResolver, providerAddressTwin, providerAddressOwner)
			switch {
			case tc.refuses && err == nil:
				t.Fatalf("премиса НЕ сработала: ветвь существует, но не исполняется — "+
					"ровно тот класс, ради которого она вынесена из тела пробы (%s)", tc.name)
			case !tc.refuses && err != nil:
				t.Fatalf("премиса отвергла ГОДНЫЙ вход: %v — тогда отказы выше зеленели "+
					"бы на условии, отвергающем всё", err)
			case tc.refuses && !strings.Contains(err.Error(), tc.says):
				t.Errorf("отказ не называет причину %q: %v", tc.says, err)
			}
		})
	}
}

// TestSplitProviderAddressReads_AttributesByEnclosingFunction — разделение
// судит по объемлющей функции, а не по файлу: строитель и второй читатель
// живут в ОДНОМ файле, и разделение по файлу не увидело бы находки вовсе.
func TestSplitProviderAddressReads_AttributesByEnclosingFunction(t *testing.T) {
	t.Parallel()
	reads := []check.ProviderAddressRead{
		{File: "cmd/kaname/wiring.go", Line: 984, Func: providerAddressOwner},
		{File: "cmd/kaname/wiring.go", Line: 1025, Func: "buildSAKeysHandler"},
	}
	atOwner, outside := check.SplitProviderAddressReads(reads, providerAddressOwner)
	if len(atOwner) != 1 || len(outside) != 1 {
		t.Fatalf("разделение по объемлющей функции не состоялось: владелец %d, вне %d",
			len(atOwner), len(outside))
	}
	if outside[0].Line != 1025 {
		t.Errorf("посторонним назван не тот читатель: %+v", outside[0])
	}
}

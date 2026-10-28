// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package audit_test

// account_id_reserve_is_a_function_of_the_string_integration_test.go — AID-39:
// резерв формы идентификатора аккаунта — функция самой строки; ни каталоги
// фундамента, ни ручки окружения, ни посев его не меняют (задача kaname#1052,
// приёмка `docs/engineering/acceptance/account-id-may-be-supplied-at-create.md`,
// редакция 7, sha256 a3dff53e9ae56e3e1fa959d6ee3b43a932aaf09d3918795a62c06377550e3e52;
// Р2 (д), Р10, C8).
//
// # Как построена
//
// Распознаватель формы судится ТЕМ входом, которым его зовёт создание, — use-case
// `AccountService.Create` с указанным `id`. Порядок проверок создания несущий
// (Р2 «Порядок»): форма и резерв раньше вопроса о праве. Поэтому дублёр
// хранилища прав, отвечающий ошибкой связи, разводит три исхода без базы:
// принятое формой доходит до вопроса о праве и получает `UNAVAILABLE`
// `authz backend unavailable`; отвергнутое — синхронный `INVALID_ARGUMENT` с
// текстом ФОРМА либо РЕЗЕРВ (§5, значения). Имя файла распознавателя назовёт
// замысел, и проба его не выписывает.
//
// Множества маршрутизатора фундамента читают ручки окружения при инициализации
// пакета, поэтому две среды — два подпроцесса этого же тестового бинарника:
// (1) без ручек; (2) с `EXTRA_RESOURCE_ID_PREFIXES=xyz`,
// `EXTRA_RESOURCE_ID_HYPHEN_PREFIXES=qq` и синонимами `KACHO_*`, заданными до
// старта. Положительный контроль ручек — вердикт `corevalidate.ResourceID` на
// `xyz7m3k9q2x5v8b4n6t1` в той же среде: в (2) принят, в (1) — нет. Без контроля
// равенство вердиктов не отличило бы «резерв ручку не читает» от «ручка до
// процесса не дошла».
//
// Предикат приёмки по файлу распознавателя (`git grep … -- "$F"`) этой пробой не
// исполняется: файл назовёт замысел.
//
// # Чем краснеет до реализации
//
// Распознавателя формы аккаунта нет (S1): создание судит форму генератора, и
// отказ на каждом значении вне её — `invalid account id '<X>'` без правила, а
// годные значения заданной формы отвергаются. Вердикт таких значений — «прочее»,
// и проба красна утверждением о таблицах AID-05/AID-06, после того как обе среды
// исполнены и положительный контроль ручек сошёлся.

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"os/exec"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	corevalidate "github.com/PRO-Robotech/corelib/validate"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/account"
	"github.com/PRO-Robotech/kaname/internal/domain"
)

const (
	// aid39ChildEnv — признак подпроцесса среды: проба исполняет только суждение
	// и печатает вердикты строкой с меткой.
	aid39ChildEnv = "KANAME_AID39_CHILD"
	// aid39Mark — метка строки вердиктов в выводе подпроцесса.
	aid39Mark = "AID39-VERDICTS "
	// aid39KnobProbe — строка положительного контроля ручек.
	aid39KnobProbe = "xyz7m3k9q2x5v8b4n6t1"
	// aid39InjectedSeed — литерал инъекции посева: форма (а)–(д) его принимает, а
	// перечень (д3) Р2 его не называет.
	aid39InjectedSeed = "rolinjectedseed"
)

// aid39ReserveListD3 — закрытый перечень (д3) Р2 приёмки дословно.
var aid39ReserveListD3 = []string{"rol000000000sysviewer"}

// Вердикты распознавателя.
const (
	aid39Accepted = "принят"
	aid39Form     = "ФОРМА"
	aid39Reserve  = "РЕЗЕРВ"
)

// aid39Report — что печатает подпроцесс среды.
type aid39Report struct {
	Verdicts map[string]string `json:"verdicts"`
	// KnobAccepted — принял ли маршрутизатор фундамента строку контроля ручек.
	KnobAccepted bool `json:"knob_accepted"`
}

// aid39Values — все значения AID-05 и AID-06, литералы посева и литерал инъекции.
func aid39Values() []string {
	seen := map[string]bool{}
	var out []string
	add := func(v string) {
		if !seen[v] {
			seen[v] = true
			out = append(out, v)
		}
	}
	for _, r := range aid05Table() {
		add(r.value)
	}
	for _, v := range aid06Values() {
		add(v)
	}
	for _, v := range domain.SeededResourceIDs() {
		add(v)
	}
	add(aid39InjectedSeed)
	return out
}

// aid39Expected — вердикт по таблицам AID-05 (ФОРМА · РЕЗЕРВ) и AID-06 (принят).
func aid39Expected() map[string]string {
	out := map[string]string{}
	for _, r := range aid05Table() {
		if r.message == formRefusal(r.value) {
			out[r.value] = aid39Form
		} else {
			out[r.value] = aid39Reserve
		}
	}
	for _, v := range aid06Values() {
		out[v] = aid39Accepted
	}
	return out
}

// aid39Judge — вердикт распознавателя по ответу создания с указанным `id`.
func aid39Judge(uc *account.CreateAccountUseCase, owner domain.UserID, v string) string {
	_, err := uc.Execute(withPrincipal(owner), domain.Account{ID: domain.AccountID(v), Name: "aid39", Labels: domain.Labels{}})
	st, ok := status.FromError(err)
	switch {
	case err == nil:
		return "прочее: операция заведена при недоступной модели прав"
	case !ok:
		return "прочее: не статус gRPC: " + err.Error()
	case st.Code() == codes.Unavailable && st.Message() == "authz backend unavailable":
		return aid39Accepted
	case st.Code() == codes.InvalidArgument && st.Message() == formRefusal(v):
		return aid39Form
	case st.Code() == codes.InvalidArgument && st.Message() == reserveRefusal(v):
		return aid39Reserve
	}
	return "прочее: " + st.Code().String() + " " + st.Message()
}

// aid39Child — тело подпроцесса среды: суждение и печать, без базы.
func aid39Child(t *testing.T) {
	rel := &relationDouble{failure: errors.New("relation store: connection refused")}
	uc := account.NewCreateAccountUseCase(nil, nil).WithRelationStore(rel, discardLogger())
	owner := domain.UserID("usr7m3k9q2x5v8b4n6t1")
	rep := aid39Report{Verdicts: map[string]string{}}
	for _, v := range aid39Values() {
		rep.Verdicts[v] = aid39Judge(uc, owner, v)
	}
	rep.KnobAccepted = corevalidate.ResourceID("account", "acc", aid39KnobProbe) == nil
	b, err := json.Marshal(rep)
	require.NoError(t, err)
	// Вывод подпроцесса читает родитель: метка — в начале строки.
	_, _ = os.Stdout.WriteString("\n" + aid39Mark + string(b) + "\n")
}

// aid39RunEnv — подпроцесс среды с ручками env; отдаёт его отчёт.
func aid39RunEnv(t *testing.T, name string, env []string) aid39Report {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestAccountID39_ReserveIsAFunctionOfTheString$", "-test.count=1", "-test.v")
	base := make([]string, 0, len(os.Environ()))
	for _, kv := range os.Environ() {
		if strings.Contains(kv, "RESOURCE_ID_PREFIXES=") || strings.Contains(kv, "RESOURCE_ID_HYPHEN_PREFIXES=") {
			continue
		}
		base = append(base, kv)
	}
	cmd.Env = append(append(base, aid39ChildEnv+"=1"), env...)
	var out bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &out
	require.NoError(t, cmd.Run(), "среда %s: подпроцесс пробы не исполнился:\n%s", name, out.String())
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.HasPrefix(line, aid39Mark) {
			var rep aid39Report
			require.NoError(t, json.Unmarshal([]byte(strings.TrimPrefix(line, aid39Mark)), &rep), "среда %s: отчёт", name)
			return rep
		}
	}
	t.Fatalf("среда %s: подпроцесс не напечатал строку вердиктов:\n%s", name, out.String())
	return aid39Report{}
}

// aid39SeedFindings — литералы посева, которые форма ПРИНИМАЕТ: каждый
// элемент перечня посеянного, кроме литералов (д3), обязан отвергаться формой
// (а)–(г) либо резервом; литералы (д3) — резервом.
func aid39SeedFindings(seeded []string, verdicts map[string]string) []string {
	d3 := map[string]bool{}
	for _, v := range aid39ReserveListD3 {
		d3[v] = true
	}
	var out []string
	for _, v := range seeded {
		got := verdicts[v]
		switch {
		case d3[v] && got != aid39Reserve:
			out = append(out, v+" ("+got+", литерал (д3) обязан быть РЕЗЕРВ)")
		case !d3[v] && got != aid39Form && got != aid39Reserve:
			out = append(out, v+" ("+got+", литерал посева вне (д3) обязан отвергаться)")
		}
	}
	sort.Strings(out)
	return out
}

// TestAccountID39_ReserveIsAFunctionOfTheString — AID-39.
func TestAccountID39_ReserveIsAFunctionOfTheString(t *testing.T) {
	if os.Getenv(aid39ChildEnv) == "1" {
		aid39Child(t)
		return
	}
	if testing.Short() {
		t.Skip("integration: две среды процесса — подпроцессы тестового бинарника")
	}

	bare := aid39RunEnv(t, "(1) без ручек", nil)
	knobs := aid39RunEnv(t, "(2) с ручками", []string{
		corevalidate.EnvExtraResourceIDPrefixes + "=xyz",
		corevalidate.LegacyEnvExtraResourceIDPrefixes + "=xyz",
		corevalidate.EnvExtraResourceIDHyphenPrefixes + "=qq",
		corevalidate.LegacyEnvExtraResourceIDHyphenPrefixes + "=qq",
	})

	// Сначала — среда построена: ручки дошли до процесса (2) и не дошли до (1).
	require.True(t, knobs.KnobAccepted, "контроль ручек: в среде (2) маршрутизатор фундамента не принял %s — "+
		"ручка до процесса не дошла, равенство вердиктов ничего бы не значило", aid39KnobProbe)
	require.False(t, bare.KnobAccepted, "контроль ручек: в среде (1) маршрутизатор фундамента принял %s", aid39KnobProbe)
	require.Len(t, bare.Verdicts, len(aid39Values()), "среда (1) судила не все значения")
	require.Len(t, knobs.Verdicts, len(aid39Values()), "среда (2) судила не все значения")

	// Затем — предмет: вердикты двух сред побайтово равны и равны таблицам.
	var differ, offTable []string
	expected := aid39Expected()
	for _, v := range aid39Values() {
		if bare.Verdicts[v] != knobs.Verdicts[v] {
			differ = append(differ, v+": (1) "+bare.Verdicts[v]+" · (2) "+knobs.Verdicts[v])
		}
		if want, ok := expected[v]; ok && bare.Verdicts[v] != want {
			offTable = append(offTable, v+": ждали "+want+", получено "+bare.Verdicts[v])
		}
	}
	t.Logf("перепись AID-39: значений %d · по таблицам %d · расходятся среды %d · вне таблиц %d",
		len(aid39Values()), len(expected), len(differ), len(offTable))
	require.Equal(t, aid39Reserve, knobs.Verdicts[aid39KnobProbe], "xyz…t1 в среде с ручками — не РЕЗЕРВ")
	require.Equal(t, aid39Reserve, knobs.Verdicts["qq-7m3k9q2x5v8b4n6t1"], "qq-…t1 в среде с ручками — не РЕЗЕРВ")
	require.Empty(t, differ, "резерв читает ручки окружения: вердикты двух сред расходятся")
	require.Empty(t, offTable, "вердикты распознавателя расходятся с таблицами AID-05/AID-06")

	// Посев: литерал (д3) — РЕЗЕРВ, прочие — отказ формы либо резерва. Инъекция —
	// литерал, добавленный в перечень посеянного, который форма принимает, а (д3)
	// не называет: находка с его именем; без инъекции — находок ноль.
	seeded := domain.SeededResourceIDs()
	require.NotEmpty(t, seeded, "перечень посеянного пуст — судить посев нечего")
	require.Empty(t, aid39SeedFindings(seeded, bare.Verdicts), "литералы посева, которые форма принимает")
	injected := aid39SeedFindings(append(append([]string(nil), seeded...), aid39InjectedSeed), bare.Verdicts)
	require.Len(t, injected, 1, "инъекция посева не найдена ровно одной находкой: %v", injected)
	require.True(t, strings.HasPrefix(injected[0], aid39InjectedSeed+" "), "находка инъекции не называет литерал: %v", injected)
}

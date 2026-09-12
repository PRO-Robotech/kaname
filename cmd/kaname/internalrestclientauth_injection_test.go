// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

// internalrestclientauth_injection_test.go — доказательство того, что обе
// половины соответствия «показание ↔ провод» СПОСОБНЫ упасть, и падают ровно на
// своём предмете.
//
// # Осей две, по числу половин
//
//  1. ПОСАДКА. Ломается режим ребра в БОЕВОМ ПРОФИЛЕ, дословно том же, что
//     читает процесс. Страж обязан отказать и назвать ручку вместе с обеими
//     величинами. Законный близнец — тот же профиль без правки: страж молчит.
//  2. ПОКАЗАНИЕ. Ломается производитель оси: вместо выведенного подаётся
//     КОНСТАНТА — ровно то, что стояло здесь до правки. Предикат соответствия
//     обязан покраснеть. Законный близнец — действующий производитель:
//     предикат молчит.
//
// # Инъекция роняет ТОЛЬКО проверяемое
//
// Дельта каждого мира против его близнеца — один факт: значение одной ручки
// либо подмена одного производителя. Ни один соседний контроль при этом не
// нарушается, поэтому красное приходит от того, что проверяется, а не от соседа.

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"gopkg.in/yaml.v3"

	"github.com/PRO-Robotech/corelib/servicecontract"

	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// loadProductionPosture ставит окружение из БОЕВОГО профиля службы — тем же
// наложением и теми же файлами, что читает проба стражей старта, — и отдаёт
// разобранную посадку транспорта.
//
// override применяется ПОСЛЕ наложения и есть единственная дельта мира.
func loadProductionPosture(t *testing.T, override map[string]string) config.MTLSConfig {
	t.Helper()
	values := map[string]any{}
	read := 0
	for _, name := range startupProfiles {
		raw, err := os.ReadFile(filepath.Join(chartDir, name))
		require.NoError(t, err, "профиль чарта не читается: %s", name)
		var profile map[string]any
		require.NoError(t, yaml.Unmarshal(raw, &profile))
		mergeInto(values, profile)
		read++
	}
	require.Equal(t, len(startupProfiles), read,
		"обход пуст: прочитано %d профилей из %d — инъекция беспредметна", read, len(startupProfiles))

	envRaw, ok := dig(values, "env")
	require.True(t, ok, "боевой профиль не объявляет карты переменных окружения")
	envMap, ok := envRaw.(map[string]any)
	require.True(t, ok)
	require.NotEmpty(t, envMap, "карта переменных окружения пуста — инъекция беспредметна")

	for name, value := range envMap {
		t.Setenv(name, strings.TrimSpace(strings.Trim(valueAsString(t, name, value), `"`)))
	}
	for name, value := range override {
		t.Setenv(name, value)
	}

	m, err := config.LoadMTLS()
	require.NoError(t, err, "посадка транспорта не разбирается")
	return m
}

const injectedInternalRESTAddr = "0.0.0.0:9099"

// TestInjection_PostureControl_ProductionProfilePassesTheGuard — КОНТРОЛЬ оси 1.
// Без него отказ ниже был бы неотличим от стража, отвергающего любую посадку.
func TestInjection_PostureControl_ProductionProfilePassesTheGuard(t *testing.T) {
	m := loadProductionPosture(t, nil)
	require.True(t, m.InternalRESTRequiresClientCert(),
		"боевой профиль обязан объявлять взаимный режим на внутреннем фронте; прочитано %q",
		m.InternalRESTClientAuthModeValue())
	require.NoError(t, requireInternalRESTMutualClientAuth(true, injectedInternalRESTAddr, m),
		"страж отверг НЕТРОНУТЫЙ боевой профиль — красное приходит не от инъекции")
}

// TestInjection_PostureBroken_OneWayEdgeIsRefused — ИНЪЕКЦИЯ оси 1, ровно один
// факт: режим ребра возвращён к одностороннему.
func TestInjection_PostureBroken_OneWayEdgeIsRefused(t *testing.T) {
	m := loadProductionPosture(t, map[string]string{
		"KANAME_INTERNALREST_SERVER_MTLS_CLIENTAUTHMODE": "server-tls-only",
	})
	require.False(t, m.InternalRESTRequiresClientCert(),
		"инъекция не доехала: посадка по-прежнему требует сертификата")

	err := requireInternalRESTMutualClientAuth(true, injectedInternalRESTAddr, m)
	require.Error(t, err,
		"боевая посадка с односторонним режимом на внутреннем фронте поднялась — "+
			"страж потерял способность отказывать")
	msg := err.Error()
	for _, want := range []string{
		"KANAME_INTERNALREST_SERVER_MTLS_CLIENTAUTHMODE",
		`"server-tls-only"`,
		`"mutual"`,
		injectedInternalRESTAddr,
	} {
		require.Contains(t, msg, want,
			"отказ не называет %q — оператор узнает, что не так, и не узнает, что чинить: %q",
			want, msg)
	}
}

// TestInjection_PostureBroken_RequestingModeIsRefused — вторая инъекция той же
// оси: запрашивающий режим выглядит взаимным и им не является.
func TestInjection_PostureBroken_RequestingModeIsRefused(t *testing.T) {
	m := loadProductionPosture(t, map[string]string{
		"KANAME_INTERNALREST_SERVER_MTLS_CLIENTAUTHMODE": "optional-mutual",
	})
	require.Error(t, requireInternalRESTMutualClientAuth(true, injectedInternalRESTAddr, m),
		"запрашивающий режим принят за сужение — соединение без удостоверения он пропускает")
}

// TestInjection_ReportControl_LiveProducerPassesItsCheck — КОНТРОЛЬ оси 2.
func TestInjection_ReportControl_LiveProducerPassesItsCheck(t *testing.T) {
	require.NoError(t, checkAuthAxisFollowsTheEdgeMode(internalRESTFrontAuthAxis),
		"предикат соответствия отверг ДЕЙСТВУЮЩИЙ производитель — красное приходит не от инъекции")
}

// TestInjection_ReportBroken_ConstantAxisIsCaught — ИНЪЕКЦИЯ оси 2: подан ровно
// тот производитель, что стоял здесь до правки, — константа, называющая
// проверенный сертификат модуля механизмом аутентификации вызывающего.
//
// Предикат обязан покраснеть. Если он молчит, самоотчёт снова может утверждать
// механизм, которого на проводе нет, и гейт, читающий его, станет вакуумным.
func TestInjection_ReportBroken_ConstantAxisIsCaught(t *testing.T) {
	retired := func(bool) servicecontract.Axis[servicecontract.SurfaceAuthMech] {
		return servicecontract.Value[servicecontract.SurfaceAuthMech](
			"цепочка внутреннего слушателя: проверенный сертификат модуля и его политика " +
				"вызывающего — фронт своего рубежа не заводит и ничего к личности не добавляет")
	}
	require.Error(t, checkAuthAxisFollowsTheEdgeMode(retired),
		"предикат принял КОНСТАНТУ: показание перестало следовать за проводом, и заметить "+
			"это нечем")
}

// TestInjection_ReportBroken_SilentAbsenceIsCaught — вторая инъекция той же
// оси: производитель, который на одностороннем режиме МОЛЧИТ.
//
// Молчание оси означает «не объявлена» — отказ старта, — но предикат обязан
// поймать это здесь, а не на поднятом стенде.
func TestInjection_ReportBroken_SilentAbsenceIsCaught(t *testing.T) {
	silent := func(requiresClientCert bool) servicecontract.Axis[servicecontract.SurfaceAuthMech] {
		if requiresClientCert {
			return internalRESTFrontAuthAxis(true)
		}
		return servicecontract.Axis[servicecontract.SurfaceAuthMech]{}
	}
	require.Error(t, checkAuthAxisFollowsTheEdgeMode(silent),
		"предикат принял НЕОБЪЯВЛЕННУЮ ось: «механизма нет» стало неотличимо от "+
			"«о механизме не сказали»")
}

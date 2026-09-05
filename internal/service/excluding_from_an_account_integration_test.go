// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// excluding_from_an_account_integration_test.go — «ИСКЛЮЧИТЬ ИЗ МОЕГО АККАУНТА»
// доступно тому, кто вправе туда пригласить, и НЕ доступно за границей его
// аккаунта. Вердикт по закоммиченным строкам, на той же двери, куда приходит
// каждый запрос платформы.
//
// # Предмет — вторая строка таблицы областей #1102 (#1127)
//
// Директива владельца (2026-08-23) оставляет распорядителю аккаунта две вещи:
// права и состав участников. Первую он имел; второй у него не было действия
// вовсе — у членства нет ни состояния приостановки, ни глагола снятия, поэтому
// «исключить» выражалось снятием выдач, а членство оставалось.
//
// # Эта проба — ЗЕРКАЛО соседних, и утверждает она обратное
//
// Соседи (`acting_as_a_person_*`, `governing_the_identity_*`,
// `removing_the_identity_*`) требуют, чтобы распорядитель аккаунта НЕ достал до
// строки личности. Здесь предмет — ЧЛЕНСТВО, и достать до него он обязан.
// Односторонний корпус читался бы как «аккаунту не оставлено ничего», а
// директива оставляет ему ровно это.
//
// Настоящий Postgres. Пропускается под кратким режимом.

package service_test

import (
	"testing"

	"github.com/stretchr/testify/require"
)

// TestExcludingFromAnAccountIsReachableFromInsideThatAccountOnly — вердикт по
// закоммиченным строкам.
func TestExcludingFromAnAccountIsReachableFromInsideThatAccountOnly(t *testing.T) {
	w := newCIWorld(t)

	const (
		accA       = "acc-excla1"
		accB       = "acc-exclb1"
		ownerA     = "usr-exclowna1"
		ownerB     = "usr-exclownb1"
		inviterA   = "usr-exclinva1"
		memberA    = "usr-exclmema1"
		cloudAdmin = "usr-exclcld1"
	)
	w.seedAccountWithOwner(t, accA, ownerA)
	w.seedAccountWithOwner(t, accB, ownerB)
	w.seedUser(t, inviterA, accA)
	w.seedUser(t, memberA, accA)
	w.seedUser(t, cloudAdmin, accA)

	// Пригласивший — распорядитель СВОЕГО аккаунта: ярус, которым гейтится
	// приглашение. Посев тем же способом, каким факт производит продукт.
	w.factThroughJournal(t, "user:"+inviterA, "editor", "account", accA)
	// Владелец — отдельным фактом, а не следствием строки: право владельца
	// приезжает кортежем, который пишет создание аккаунта. Посев без него сделал
	// бы утверждение «владелец может» ложным по причине фикстуры, а не продукта.
	w.factThroughJournal(t, "user:"+ownerA, "owner", "account", accA)
	w.factThroughJournal(t, "user:"+ownerB, "owner", "account", accB)
	// Уровень 1.
	w.factThroughJournal(t, "user:"+cloudAdmin, "system_admin", "cluster", "cluster_kacho_root")

	// Гейты спрашиваются У КАТАЛОГА: он порождается из proto и есть единственный
	// источник per-RPC решения края. Литерал означал бы, что проба утверждает о
	// СВОЁМ представлении гейта, а не о действующем.
	exclRel, exclType := actingAsGateFromCatalog(t, "kacho.cloud.iam.v1.UserService/RemoveFromAccount")
	admitRel, admitType := actingAsGateFromCatalog(t, "kacho.cloud.iam.v1.UserService/Invite")
	require.Equalf(t, "account", exclType,
		"исключение гейтится не на объекте аккаунта (%s) — предмет пробы сменился", exclType)
	require.Equalf(t, "account", admitType,
		"приглашение гейтится не на объекте аккаунта (%s) — контроль пары сменил предмет", admitType)
	require.NotEqualf(t, admitRel, exclRel,
		"приглашение и исключение гейтятся ОДНИМ отношением %q — тогда согласие пары ниже "+
			"тавтологично", exclRel)

	own := "account:" + accA
	foreign := "account:" + accB

	// ── КОНТРОЛЬ ФИКСТУРЫ ────────────────────────────────────────────────────
	// Посев живой: пригласивший ДЕЙСТВИТЕЛЬНО вправе приглашать в свой аккаунт.
	// Без этого утверждения «он может исключать» зеленело бы и на пустой базе с
	// отношением, разрешающим всё.
	require.True(t, w.allowed(t, "user:"+inviterA, admitRel, own),
		"КОНТРОЛЬ: пригласивший обязан держать отношение ПРИГЛАШЕНИЯ на своём аккаунте — "+
			"иначе фикстура ничего не посеяла, и равенство пары ниже вакуумно")

	// ── ПОЛОЖИТЕЛЬНОЕ — предмет пробы ────────────────────────────────────────
	require.True(t, w.allowed(t, "user:"+inviterA, exclRel, own),
		"пригласивший НЕ может исключить человека из СВОЕГО аккаунта. Тогда действие заведено, "+
			"а адресату не досталось: аккаунт по-прежнему копит людей, которых не может убрать, "+
			"— то самое состояние, ради выхода из которого заведено исключение (#1127)")
	require.True(t, w.allowed(t, "user:"+ownerA, exclRel, own),
		"владелец аккаунта не может исключить из своего аккаунта")
	require.True(t, w.allowed(t, "user:"+cloudAdmin, exclRel, own),
		"надзор облака не достаёт до исключения — сужение обязано оставлять расследование "+
			"возможным")

	// ── ОТРИЦАНИЕ 1 — за границей своего аккаунта права нет ──────────────────
	require.False(t, w.allowed(t, "user:"+inviterA, exclRel, foreign),
		"распорядитель аккаунта A исключает людей из аккаунта B. Область решения — аккаунт, "+
			"названный в запросе, и за его границу право не выходит")

	// ── ОТРИЦАНИЕ 2 — рядовой член аккаунта права не имеет ───────────────────
	require.False(t, w.allowed(t, "user:"+memberA, exclRel, own),
		"рядовой член аккаунта исключает из него других. Исключение — распоряжение составом "+
			"участников, а не действие, которое даёт само участие")

	// ── СОГЛАСИЕ ПАРЫ на наблюдаемом уровне ──────────────────────────────────
	// Модельный гейт сверяет круги ПЛАНОВ; здесь то же утверждение проверяется
	// ИСХОДОМ по каждому субъекту. Разъехаться они могут молча: у края своя
	// композиция, провязанная в композиционном корне, а не в модели.
	for _, who := range []string{inviterA, ownerA, cloudAdmin, memberA} {
		require.Equalf(t,
			w.allowed(t, "user:"+who, admitRel, own),
			w.allowed(t, "user:"+who, exclRel, own),
			"у субъекта %s вердикты ПРИГЛАШЕНИЯ и ИСКЛЮЧЕНИЯ разошлись. Тот, кто вправе ввести "+
				"человека в аккаунт, обязан быть вправе его оттуда вывести — и наоборот: право "+
				"выводить, но не вводить, столь же несимметрично", who)
	}

	t.Logf("перепись: гейт исключения %s.%s · гейт приглашения %s.%s · субъектов сверено 4 · "+
		"аккаунтов в фикстуре 2", exclType, exclRel, admitType, admitRel)
}

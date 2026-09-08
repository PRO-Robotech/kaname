// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"strings"
	"testing"
)

// restfrontaddr_test.go — отказ старта, когда адреса поверхностей совпали.
//
// # Предмет
//
// Раздельность фронтов есть свойство СОКЕТА: «внутреннее не опубликовано»
// проверяемо ровно тогда, когда оно недосягаемо. Совпавшие адреса делают
// требование невыполнимым by construction — но не отказом, а ТИШИНОЙ: поднимется
// то из двух, что успело занять порт, и снаружи это выглядит исправной работой.
//
// Поэтому исход — отказ СТАРТА, а не запись в журнал: неверную посадку чинят
// один раз в профиле, а не ловят потом по симптому.

func TestRefusesToStartWhenSurfaceAddressesCollide(t *testing.T) {
	const (
		publicGRPC   = ":9090"
		internalGRPC = ":9091"
		publicREST   = ":9098"
		internalREST = ":9099"
	)

	t.Run("контроль: все четыре адреса различны — старт разрешён", func(t *testing.T) {
		if err := requireDistinctSurfaceAddrs(publicGRPC, internalGRPC, publicREST, internalREST); err != nil {
			t.Fatalf("страж отказал на законной посадке: %v", err)
		}
	})

	t.Run("контроль: фронты не объявлены — судить нечего", func(t *testing.T) {
		// Пустой адрес означает «фронт не поднят». Два невыставленных фронта
		// НЕ совпадают: совпасть могут только занятые порты.
		if err := requireDistinctSurfaceAddrs(publicGRPC, internalGRPC, "", ""); err != nil {
			t.Fatalf("страж отказал на посадке без фронтов: %v", err)
		}
	})

	t.Run("инъекция: адреса двух фронтов совпали", func(t *testing.T) {
		err := requireDistinctSurfaceAddrs(publicGRPC, internalGRPC, publicREST, publicREST)
		if err == nil {
			t.Fatal("страж принял посадку, где оба фронта слушают один адрес: " +
				"раздельность перестала быть свойством сокета, и это не отказ, а тишина")
		}
		// Текст отказа — рантайм-диагностика оператору: он обязан назвать ОБЕ
		// совпавшие ручки, иначе оператор знает, что не так, и не знает, где чинить.
		for _, want := range []string{"REST_ENDPOINT", "INTERNAL_REST_ENDPOINT", publicREST} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("отказ не называет %q: %v", want, err)
			}
		}
	})

	t.Run("инъекция: адрес фронта совпал с адресом gRPC-слушателя", func(t *testing.T) {
		err := requireDistinctSurfaceAddrs(publicGRPC, internalGRPC, publicGRPC, internalREST)
		if err == nil {
			t.Fatal("страж принял посадку, где REST-фронт слушает адрес gRPC-слушателя")
		}
		for _, want := range []string{"REST_ENDPOINT", "ENDPOINT", publicGRPC} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("отказ не называет %q: %v", want, err)
			}
		}
	})

	t.Run("инъекция: внутренний фронт занял адрес внутреннего слушателя", func(t *testing.T) {
		if err := requireDistinctSurfaceAddrs(publicGRPC, internalGRPC, publicREST, internalGRPC); err == nil {
			t.Fatal("страж принял посадку, где внутренний фронт слушает адрес внутреннего слушателя")
		}
	})

	t.Run("отказ называет ВСЕ совпадения сразу, а не первое", func(t *testing.T) {
		// Оператор чинит профиль один раз, а не по одному совпадению за
		// перезапуск: страж, останавливающийся на первом, продаёт круг подъёма.
		err := requireDistinctSurfaceAddrs(publicGRPC, internalGRPC, publicGRPC, internalGRPC)
		if err == nil {
			t.Fatal("страж принял посадку с двумя совпадениями разом")
		}
		if strings.Count(err.Error(), "REST_ENDPOINT") < 2 {
			t.Errorf("отказ назвал не все совпадения: %v", err)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// УДОСТОВЕРЕНИЕ ФРОНТА К СОБСТВЕННОМУ СЛУШАТЕЛЮ
//
// Класс: контроль, у которого нет механизма исполниться. Адрес соседа объявлен,
// а удостоверение, которым к нему представляются, — нет. Отказ тогда
// детерминированный и одинаковый: слушатель отвечает «требуется сертификат
// клиента», фронт классифицирует это как невозможность получить ответ, и
// снаружи это выглядит как «служба недоступна» при исправной службе.
//
// Заметить это на стенде без боевой посадки нельзя: там слушатель сертификата
// не требует, и фронт работает. Поэтому предмет — ОТКАЗ СТАРТА, а не журнал.

type upstreamCredStub struct{ enabled bool }

func (s upstreamCredStub) RESTUpstreamEnabled() bool { return s.enabled }

func TestRefusesToStartWhenTheFrontHasNoCredentialForItsOwnListener(t *testing.T) {
	t.Run("контроль: фронт поднят, удостоверение задано — старт разрешён", func(t *testing.T) {
		if err := requireRESTUpstreamCredential(true, ":9098", ":9099", upstreamCredStub{true}); err != nil {
			t.Fatalf("страж отказал на законной посадке: %v", err)
		}
	})

	t.Run("контроль: не боевая посадка — судить нечего", func(t *testing.T) {
		if err := requireRESTUpstreamCredential(false, ":9098", ":9099", upstreamCredStub{false}); err != nil {
			t.Fatalf("страж отказал вне боевой посадки: %v", err)
		}
	})

	t.Run("контроль: фронты не подняты — удостоверение не нужно", func(t *testing.T) {
		if err := requireRESTUpstreamCredential(true, "", "", upstreamCredStub{false}); err != nil {
			t.Fatalf("страж отказал там, где фронтов нет: %v", err)
		}
	})

	t.Run("инъекция: фронт поднят, удостоверения нет", func(t *testing.T) {
		err := requireRESTUpstreamCredential(true, ":9098", "", upstreamCredStub{false})
		if err == nil {
			t.Fatal("страж принял посадку, где фронт поднят без удостоверения к своему " +
				"слушателю: в боевом режиме слушатель отвергнет его на КАЖДОМ запросе, " +
				"и снаружи это неотличимо от недоступной службы")
		}
		for _, want := range []string{"KANAME_REST_UPSTREAM_MTLS_ENABLE", "REST_ENDPOINT"} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("отказ не называет %q: %v", want, err)
			}
		}
	})

	t.Run("инъекция: поднят только внутренний фронт — та же пара обязательна", func(t *testing.T) {
		if err := requireRESTUpstreamCredential(true, "", ":9099", upstreamCredStub{false}); err == nil {
			t.Fatal("страж принял внутренний фронт без удостоверения")
		}
	})
}

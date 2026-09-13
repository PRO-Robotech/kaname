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
// Раздельность поверхностей есть свойство СОКЕТА: «внутреннее не опубликовано»
// проверяемо ровно тогда, когда оно недосягаемо. Совпавшие адреса делают
// требование невыполнимым by construction.
//
// Здесь проверяется, что страж видит ВСЕ поверхности корня, а не четыре из
// восьми (#2639): совпадение скрейпа с зеркалом ключей — такая же неисполнимая
// посадка, как совпадение двух фронтов, и до расширения сверки страж о нём
// молчал.
//
// Почему исход — отказ старта, а не запись в журнал, и чего страж НЕ закрывает
// (привязка судит сокет, а он — строку профиля), разобрано в шапке
// `restfrontaddr.go`; здесь это не пересказывается.

func TestRefusesToStartWhenSurfaceAddressesCollide(t *testing.T) {
	const (
		publicGRPC    = ":9090"
		internalGRPC  = ":9091"
		hooks         = ":9094"
		metrics       = ":9095"
		registryToken = ":9096"
		jwksProxy     = ":9097"
		publicREST    = ":9098"
		internalREST  = ":9099"
	)
	// allEight — посадка, какой её объявляет боевой профиль: восемь поверхностей,
	// все на своих адресах.
	allEight := func() []surfaceAddr {
		return []surfaceAddr{
			{knobPublicGRPC, publicGRPC},
			{knobInternalGRPC, internalGRPC},
			{knobHooks, hooks},
			{knobMetrics, metrics},
			{knobRegistryToken, registryToken},
			{knobJWKSProxy, jwksProxy},
			{knobPublicREST, publicREST},
			{knobInternalREST, internalREST},
		}
	}

	t.Run("контроль: восемь адресов различны — старт разрешён", func(t *testing.T) {
		census, err := requireDistinctSurfaceAddrs(allEight())
		if err != nil {
			t.Fatalf("страж отказал на законной посадке: %v", err)
		}
		if census.Declared != 8 || census.Addressed != 8 {
			t.Fatalf("перепись: объявлено %d, с адресом %d — ожидалось 8 и 8. Одно "+
				"число скрыло бы поверхность, выпавшую из сверки",
				census.Declared, census.Addressed)
		}
		if census.Pairs != 28 {
			t.Fatalf("сверено пар %d, а восемь адресов дают 28 — часть поверхностей "+
				"в сверку не вошла", census.Pairs)
		}
	})

	t.Run("контроль: поверхность не объявлена — судить нечего", func(t *testing.T) {
		// Пустой адрес означает «поверхность не поднята». Две неподнятые НЕ
		// совпадают: совпасть могут только занятые порты.
		surfaces := append(allEight()[:6:6],
			surfaceAddr{knobPublicREST, ""}, surfaceAddr{knobInternalREST, ""})
		census, err := requireDistinctSurfaceAddrs(surfaces)
		if err != nil {
			t.Fatalf("страж отказал на посадке без фронтов: %v", err)
		}
		if census.Declared != 8 || census.Addressed != 6 {
			t.Fatalf("перепись: объявлено %d, с адресом %d — ожидалось 8 и 6: "+
				"выключенная поверхность обязана быть видна объявленной и не сверяемой",
				census.Declared, census.Addressed)
		}
	})

	t.Run("инъекция: адреса двух фронтов совпали", func(t *testing.T) {
		surfaces := allEight()
		surfaces[7].addr = publicREST
		_, err := requireDistinctSurfaceAddrs(surfaces)
		if err == nil {
			t.Fatal("страж принял посадку, где оба фронта слушают один адрес: " +
				"раздельность перестала быть свойством сокета")
		}
		// Текст отказа — рантайм-диагностика оператору: он обязан назвать ОБЕ
		// совпавшие ручки, иначе оператор знает, что не так, и не знает, где чинить.
		for _, want := range []string{knobPublicREST, knobInternalREST, publicREST} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("отказ не называет %q: %v", want, err)
			}
		}
	})

	t.Run("инъекция: скрейп занял адрес зеркала ключей", func(t *testing.T) {
		// РАДИ ЭТОГО СЛУЧАЯ сверка и расширена: обе поверхности прежним стражем
		// не судились вовсе, и совпадение их адресов он принимал молча.
		surfaces := allEight()
		surfaces[3].addr = jwksProxy
		_, err := requireDistinctSurfaceAddrs(surfaces)
		if err == nil {
			t.Fatal("страж принял посадку, где скрейп и зеркало ключей слушают один " +
				"адрес: поверхности, которых сверка не знает, и есть её слепая зона")
		}
		for _, want := range []string{knobMetrics, knobJWKSProxy, jwksProxy} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("отказ не называет %q: %v", want, err)
			}
		}
	})

	t.Run("инъекция: вебхуки заняли адрес публичного gRPC", func(t *testing.T) {
		surfaces := allEight()
		surfaces[2].addr = publicGRPC
		_, err := requireDistinctSurfaceAddrs(surfaces)
		if err == nil {
			t.Fatal("страж принял посадку, где вебхуки слушают адрес gRPC-слушателя")
		}
		for _, want := range []string{knobHooks, knobPublicGRPC} {
			if !strings.Contains(err.Error(), want) {
				t.Errorf("отказ не называет %q: %v", want, err)
			}
		}
	})

	t.Run("инъекция: выдача докерного токена заняла адрес внутреннего фронта", func(t *testing.T) {
		surfaces := allEight()
		surfaces[4].addr = internalREST
		if _, err := requireDistinctSurfaceAddrs(surfaces); err == nil {
			t.Fatal("страж принял посадку, где выдача токена слушает адрес " +
				"внутреннего REST-фронта")
		}
	})

	t.Run("отказ называет ВСЕ совпадения сразу, а не первое", func(t *testing.T) {
		// Оператор чинит профиль один раз, а не по одному совпадению за
		// перезапуск: страж, останавливающийся на первом, продаёт круг подъёма.
		surfaces := allEight()
		surfaces[3].addr = jwksProxy  // скрейп ↔ зеркало ключей
		surfaces[7].addr = publicREST // внутренний фронт ↔ публичный
		census, err := requireDistinctSurfaceAddrs(surfaces)
		if err == nil {
			t.Fatal("страж принял посадку с двумя совпадениями разом")
		}
		if census.Collisions != 2 {
			t.Errorf("совпадений названо %d, внесено 2: %v", census.Collisions, err)
		}
	})

	t.Run("контроль: пустая посадка — вердикт беспредметен и виден переписью", func(t *testing.T) {
		// Ноль сверенных пар выглядит как чистая посадка, и отличить одно от
		// другого может только перепись. Страж не падает здесь намеренно:
		// «поверхностей не объявлено» — состояние корня, а не профиля.
		census, err := requireDistinctSurfaceAddrs(nil)
		if err != nil {
			t.Fatalf("страж отказал на пустом перечне: %v", err)
		}
		if census.Declared != 0 || census.Pairs != 0 {
			t.Fatalf("перепись пустого перечня: объявлено %d, пар %d",
				census.Declared, census.Pairs)
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

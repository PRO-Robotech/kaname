// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package main

import (
	"fmt"
	"log/slog"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kacho/pkg/servicecontract"

	"github.com/PRO-Robotech/kacho-iam/internal/apps/kacho/config"
)

// describePosture — ОБЪЯВЛЕНИЕ kacho-iam о своей посадке центральному
// дескриптору (`pkg/servicecontract`), задача продукта #1406.
//
// # Что это меняет, и это НЕ «была дыра»
//
// Стража посадки у iam и раньше было два — `config.Config.Validate` и
// production-гейт обоих gRPC-слушателей в `runServe`, — оба позваны, оба
// отказывают. Не хватало другого: ЕДИНОГО ИСТОЧНИКА. Пока набор осей, которые
// процесс судит, выбирает он сам, «эту ось здесь забыли» неотличимо от «эту ось
// здесь решили не судить», а перечни безопасных значений расходятся молча —
// каждый в своей копии. Здесь iam приносит те же величины туда, где их судят
// ОДНИМ перечнем на всё дерево, и отказ называет каждую незаполненную ось разом.
//
// # Почему объявлен СОБСТВЕННЫЙ контур
//
// [servicecontract.Spec] описывает две разные вещи: посадку — она есть у
// каждого развёрнутого процесса, — и проводку носителя (`pkg/servicehost`):
// что эмитить, что сужать, что скрывать, какие пределы ставить звеньям. Вторую
// читает только носитель. Контур входящего пути iam носитель НЕ поднимает:
// gRPC-слушателей у процесса два, но рядом с ними живут ещё четыре не-gRPC
// поверхности, своя дверь решения о доступе (iam — владелец модели, а не её
// спрашивающий) и своя цепочка звеньев, собранная в этом корне. Принеси мы
// проводку — её бы никто не прочитал, и она разошлась бы с фактической ручной
// сборкой МОЛЧА. Поэтому она не приносится, а конструктор её принесение
// отвергает (О14).
//
// # Что осталось у процесса и почему
//
// Транспорт двух gRPC-слушателей судит production-гейт в `runServe`: у iam их
// не «ровно два», как знает дескриптор, а два gRPC плюс четыре HTTP-поверхности
// со своими профилями ([servicecontract.Surface]), и объявить их парой полей
// значило бы описать форму, которой у процесса нет. Ось названа остатком, а не
// закрыта молча.
func describePosture(cfg config.Config, logger *slog.Logger) (servicecontract.Descriptor, error) {
	mode, err := servicecontract.ParseMode(cfg.AuthN.Mode.String())
	if err != nil {
		return servicecontract.Descriptor{}, fmt.Errorf("authn.mode: %w", err)
	}

	return servicecontract.New(servicecontract.Spec{
		Service: "kacho-iam",
		Mode:    mode,
		Logger:  logger,

		// Контур входящего пути собран в этом корне — см. разбор в шапке.
		OwnContour: "контур входящего пути kacho-iam собран в его композиционном корне: " +
			"два gRPC-слушателя плюс четыре не-gRPC поверхности со своими профилями, " +
			"и дверь решения о доступе своя — iam владелец модели, а не её спрашивающий",

		// Круг отправителей — ЗНАЧЕНИЕ, а не изъятие: iam принимает переданную
		// личность конечного пользователя на обоих gRPC-слушателях, и сужать её
		// круг ему есть чем. Берётся ровно то значение, что уезжает в звенья
		// извлечения личности: общая библиотека отбрасывает пустые записи,
		// поэтому список из одних пустых вырождается там в «доверяем любому», и
		// подать сюда сырое поле значило бы судить намерение вместо исхода.
		Forwarders: servicecontract.Value(cfg.AuthN.TrustedForwarders()),
		ForwarderKnobs: servicecontract.ForwarderKnobs{
			SANs:     "authn.trusted-forwarder-sans (env KACHO_IAM_AUTHN__TRUSTED_FORWARDER_SANS)",
			TrustAny: "authn.trust-any-forwarder (env KACHO_IAM_AUTHN__TRUST_ANY_FORWARDER)",
			OptIn:    cfg.AuthN.TrustAnyForwarder,
		},

		// Шифрование до собственной базы — ЗНАЧЕНИЕ: база у iam своя. Читается из
		// ТОЙ строки, что уходит в пул: `sslmode` приходит и из настройки, и из
		// сырого URL, а пустое поле деривится в `disable`. Судить настройку
		// вместо строки значило бы судить намерение.
		DBSSLMode: servicecontract.Value(coredb.SSLModeFromDSN(cfg.DSN())),
	})
}

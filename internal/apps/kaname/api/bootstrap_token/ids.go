// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package bootstrap_token — the InternalBootstrapTokenService use-case (#58):
// idempotently provision the singleton bootstrap-admin ServiceAccount's key
// mapping, then mint a short-lived access-token for it with OUR signer
// (aud = https://{API_DOMAIN}).
//
// The bootstrap SA row + its cluster system_admin grant are seeded by the
// baseline (deterministic id → DB-singleton). This use-case provisions only the
// 1:1 service_account_oauth_clients mapping, gated by the UNIQUE(sva_id)
// mapping index + a transaction-scoped advisory lock (IBT-03), and mints the
// token. The signing key is env-held (k8s Secret), NEVER persisted in the DB —
// the secrets-at-rest posture of the platform.
package bootstrap_token

// ids.go — идентификаторы посевной идентичности, ПИННУТЫЕ литералом.
//
// # ПОЧЕМУ ЛИТЕРАЛ, А НЕ ФОРМУЛА (задача продукта #2554, §2.2 приёмки
// `docs/engineering/acceptance/seed-identity-names-its-own-service.md`)
//
// Прежде все три значения выводились из ИМЁН: `'sva' || substr(md5('<имя>'),1,17)`
// и далее. Формула была верна, пока имя стояло на месте, — и переставала быть
// верной в тот момент, когда имя переводили. Переводится оно решением §2.3, а
// идентификатор двигать нельзя (ban #15: операции смены id не существует) и
// поправить посев нельзя (ban #5: применённую миграцию не правят).
//
// Два требования несовместимы, пока формула хозяин, — значит хозяином
// перестаёт быть формула. Литерал здесь не «магическое число»: это ТА САМАЯ
// строка, которую посеял свод, и её единственный источник — текст свода, а не
// второй расчёт. Пересчёт был бы вторым объявлением одной формулы и сошёлся бы с
// первым при ЛЮБОМ имени, то есть остался бы зелёным ровно в том случае, ради
// которого написан.
//
// Держит это `TestDeriveIdentity_IDsArePinnedToTheAppliedBaseline`: каждый
// идентификатор обязан встречаться литералом в тексте применённого свода.
//
// # ЧТО ФОРМУЛА ПРОДОЛЖАЕТ ДЕЛАТЬ — ГРАНИЦА, А НЕ ОСТАТОК
//
// `domain.DerivedIDSuffix` не снят и снят не будет: служебные учётки модулей
// (`authzguard`) выводят идентификатор из имени законно — там имя и
// идентификатор двигаются ВМЕСТЕ, и деривация верна. Единственность её
// объявления держит `TestDeterministicIDDerivationIsDeclaredOnce`.
//
// # ИМЕНИ КЛИЕНТА У ВНЕШНЕГО ПРОВАЙДЕРА ЗДЕСЬ БОЛЬШЕ НЕТ
//
// Строка чеканки называлась у прежнего издателя своим именем, отличным от её
// `id`, и путь запроса писал это имя в столбец зеркала. Столбец снят (kaname#362): токен
// бутстрапа чеканит наш подписант, клиентом строка называется по своему `id`, а
// край токенов прежнего издателя не принимает. Прежние строки с этим именем
// миграция снятия пропускает названным исключением ровно по этой тройке.

const (
	// pinnedBootstrapSvaID — `service_accounts.id` служебной записи чеканки.
	// Посеян `0001_initial.sql:3843`.
	pinnedBootstrapSvaID = "svab91854890de887e6d"

	// pinnedBootstrapSocID — `service_account_oauth_clients.id`, он же `kid`
	// ключа и имя клиента.
	//
	// Свод этой строки НЕ сеет — её заводит путь запроса, — но значение обязано
	// оставаться тем же: строку, заведённую прежним выпуском, путь запроса
	// находит по нему, и исключение миграции снятия зеркала названо им же.
	pinnedBootstrapSocID = "soc_db27d17291ff453b6"

	// pinnedSystemOwnerUserID — `users.id` владельца системного аккаунта,
	// внешний ключ строки отображения. Посеян `0001_initial.sql:3880`.
	pinnedSystemOwnerUserID = "usr1a18042d81fb438d6"
)

// Identity — the deterministic bootstrap identity (matches migration 0058's
// seeded rows).
type Identity struct {
	// SvaID — the bootstrap ServiceAccount id (`sva…`, seeded by 0058).
	SvaID string
	// SocID — the service_account_oauth_clients mapping id (`soc_…`); also the
	// key `kid` and the client name.
	SocID string
	// CreatedByUserID — the system owner user (`usr…`, FK for the mapping row).
	CreatedByUserID string
}

// DeriveIdentity возвращает посевную идентичность чеканки. Чистая; ввода-вывода
// нет.
//
// Имя функции сохранено намеренно: у неё 19 вызывающих, и переименование ради
// точности слова стоило бы правки каждого при нулевом выигрыше для читателя.
// Что она больше не ВЫЧИСЛЯЕТ, сказано шапкой файла и держится пробой, а не
// именем.
func DeriveIdentity() Identity {
	return Identity{
		SvaID:           pinnedBootstrapSvaID,
		SocID:           pinnedBootstrapSocID,
		CreatedByUserID: pinnedSystemOwnerUserID,
	}
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_copy_parity.go — сверка двух копий каталога прав: своей и копии края.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ЗДЕСЬ ИЗМЕНИЛОСЬ И ПОЧЕМУ (kaname#79)
//
// Прежняя сверка была `cmp` двух файлов с ОДНОНАПРАВЛЕННОЙ посылкой: «источник
// истины один — копия края», и единственный совет находки — позвать
// `sync-permission-catalog`, то есть ПЕРЕПИСАТЬ свою копию копией края.
//
// Посылка держалась, пока оба дерева линковали ОДИН фундамент. Она перестала
// держаться, когда фундамент переименовал свой контракт: полное имя метода у
// контракта, живущего в библиотеке, задаёт ВЕРСИЯ БИБЛИОТЕКИ, которую линкует
// дерево, а версии у деревьев разные. Тогда расхождение означает не «наша копия
// отстала», а «отстала копия края», и прежний совет в этом направлении ВРЕДЕН:
//
//	перепись 2026-09-14 (`corelib@v1.7.0` переименовал форму подписки;
//	платформа на своём стволе пинила `corelib@v1.5.0`):
//	  записей у каждой стороны   338
//	  расходится                   1  — только сегмент пакета в `fqn`
//	  остальные поля записи       совпадают дословно
//
// Этот случай ЗАКРЫТ 2026-09-15: платформа подняла пин, копии снова совпадают
// побайтово, и запись ведомости, объяснявшая расхождение, снята — разбор у
// самой ведомости ниже. Довод о направлении оставлен, потому что он о КЛАССЕ:
// следующее переименование в фундаменте даст ту же картину.
//
// ЧЕМ ВРЕДЕН СОВЕТ — сказано ровно настолько, насколько измерено.
//
// Наша копия индексируется ПО `fqn` (`internal/apps/kaname/seed/permissions.go`,
// `byFQN`), и по нему же её спрашивают о ПОЛНОМ ИМЕНИ МЕТОДА, с которым вызов
// пришёл на СВОЙ слушатель (`internal/authzguard/acr_floor.go`,
// `requiredACRMin` → `strings.TrimPrefix(fullMethod, "/")`;
// `public_caller_policy.go`). Служба линкует `corelib@v1.7.0`, поэтому вызов
// приходит как `/corelib.subscription.…/Subscribe`. Записав сюда имя отставшего
// края, мы положили бы в посев имя метода, которого этот двоичный файл НЕ
// СЛУЖИТ, — мёртвая запись, а у служимого глагола записи бы не стало.
//
// ГРАНИЦА ЭТОГО ДОВОДА НАЗВАНА, ЧТОБЫ ЕГО НЕ ПЕРЕСКАЗАЛИ ШИРЕ. У пола ACR
// промах поиска даёт исход «требования нет» (правило 3 в `allow`), но ДО него
// стоит правило 1: глагол обязан быть во фронтируемом краем наборе
// (`authzguard.GatewayFrontedInternalRPCs`). Перепись 2026-09-14: глагола
// подписки в этом наборе НЕТ, значит сегодня промах на нём ИНЕРТЕН. Довод
// латентный, а не наступивший, и записан он так намеренно: наступит он тогда,
// когда глагол во фронтируемый набор внесут, — и заметить это будет нечем.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО СВЕРКА УТВЕРЖДАЕТ ТЕПЕРЬ
//
// Норма прежняя и НЕ ослаблена: копии — ОДИН порождённый артефакт. Изменилось
// то, что у равенства появились ТРИ закрытых перечня объявленных окон —
// переименования фундамента, записи службы, ждущие края (kaname#181), и
// глаголы, снятые службой, которые край ещё называет (kaname#564), — и каждая
// запись обязана держать себя САМА в обе стороны. Остаток после их
// применения — находка с прежним текстом.
//
// Сравнение остаётся ПОБАЙТОВЫМ, а не «по смыслу»: файл режется на блоки
// записей по своей же форме, сборка блоков обязана дословно воспроизвести
// исходный файл (иначе форма файла сменилась — тоже находка), переименование
// применяется к блоку края, блоки пересортировываются по `fqn` (переименование
// двигает запись в перечне) и сравниваются дословно.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ЭТА СВЕРКА НЕ ЗАКРЫВАЕТ — сказано прямо
//
//  1. Она НЕ знает пина фундамента у края: в конвейере копия края приезжает
//     ВЫБОРКОЙ одного каталога, `go.mod` платформы в ней нет. Поэтому
//     направление расхождения не ВЫЧИСЛЯЕТСЯ, а ОБЪЯВЛЯЕТСЯ ведомостью ниже, и
//     держится ведомость самоистечением, а не доверием.
//  2. Она НЕ судит, верно ли переименование по существу. Она судит, что оно
//     объявлено, что обе его стороны в деревьях ЕСТЬ и что кроме него не
//     разошлось ничего.
//  3. Провязка сверки к конвейеру — предмет `catalog_check_wiring.go`, не этот.
package check

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

// CatalogFoundationRename — объявленное расхождение копий, произведённое
// переименованием контракта, чей владелец — ФУНДАМЕНТ, а не одно из двух
// деревьев. Пока деревья пинят разные версии фундамента, обе копии верны
// каждая для своей, и совпасть они не могут by construction.
type CatalogFoundationRename struct {
	// EdgeFQN — полное имя метода в копии края.
	EdgeFQN string
	// OwnFQN — полное имя того же метода в нашей копии.
	OwnFQN string
	// Why — почему расхождение не дефект.
	Why string
	// Removal — ПРЕДИКАТ СНЯТИЯ записи, внешний по отношению к этому дереву.
	Removal string
	// Refs — где предмет ведётся.
	Refs string
}

// catalogFoundationRenames — ЗАКРЫТЫЙ перечень объявленных расхождений.
//
// Запись здесь — послабление, и оно связано теми же тремя условиями, что всякое
// другое: величина названа замером (сколько записей из скольких расходится),
// предмет заведён (`Refs`), снятие наступает от ВНЕШНЕГО факта, а не от чьей-то
// памяти. Самоистечение держит `CompareCatalogCopies`: запись, чьей стороне в
// дереве больше нечего исключать, — находка.
//
// ПУСТОЙ ПЕРЕЧЕНЬ — ЦЕЛЬ, А НЕ ПОЛОМКА. На нём сверка требует побайтового
// совпадения копий и печатает «переименований объявлено 0»; способность падать
// у неё держат пробы на синтетике, а не наличие записи здесь.
//
// ─────────────────────────────────────────────────────────────────────────────
// СНЯТА ЕДИНСТВЕННАЯ ЗАПИСЬ — САМОИСТЕЧЕНИЕ СРАБОТАЛО ТАК, КАК ОБЪЯВЛЕНО
//
// Запись объясняла расхождение формы подписки: у края глагол стоял под именем
// пакета платформы, у нас — под именем пакета фундамента (`corelib@v1.7.0`
// переименовал контракт; kaname#79 · PRO-Robotech/kacho#2601 ·
// PRO-Robotech/corelib#7). Её предикат снятия звучал: «копия края называет
// глагол именем фундамента — платформа подняла пин до v1.7.0 и перегенерировала
// каталог».
//
// Предикат наступил на стволе платформы `edc98869b7` (2026-09-15): её `go.mod`
// пинит `corelib v1.7.0`, копия края называет глагол именем фундамента, прежнего
// имени в ней нет. Сверка против этого ствола дала (`make check-permission-catalog
// EDGE_TREE=<выборка ствола>`):
//
//	перепись: записей у края 338 · записей у нас 338 · переименований объявлено 1 · применено 0 · побайтово до ведомости true
//	НАХОДКА: ведомость объявленных переименований пережила свой предмет.
//
// То есть копии совпали побайтово, а красное пришло от самой записи — вид
// `CatalogFindingLedger`, не `CatalogFindingCopies`. Других записей в перечне не
// было, поэтому он опустел.
//
// ─────────────────────────────────────────────────────────────────────────────
// СНЯТЫ ДВЕ ЗАПИСИ ОКНА — ФОРМА ОПЕРАЦИИ (PRO-Robotech/kacho#2601)
//
// Класс предсказан абзацем в шапке файла и наступил третьим переименованием в
// фундаменте: `corelib@v1.8.0` назвал форму операции корнем фундамента, служба
// начала служить `OperationService/Get` и `/Cancel` под именем
// `corelib.operation`, а копия края на стволе платформы до подъёма её пинов
// называла их по-прежнему. Окно держали две записи ведомости (#98).
//
// Предикат снятия наступил на стволе платформы `bdaedfd5aa` (#2659): её `go.mod` пинит
// `corelib v1.8.0` и службу `40bd49a3`, каталог края перерождён и называет оба
// глагола именем фундамента. Сверка против этого ствола дала находку вида
// `CatalogFindingLedger` («нечего исключать» по обеим записям) при побайтово
// совпавших копиях — самоистечение, а не расхождение. Других записей нет,
// перечень пуст.
var catalogFoundationRenames = []CatalogFoundationRename{}

// CatalogFoundationRenames — объявленный перечень (копия, чтобы вызывающий не
// правил ведомость через возвращённый срез).
func CatalogFoundationRenames() []CatalogFoundationRename {
	out := make([]CatalogFoundationRename, len(catalogFoundationRenames))
	copy(out, catalogFoundationRenames)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// ВТОРОЙ ВИД ЗАПИСИ — ГЛАГОЛ СЛУЖБЫ, КОТОРОГО КРАЙ ЕЩЁ НЕ ВИДЕЛ (kaname#181)
//
// Тот же класс окна, что у переименования фундамента, с другой стороны: служба
// завела СВОЙ глагол, а копия края порождается из её контракта ПО ПИНУ — то есть
// увидит его только после посадки в ствол службы и подъёма пина платформой.
// Промежуточного состояния, в котором обе копии совпали бы, не существует by
// construction: пин не поднять на ревизию, которой в стволе нет, а ствол не
// принять с красной сверкой.
//
// Запись объявляет: у нас эта запись ЕСТЬ, у края её ещё НЕТ, и это не
// расхождение. Держит себя в обе стороны: край назвал глагол — предикат снятия
// наступил, запись обязана уйти и копия — синхронизироваться; в нашей копии
// глагола нет — запись утверждает о дереве неправду.
//
// Что при этом НЕ ослаблено: содержимое нашей записи не сверяется ни с чем,
// пока края нет, — поэтому запись сюда кладётся ПОРОЖДЁННОЙ генератором края
// над своим контрактом, а не рукой; расхождение с тем, что край породит по
// пину, всплывёт первой же сверкой после подъёма — находкой вида «копии».

// CatalogPendingEntry — запись нашей копии, у которой в копии края ещё нет
// предмета, потому что край порождает её из нашего контракта по пину.
type CatalogPendingEntry struct {
	// OwnFQN — полное имя метода в нашей копии.
	OwnFQN string
	// Why — почему отсутствие у края не дефект.
	Why string
	// Removal — ПРЕДИКАТ СНЯТИЯ, внешний по отношению к этому дереву.
	Removal string
	// Refs — где предмет ведётся.
	Refs string
}

// catalogPendingEntries — ЗАКРЫТЫЙ перечень записей, ждущих края.
//
// Условия те же три, что у переименований: величина названа замером, предмет
// заведён, снятие наступает от внешнего факта. Самоистечение держит
// `CompareCatalogCopies`: запись, чей глагол край уже назвал, — находка.
//
// Самоистечение сработало 2026-09-17: ствол платформы `b5fa0933` (kacho#2706,
// пин службы `94352d9c`) назвал `MembershipService/Create` (kaname#181) и
// `UserService/ResendInvite` (kaname#186) — обе записи сняты тем же изменением
// (перепись до снятия: у края 341 · у нас 343 · ожидающих 4 · применено 2).
//
// Самоистечение сработало снова 2026-09-18: ствол платформы `ac33f733`
// (kacho#2710, пин службы `16b5cade`) назвал `UserService/ResetSecondFactor`
// (kacho#1281, Ф12) и `MembershipService/ListMine` (kaname#206) — обе записи
// сняты тем же изменением (перепись до снятия: у края 343 · у нас 349 ·
// ожидающих 8 · применено 6). Наша копия уже несла оба глагола в ФОРМЕ КРАЯ
// (порождены генератором края над контрактом), поэтому копии совпадают в их
// части побайтово: пересинхронизация не нужна, а `sync-permission-catalog`
// здесь ВРЕДНА — наша копия надмножество края на шесть глаголов ключа доступа
// (kacho#1273), и `cp` копии края поверх снял бы их.
//
// Самоистечение сработало в третий раз 2026-10-03: ствол платформы `e702195f5`
// (kacho#2718, «край Ф7: шесть глаголов AccessKeyService на внешнем крае»)
// назвал все шесть глаголов ключа доступа (kacho#1273) — шесть записей сняты
// тем же изменением, перечень пуст (перепись до снятия: у края 349 · у нас 348 ·
// ожидающих 6 · применено 0). Наша копия несла их в ФОРМЕ КРАЯ, поэтому в их
// части копии совпадают побайтово и пересинхронизация не нужна.
//
// Пустой перечень — цель, а не отказ: сверка на нём проходит с переписью
// «ожидающих края объявлено 0» (TestDeclaredPendingEntriesCarryASubject
// проходит на пустом), а способность записи истечь
// доказывается синтетикой (TestDeclaredPendingEntryExpiresOnItsOwn), не живой
// записью.
//
// Перечень снова непуст с 2026-10-04: три глагола контракта
// `InternalNotificationGrantService` (полоса K3c, перепись на заведении: у края
// 348 · у нас 351 · ожидающих 3 · применено 3; ствол платформы f4c74ba1aa1).
// Тем же днём к ним прибавились два глагола контракта
// `InternalNotificationRecipientService` (полоса X4D NTF-3, перепись на
// заведении: у края 348 · у нас 353 · ожидающих 5 · применено 5; ствол
// платформы 2afc06571c7); второй из них, `ListProjectAudience`, снят полосой K3
// (редакция 35 приёмки, §4) и заменён `ListEventAudience` — край его не называл,
// поэтому замена — перепись ожидающих, а не окно снятого (у края 348 · у нас 355 ·
// ожидающих 7, без изменения числа). Тем же эпиком прибавился глагол токена версии прав
// `InternalIAMService/CurrentAuthzRevision` (полоса K1 NTF-3, перепись на
// заведении: у края 348 · у нас 354 · ожидающих 6 · применено 6; ствол
// платформы ffbe930dbef). Тем же эпиком прибавился глагол публикации для
// анонимного чтения `InternalIAMService/SetPublicReadPublication` (полоса K2
// NTF-3, перепись на заведении: у края 348 · у нас 355 · ожидающих 7 · применено 7;
// ствол платформы ffbe930dbef).
var catalogPendingEntries = []CatalogPendingEntry{
	// ПУБЛИКАЦИЯ ДЛЯ АНОНИМНОГО ЧТЕНИЯ (NTF-3 Р30 «Публикация для анонимного чтения»,
	// kaname#484, полоса K2).
	{
		OwnFQN: "kaname.cloud.iam.v1.InternalIAMService/SetPublicReadPublication",
		Why: "глагол публикации для анонимного чтения заведён контрактом службы (kaname#484, NTF-3 Р30: " +
			"внутренний слушатель, освобождение `INTERNAL_LISTENER` — круг модуля-владельца типа, допускающего " +
			"публикацию, судит обработчик дверью `RegisterResource` и владением типом объекта); " +
			"запись порождена генератором края над контрактом этой ревизии (`gateway/scripts/gen-permission-catalog.sh` " +
			"платформы над деревом ствола ffbe930dbef, где `kaname/` — контракт службы этой ревизии: полный прогон " +
			"без отбора — 355 записей, побайтово равен нашей копии; у края на стволе платформы ffbe930dbef записей " +
			"348, этой нет); край порождает свою копию по пину службы и увидит запись после подъёма пина",
		Removal: "копия края на стволе платформы несёт `kaname.cloud.iam.v1.InternalIAMService/SetPublicReadPublication` " +
			"— платформа подняла пин службы до ревизии с этим глаголом и перегенерировала каталог; " +
			"тогда запись снимается тем же изменением (подъём пина службы эпиком kacho#2918)",
		Refs: "PRO-Robotech/kaname#484, PRO-Robotech/kacho#2918",
	},
	// ТОКЕН ВЕРСИИ ПРАВ (NTF-3 Р30 «Производитель токена», kaname#484, полоса K1).
	{
		OwnFQN: "kaname.cloud.iam.v1.InternalIAMService/CurrentAuthzRevision",
		Why: "глагол токена версии прав `R_E` заведён контрактом службы (kaname#484, NTF-3 Р30: " +
			"внутренний слушатель, освобождение `INTERNAL_LISTENER` — круг модулей-владельцев видов судит " +
			"обработчик той же дверью, что у `RegisterResource`); " +
			"запись порождена генератором края над контрактом этой ревизии (`gateway/scripts/gen-permission-catalog.sh` " +
			"платформы над деревом ствола ffbe930dbef, где `kaname/` — контракт службы этой ревизии: полный прогон " +
			"без отбора — 354 записи, побайтово равен нашей копии; у края на стволе платформы ffbe930dbef записей " +
			"348, этой нет); край порождает свою копию по пину службы и увидит запись после подъёма пина",
		Removal: "копия края на стволе платформы несёт `kaname.cloud.iam.v1.InternalIAMService/CurrentAuthzRevision` " +
			"— платформа подняла пин службы до ревизии с этим глаголом и перегенерировала каталог; " +
			"тогда запись снимается тем же изменением (подъём пина службы эпиком kacho#2918)",
		Refs: "PRO-Robotech/kaname#484, PRO-Robotech/kacho#2918",
	},
	// ТРИ ГЛАГОЛА ВЫДАЧИ ПРАВА НА ПИСЬМА (NTF-1, kaname#484; замысел kacho#2915 З13, З18,
	// CX1-104). Контракт `InternalNotificationGrantService` заведён полосой K3c;
	// обработчиков в ней нет — сервер регистрирует K3. Окно закрывает K3r: посадка
	// эпика в ствол платформы с подъёмом пина службы.
	{
		OwnFQN: "kaname.cloud.iam.v1.InternalNotificationGrantService/ResolveSend",
		Why: "глагол решения о письме строки ленты заведён контрактом службы (kaname#484, NTF-1 З18: " +
			"внутренний слушатель, освобождение `INTERNAL_LISTENER` — право решает обработчик вопросом " +
			"`reader` на `notification_feed`); " +
			"запись порождена генератором края над контрактом этой ревизии (`gateway/scripts/gen-permission-catalog.sh` " +
			"платформы с отбором домена iam над деревом, где `kaname/` — контракт службы этой ревизии: 121 имя " +
			"службы, все побайтово равны нашей копии; полный прогон без отбора — 351 запись, побайтово равен нашей " +
			"копии; у края на стволе платформы f4c74ba1aa1 записей 348, ни одной из трёх нет); край порождает свою " +
			"копию по пину службы и увидит запись после подъёма пина",
		Removal: "копия края на стволе платформы несёт `kaname.cloud.iam.v1.InternalNotificationGrantService/ResolveSend` " +
			"— платформа подняла пин службы до ревизии с этим глаголом и перегенерировала каталог; " +
			"тогда запись снимается тем же изменением (полоса K3r маршрута kacho#2915)",
		Refs: "PRO-Robotech/kaname#484, PRO-Robotech/kacho#2915",
	},
	{
		OwnFQN: "kaname.cloud.iam.v1.InternalNotificationGrantService/Restore",
		Why: "глагол снятия надгробия выдачи заведён тем же контрактом (NTF-1 З18: `system_admin` на " +
			"`cluster`, пол «2», образец `InternalClusterService/RevokeAdmin`); " +
			"запись порождена генератором края над контрактом этой ревизии (`gateway/scripts/gen-permission-catalog.sh` " +
			"платформы с отбором домена iam над деревом, где `kaname/` — контракт службы этой ревизии: 121 имя " +
			"службы, все побайтово равны нашей копии; полный прогон без отбора — 351 запись, побайтово равен нашей " +
			"копии; у края на стволе платформы f4c74ba1aa1 записей 348, ни одной из трёх нет); край порождает свою " +
			"копию по пину службы и увидит запись после подъёма пина",
		Removal: "копия края на стволе платформы несёт `kaname.cloud.iam.v1.InternalNotificationGrantService/Restore` " +
			"— платформа подняла пин службы до ревизии с этим глаголом и перегенерировала каталог; " +
			"тогда запись снимается тем же изменением (полоса K3r маршрута kacho#2915)",
		Refs: "PRO-Robotech/kaname#484, PRO-Robotech/kacho#2915",
	},
	{
		OwnFQN: "kaname.cloud.iam.v1.InternalNotificationGrantService/Revoke",
		Why: "глагол надгробия выдачи заведён тем же контрактом (NTF-1 З18: `system_admin` на " +
			"`cluster`, пол «2», образец `InternalClusterService/RevokeAdmin`); " +
			"запись порождена генератором края над контрактом этой ревизии (`gateway/scripts/gen-permission-catalog.sh` " +
			"платформы с отбором домена iam над деревом, где `kaname/` — контракт службы этой ревизии: 121 имя " +
			"службы, все побайтово равны нашей копии; полный прогон без отбора — 351 запись, побайтово равен нашей " +
			"копии; у края на стволе платформы f4c74ba1aa1 записей 348, ни одной из трёх нет); край порождает свою " +
			"копию по пину службы и увидит запись после подъёма пина",
		Removal: "копия края на стволе платформы несёт `kaname.cloud.iam.v1.InternalNotificationGrantService/Revoke` " +
			"— платформа подняла пин службы до ревизии с этим глаголом и перегенерировала каталог; " +
			"тогда запись снимается тем же изменением (полоса K3r маршрута kacho#2915)",
		Refs: "PRO-Robotech/kaname#484, PRO-Robotech/kacho#2915",
	},
	// ПЕРЕЧЕНЬ АУДИТОРИИ ВЕРСИИ СОБЫТИЯ (NTF-3 Р7, Р30, kaname#484, полоса K3). Запись заменила
	// `ListProjectAudience` того же контракта: снятый глагол край не называл ни разу (запись о нём
	// ждала края), поэтому снятие окна «снятого службой» не требует — исчезает и запись, и её предмет.
	{
		OwnFQN: "kaname.cloud.iam.v1.InternalNotificationRecipientService/ListEventAudience",
		Why: "глагол справочника адресов заведён контрактом службы (kaname#484, NTF-3 Р7, Р28, Р30: " +
			"внутренний слушатель, `reader` на `notification_recipient_directory`, вызывающий — `service:notify`); " +
			"запись порождена генератором края над контрактом этой ревизии (`gateway/scripts/gen-permission-catalog.sh` " +
			"платформы над деревом ствола ffbe930dbef, где `kaname/` — контракт службы этой ревизии: полный прогон " +
			"без отбора — 355 записей, побайтово равен нашей копии; у края на стволе платформы ffbe930dbef записей " +
			"348, этой нет); край порождает свою копию по пину службы и увидит запись после подъёма пина",
		Removal: "копия края на стволе платформы несёт `kaname.cloud.iam.v1.InternalNotificationRecipientService/ListEventAudience` " +
			"— платформа подняла пин службы до ревизии с этим глаголом и перегенерировала каталог; " +
			"тогда запись снимается тем же изменением (подъём пина службы эпиком kacho#2918)",
		Refs: "PRO-Robotech/kaname#484, PRO-Robotech/kacho#2918",
	},
	{
		OwnFQN: "kaname.cloud.iam.v1.InternalNotificationRecipientService/Resolve",
		Why: "глагол справочника адресов заведён контрактом службы (kaname#484, NTF-3 Р7, Р28: " +
			"внутренний слушатель, `reader` на `notification_recipient_directory`, вызывающий — `service:notify`); " +
			"запись порождена генератором края над контрактом этой ревизии (`gateway/scripts/gen-permission-catalog.sh` " +
			"платформы с отбором домена iam над деревом, где `kaname/` — контракт службы этой ревизии: 123 имени " +
			"службы, все побайтово равны нашей копии; полный прогон без отбора — 353 записи, побайтово равен нашей " +
			"копии; у края на стволе платформы 2afc06571c7 записей 348, ни одной из пяти нет); край порождает свою " +
			"копию по пину службы и увидит запись после подъёма пина",
		Removal: "копия края на стволе платформы несёт `kaname.cloud.iam.v1.InternalNotificationRecipientService/Resolve` " +
			"— платформа подняла пин службы до ревизии с этим глаголом и перегенерировала каталог; " +
			"тогда запись снимается тем же изменением (подъём пина службы эпиком kacho#2918)",
		Refs: "PRO-Robotech/kaname#484, PRO-Robotech/kacho#2918",
	},
}

// CatalogPendingEntries — объявленный перечень (копия, см. CatalogFoundationRenames).
func CatalogPendingEntries() []CatalogPendingEntry {
	out := make([]CatalogPendingEntry, len(catalogPendingEntries))
	copy(out, catalogPendingEntries)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// ТРЕТИЙ ВИД ЗАПИСИ — ГЛАГОЛ, СНЯТЫЙ СЛУЖБОЙ, КОТОРЫЙ КРАЙ ЕЩЁ НАЗЫВАЕТ (kaname#564)
//
// Зеркало второго вида с обратным знаком: служба СНЯЛА свой глагол вместе с его
// записью, а копия края порождается из контракта службы ПО ПИНУ — то есть
// перестанет его называть только после посадки снятия в ствол службы и подъёма
// пина платформой. Промежуточного состояния, в котором обе копии совпали бы, не
// существует by construction — ровно как у записи, ждущей края.
//
// Запись объявляет: у края эта запись ЕСТЬ, у нас её УЖЕ НЕТ, и это не
// расхождение. Держит себя в обе стороны: край перестал называть глагол —
// предикат снятия наступил, запись обязана уйти; в нашей копии глагол всё ещё
// есть — запись утверждает о дереве неправду.
//
// Что при этом НЕ ослаблено: из сравнения выносится ровно названная запись края
// и только пока её нет у нас. Расхождение содержимым любой другой записи, лишняя
// запись с любой стороны и форма файла судятся побайтово, как прежде.

// CatalogRetiredEntry — запись копии края, чей глагол служба уже сняла, а край
// ещё называет, потому что порождает её из нашего контракта по пину.
type CatalogRetiredEntry struct {
	// EdgeFQN — полное имя снятого метода в копии края.
	EdgeFQN string
	// Why — почему присутствие у края не дефект.
	Why string
	// Removal — ПРЕДИКАТ СНЯТИЯ, внешний по отношению к этому дереву.
	Removal string
	// Refs — где предмет ведётся.
	Refs string
}

// catalogRetiredEntries — ЗАКРЫТЫЙ перечень снятых службой глаголов, которые
// край ещё называет. Условия те же три, что у прочих окон. Самоистечение держит
// `CompareCatalogCopies`: запись, чей глагол край больше не называет, — находка.
//
// Самоистечение сработало 2026-10-03: ствол платформы `e801c0f78` больше не
// называет `InternalUserService/OnRecoveryCompleted` (kaname#564) — платформа
// подняла пин службы до `0dd03218` (kacho#3000, `7032505b37e`) и
// перегенерировала каталог; запись снята тем же
// изменением, перечень пуст (перепись до снятия: у края 348 · у нас 348 ·
// снятых службой объявлено 1 · применено 0 · побайтово до ведомости true).
// Копии теперь совпадают побайтово целиком, ни одного окна не объявлено.
//
// Пустой перечень — цель, а не отказ: сверка на нём проходит с переписью
// «снятых службой объявлено 0», а способность записи истечь доказывается
// синтетикой (TestDeclaredRetiredEntryExpiresOnItsOwn), не живой записью.
var catalogRetiredEntries = []CatalogRetiredEntry{}

// CatalogRetiredEntries — объявленный перечень (копия, см. CatalogFoundationRenames).
func CatalogRetiredEntries() []CatalogRetiredEntry {
	out := make([]CatalogRetiredEntry, len(catalogRetiredEntries))
	copy(out, catalogRetiredEntries)
	return out
}

// Виды находок. Разделены потому, что у них РАЗНЫЙ адресат: ведомость правят
// здесь, а расхождение копий ведёт либо к синхронизации, либо к платформе.
// Общий заголовок «копии разошлись» на находке ведомости лгал бы: при
// наступившем предикате снятия копии как раз СОВПАДАЮТ.
const (
	// CatalogFindingLedger — находка в ведомости послаблений.
	CatalogFindingLedger = "ведомость"
	// CatalogFindingCopies — находка в самих копиях.
	CatalogFindingCopies = "копии"
)

// CatalogParityFinding — одна находка: вид и текст.
type CatalogParityFinding struct {
	Kind string
	Text string
}

// CatalogParityCensus — объём осмотренного. «Ноль находок» обязано быть отличимо
// от «ноль прочитанного», а «ноль расхождений» — от «распознаватель ослеп».
type CatalogParityCensus struct {
	// EdgeEntries, OwnEntries — записей у каждой стороны.
	EdgeEntries int
	OwnEntries  int
	// RenamesDeclared — записей в ведомости.
	RenamesDeclared int
	// RenamesApplied — сколько из них ДЕЙСТВИТЕЛЬНО применились к копии края.
	RenamesApplied int
	// PendingDeclared — записей, ждущих края, в ведомости.
	PendingDeclared int
	// PendingApplied — сколько из них ДЕЙСТВИТЕЛЬНО вынесены из сравнения:
	// глагол есть у нас и его ещё нет у края.
	PendingApplied int
	// RetiredDeclared — записей о снятых службой глаголах в ведомости.
	RetiredDeclared int
	// RetiredApplied — сколько из них ДЕЙСТВИТЕЛЬНО вынесены из сравнения:
	// глагол есть у края и его уже нет у нас.
	RetiredApplied int
	// BytesEqual — совпали ли копии побайтово ДО применения ведомости.
	BytesEqual bool
}

// String — перепись одной строкой, пригодной для журнала конвейера.
func (c CatalogParityCensus) String() string {
	return fmt.Sprintf(
		"перепись: записей у края %d · записей у нас %d · переименований объявлено %d · применено %d · "+
			"ожидающих края объявлено %d · применено %d · снятых службой объявлено %d · применено %d · "+
			"побайтово до ведомости %v",
		c.EdgeEntries, c.OwnEntries, c.RenamesDeclared, c.RenamesApplied,
		c.PendingDeclared, c.PendingApplied, c.RetiredDeclared, c.RetiredApplied, c.BytesEqual)
}

// CompareCatalogCopies — сверка против ДЕЙСТВУЮЩЕЙ ведомости дерева. Возвращает
// перечень находок (пустой = зелёное) и перепись. Ошибка — это ТРЕТИЙ ИСХОД:
// разобрать не удалось, вердикта о совпадении копий НЕТ (не путать с находкой).
func CompareCatalogCopies(edgeRaw, ownRaw string) ([]CatalogParityFinding, CatalogParityCensus, error) {
	return compareCatalogCopiesWithLedgers(catalogFoundationRenames, catalogPendingEntries, catalogRetiredEntries,
		edgeRaw, ownRaw)
}

// compareCatalogCopiesWith — та же сверка с ЯВНЫМИ ведомостями.
//
// Отдельная форма нужна ПРОБАМ: инъекция обязана вносить дефект в ведомость и
// в копии, а не подменять пакетную переменную из-под соседних проб. Прод-вход
// остаётся один и ведомости берёт только свои — подменить их вызовом нельзя.
func compareCatalogCopiesWith(
	renames []CatalogFoundationRename, pending []CatalogPendingEntry, edgeRaw, ownRaw string,
) ([]CatalogParityFinding, CatalogParityCensus, error) {
	return compareCatalogCopiesWithLedgers(renames, pending, nil, edgeRaw, ownRaw)
}

// compareCatalogCopiesWithLedgers — та же сверка со всеми тремя ЯВНЫМИ
// ведомостями (форма для проб третьего вида записи).
func compareCatalogCopiesWithLedgers(
	renames []CatalogFoundationRename, pending []CatalogPendingEntry, retired []CatalogRetiredEntry,
	edgeRaw, ownRaw string,
) ([]CatalogParityFinding, CatalogParityCensus, error) {
	census := CatalogParityCensus{
		RenamesDeclared: len(renames),
		PendingDeclared: len(pending),
		RetiredDeclared: len(retired),
		BytesEqual:      edgeRaw == ownRaw,
	}

	edgeBlocks, err := splitCatalogBlocks(edgeRaw)
	if err != nil {
		return nil, census, fmt.Errorf("копия края: %w", err)
	}
	ownBlocks, err := splitCatalogBlocks(ownRaw)
	if err != nil {
		return nil, census, fmt.Errorf("своя копия: %w", err)
	}
	census.EdgeEntries = len(edgeBlocks)
	census.OwnEntries = len(ownBlocks)

	var findings []CatalogParityFinding

	// ── ВЕДОМОСТЬ ДЕРЖИТ СЕБЯ В ОБЕ СТОРОНЫ ──────────────────────────────────
	//
	// Сторона края отсутствует → исключать больше нечего: край догнал (либо
	// глагол снят), запись обязана уйти вместе со своим предметом.
	// Сторона своя отсутствует → ведомость утверждает о НАШЕМ дереве неправду.
	edgeByFQN := blocksByFQN(edgeBlocks)
	ownByFQN := blocksByFQN(ownBlocks)
	renamed := make(map[string]string, len(renames))
	for _, r := range renames {
		if _, ok := edgeByFQN[r.EdgeFQN]; !ok {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"нечего исключать: у края больше нет глагола %q — снимите запись, предикат снятия наступил. %s",
				r.EdgeFQN, r.Refs)})
			continue
		}
		if _, ok := ownByFQN[r.OwnFQN]; !ok {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"запись называет наш глагол %q, которого в нашей копии НЕТ — она утверждает о дереве неправду. %s",
				r.OwnFQN, r.Refs)})
			continue
		}
		renamed[r.EdgeFQN] = r.OwnFQN
		census.RenamesApplied++
	}

	// ── ЗАПИСИ, ЖДУЩИЕ КРАЯ, ДЕРЖАТ СЕБЯ В ОБЕ СТОРОНЫ ────────────────────────
	//
	// Край уже назвал глагол → предикат снятия наступил: запись обязана уйти, а
	// копия — синхронизироваться. В нашей копии глагола нет → ведомость
	// утверждает о НАШЕМ дереве неправду. Только при предмете с обеих сторон
	// запись выносится из сравнения — и ровно она одна.
	awaited := make(map[string]bool, len(pending))
	for _, e := range pending {
		if _, ok := edgeByFQN[e.OwnFQN]; ok {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"край уже несёт глагол %q — предикат снятия наступил: снимите запись и синхронизируйте копию. %s",
				e.OwnFQN, e.Refs)})
			continue
		}
		if _, ok := ownByFQN[e.OwnFQN]; !ok {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"запись ждёт края для глагола %q, которого в НАШЕЙ копии нет — она утверждает о дереве неправду. %s",
				e.OwnFQN, e.Refs)})
			continue
		}
		awaited[e.OwnFQN] = true
		census.PendingApplied++
	}
	// ── ЗАПИСИ О СНЯТЫХ СЛУЖБОЙ ГЛАГОЛАХ ДЕРЖАТ СЕБЯ В ОБЕ СТОРОНЫ ────────────
	//
	// Край больше не называет глагол → предикат снятия наступил: запись обязана
	// уйти. У нас глагол всё ещё есть → ведомость утверждает о НАШЕМ дереве
	// неправду. Только при предмете с обеих сторон запись края выносится из
	// сравнения — и ровно она одна.
	retiredAway := make(map[string]bool, len(retired))
	for _, e := range retired {
		if _, ok := edgeByFQN[e.EdgeFQN]; !ok {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"край больше не несёт снятый глагол %q — предикат снятия наступил: снимите запись. %s",
				e.EdgeFQN, e.Refs)})
			continue
		}
		if _, ok := ownByFQN[e.EdgeFQN]; ok {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"запись объявляет глагол %q снятым, а в НАШЕЙ копии он есть — она утверждает о дереве неправду. %s",
				e.EdgeFQN, e.Refs)})
			continue
		}
		retiredAway[e.EdgeFQN] = true
		census.RetiredApplied++
	}

	ownCompared := ownBlocks
	if len(awaited) > 0 {
		ownCompared = make([]catalogBlock, 0, len(ownBlocks))
		for _, b := range ownBlocks {
			if !awaited[b.fqn] {
				ownCompared = append(ownCompared, b)
			}
		}
	}

	// ── ПРИМЕНЕНИЕ ВЕДОМОСТИ К КОПИИ КРАЯ ────────────────────────────────────
	//
	// Переименование двигает запись в перечне: он отсортирован по `fqn`. Значит
	// после подстановки блоки пересортировываются, и только тогда сравниваются.
	projected := make([]catalogBlock, 0, len(edgeBlocks))
	for _, b := range edgeBlocks {
		if retiredAway[b.fqn] {
			continue
		}
		if own, ok := renamed[b.fqn]; ok {
			body := strings.Replace(b.body, catalogFQNField(b.fqn), catalogFQNField(own), 1)
			if body == b.body {
				return nil, census, fmt.Errorf(
					"поле `fqn` записи %q не найдено дословно — форма записи не та, что разбирает эта сверка", b.fqn)
			}
			b = catalogBlock{fqn: own, body: body}
		}
		projected = append(projected, b)
	}
	sort.Slice(projected, func(i, j int) bool { return projected[i].fqn < projected[j].fqn })

	if assembleCatalog(projected) == assembleCatalog(ownCompared) {
		return findings, census, nil
	}

	// ── ОСТАТОК — НАХОДКА, И ОН НАЗЫВАЕТСЯ ПОИМЁННО ──────────────────────────
	findings = append(findings, catalogResidualFindings(projected, ownCompared)...)
	if len(findings) == 0 {
		// Состав и содержимое записей сошлись, а файл — нет: разошлась ФОРМА
		// файла (порядок, отступ, перевод строки). Молчать об этом нельзя:
		// побайтовость и есть предмет сверки.
		findings = append(findings, CatalogParityFinding{CatalogFindingCopies,
			"состав и содержимое записей сходятся, а файлы — нет: " +
				"разошлась ФОРМА файла (порядок записей, отступ либо перевод строки)"})
	}
	return findings, census, nil
}

// catalogFQNField — поле `fqn` записи в том виде, в каком его пишет генератор.
func catalogFQNField(fqn string) string {
	return `"fqn": ` + mustJSONString(fqn)
}

func mustJSONString(s string) string {
	b, err := json.Marshal(s)
	if err != nil { // недостижимо для строки
		panic(err)
	}
	return string(b)
}

// catalogResidualFindings — что именно осталось разошедшимся после ведомости.
func catalogResidualFindings(projected, own []catalogBlock) []CatalogParityFinding {
	projByFQN := blocksByFQN(projected)
	ownByFQN := blocksByFQN(own)

	var findings []CatalogParityFinding
	for _, b := range projected {
		o, ok := ownByFQN[b.fqn]
		if !ok {
			findings = append(findings, CatalogParityFinding{CatalogFindingCopies,
				fmt.Sprintf("есть у края, нет у нас: %s", b.fqn)})
			continue
		}
		if o.body != b.body {
			findings = append(findings, CatalogParityFinding{CatalogFindingCopies,
				fmt.Sprintf("запись расходится содержимым: %s", b.fqn)})
		}
	}
	for _, b := range own {
		if _, ok := projByFQN[b.fqn]; !ok {
			findings = append(findings, CatalogParityFinding{CatalogFindingCopies,
				fmt.Sprintf("есть у нас, нет у края: %s", b.fqn)})
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].Text < findings[j].Text })
	return findings
}

// catalogBlock — одна запись каталога ДОСЛОВНЫМИ байтами плюс её `fqn`.
type catalogBlock struct {
	fqn  string
	body string
}

func blocksByFQN(blocks []catalogBlock) map[string]catalogBlock {
	m := make(map[string]catalogBlock, len(blocks))
	for _, b := range blocks {
		m[b.fqn] = b
	}
	return m
}

const (
	catalogPrefix    = "[\n"
	catalogSuffix    = "\n]\n"
	catalogSeparator = ",\n"
)

// splitCatalogBlocks — режет файл на записи ДОСЛОВНО и проверяет СВОЮ ЖЕ
// предпосылку: сборка блоков обязана воспроизвести исходный текст побайтово.
// Не воспроизвела — форма файла не та, что разбирает эта сверка, и это ТРЕТИЙ
// ИСХОД, а не находка: о совпадении копий мы не узнали ничего.
func splitCatalogBlocks(raw string) ([]catalogBlock, error) {
	if !strings.HasPrefix(raw, catalogPrefix) || !strings.HasSuffix(raw, catalogSuffix) {
		return nil, fmt.Errorf("форма файла не та: ожидались %q в начале и %q в конце",
			catalogPrefix, catalogSuffix)
	}
	body := raw[len(catalogPrefix) : len(raw)-len(catalogSuffix)]
	if strings.TrimSpace(body) == "" {
		return nil, fmt.Errorf("перечень пуст — сверять нечего")
	}

	parts := strings.Split(body, "\n  },\n")
	blocks := make([]catalogBlock, 0, len(parts))
	for i, p := range parts {
		if i < len(parts)-1 {
			p += "\n  }"
		}
		fqn, err := catalogBlockFQN(p)
		if err != nil {
			return nil, err
		}
		blocks = append(blocks, catalogBlock{fqn: fqn, body: p})
	}
	if got := assembleCatalog(blocks); got != raw {
		return nil, fmt.Errorf("разбор не воспроизводит файл побайтово (%d байт против %d) — форма файла сменилась",
			len(got), len(raw))
	}
	return blocks, nil
}

// assembleCatalog — сборка обратно. Обратна `splitCatalogBlocks` by construction.
func assembleCatalog(blocks []catalogBlock) string {
	bodies := make([]string, 0, len(blocks))
	for _, b := range blocks {
		bodies = append(bodies, b.body)
	}
	return catalogPrefix + strings.Join(bodies, catalogSeparator) + catalogSuffix
}

// catalogBlockFQN — `fqn` записи, прочитанный РАЗБОРОМ, а не поиском подстроки:
// имя метода встречается и в значении `permission`, и сверка по образцу взяла
// бы не то поле.
func catalogBlockFQN(block string) (string, error) {
	var entry struct {
		FQN string `json:"fqn"`
	}
	if err := json.Unmarshal([]byte(block), &entry); err != nil {
		return "", fmt.Errorf("запись не разбирается как JSON: %w", err)
	}
	if entry.FQN == "" {
		return "", fmt.Errorf("у записи пустое поле `fqn` — сверять её не по чему")
	}
	return entry.FQN, nil
}

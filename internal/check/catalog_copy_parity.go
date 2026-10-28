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
// то, что у равенства появились ПЯТЬ закрытых перечней объявленных окон —
// переименования фундамента, записи службы, ждущие края (kaname#181),
// глаголы, снятые службой, которые край ещё называет (kaname#564), записи,
// у которых служба сменила значение одного поля (kaname#720), и записи,
// которые служба переаннотировала целиком (kaname#986), — и каждая
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
// Предикат снятия наступил на стволе платформы `bdaedfd5aa` (kacho#2659): её `go.mod` пинит
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
// Перечень снова непуст с 2026-10-08: четыре глагола публичного близнеца
// `ClusterService` (kaname#661) ждали края — его стадия S2 (kacho#3093) поднимала
// пин службы и регенерировала каталог. Пятая запись — `UserService/ResetAccessKeys`
// (kaname#638, kacho#2702) — ждала того же подъёма пина.
//
// Самоистечение сработало в четвёртый раз 2026-10-14: ствол платформы
// `dd9739fe6d` (посадка эпика kacho#1266) назвал все пять глаголов — пять
// записей сняты тем же изменением, перечень пуст (kaname#819; перепись до
// снятия: у края 359 · у нас 353 · ожидающих 5 · применено 0). Тем же
// изменением наша копия синхронизирована с копией края: край завёл шесть
// глаголов `kacho.cloud.geo.v1` (Region/Zone Create/Update/Delete, kacho#3092),
// которых у нас не было.
//
// Перечень снова непуст с 2026-10-26: четыре глагола службы делегированных
// выдач `GrantDelegationService` (kaname#986) заведены контрактом службы, а
// копия края на стволе платформы `41d7edad9b` их ещё не называет (перепись
// против этого ствола: «есть у нас, нет у края» — ровно эти четыре). Наша копия
// несёт их в форме генератора края: обход `catalog_covers_contract.go` сверяет
// каждую строку с аннотациями метода по каждой оси каталога. До подъёма пина
// край отвечает на эти глаголы отказом «нет записи каталога» — окно закрыто, а
// не открыто (fail-closed).
var catalogPendingEntries = []CatalogPendingEntry{
	{
		OwnFQN:  "kaname.cloud.iam.v1.GrantDelegationService/Create",
		Why:     grantDelegationPendingWhy,
		Removal: grantDelegationPendingRemoval,
		Refs:    "PRO-Robotech/kaname#986",
	},
	{
		OwnFQN:  "kaname.cloud.iam.v1.GrantDelegationService/Get",
		Why:     grantDelegationPendingWhy,
		Removal: grantDelegationPendingRemoval,
		Refs:    "PRO-Robotech/kaname#986",
	},
	{
		OwnFQN:  "kaname.cloud.iam.v1.GrantDelegationService/List",
		Why:     grantDelegationPendingWhy,
		Removal: grantDelegationPendingRemoval,
		Refs:    "PRO-Robotech/kaname#986",
	},
	{
		OwnFQN:  "kaname.cloud.iam.v1.GrantDelegationService/Revoke",
		Why:     grantDelegationPendingWhy,
		Removal: grantDelegationPendingRemoval,
		Refs:    "PRO-Robotech/kaname#986",
	},
}

const (
	// grantDelegationPendingWhy — общая причина четырёх записей одного предмета.
	grantDelegationPendingWhy = "глагол службы делегированных выдач заведён контрактом службы (kaname#986); " +
		"край порождает свою копию из контракта службы по пину и назовёт глагол после подъёма пина " +
		"(перепись против ствола платформы 41d7edad9b: «есть у нас, нет у края» — ровно четыре глагола " +
		"GrantDelegationService); до того край отвечает на глагол отказом «нет записи каталога»"
	// grantDelegationPendingRemoval — внешний предикат снятия тех же четырёх записей.
	grantDelegationPendingRemoval = "копия края на стволе платформы несёт глагол — платформа подняла пин " +
		"службы до ревизии с GrantDelegationService и перегенерировала каталог; тогда запись снимается"
)

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
// Копии тогда совпали побайтово целиком, ни одного окна не было объявлено.
//
// Пустой перечень — цель, а не отказ: сверка на нём проходит с переписью
// «снятых службой объявлено 0», а способность записи истечь доказывается
// синтетикой (TestDeclaredRetiredEntryExpiresOnItsOwn), не живой записью.
//
// Запись kaname#929 заведена тем же изменением, что сняло глагол: копия края на
// стволе платформы `41d7edad9b` называет его, наша — нет, и расходится ровно
// эта запись.
var catalogRetiredEntries = []CatalogRetiredEntry{
	{
		EdgeFQN: "kaname.cloud.iam.v1.InternalUserService/UpsertFromIdentity",
		Why: "глагол заведения личности по внешнему удостоверению снят с контракта службы вместе с " +
			"записью каталога по приёмке AWI-09 (kaname#929): его обратный вызов из края снят " +
			"платформой, вызывающего нет ни в дереве службы, ни в дереве платформы, а сам глагол " +
			"производил личность ACTIVE без способа входа; край порождает свою копию по пину службы " +
			"и перестанет называть глагол после подъёма пина (перепись против ствола платформы " +
			"41d7edad9b: расходится ровно эта запись — «есть у края, нет у нас»)",
		Removal: "копия края на стволе платформы НЕ несёт `kaname.cloud.iam.v1.InternalUserService/UpsertFromIdentity` " +
			"— платформа подняла пин службы до ревизии со снятым глаголом и перегенерировала каталог; " +
			"тогда запись снимается",
		Refs: "PRO-Robotech/kaname#929",
	},
}

// CatalogRetiredEntries — объявленный перечень (копия, см. CatalogFoundationRenames).
func CatalogRetiredEntries() []CatalogRetiredEntry {
	out := make([]CatalogRetiredEntry, len(catalogRetiredEntries))
	copy(out, catalogRetiredEntries)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// ЧЕТВЁРТЫЙ ВИД ЗАПИСИ — СМЕНА ЗНАЧЕНИЯ ОДНОГО ПОЛЯ, КОТОРУЮ КРАЙ ЕЩЁ НЕ ВИДЕЛ (kaname#720)
//
// Тот же класс окна, что у записи, ждущей края, но глагол у края УЖЕ есть: служба
// сменила в своём контракте аннотацию, из которой порождается одно поле записи,
// а край порождает запись по пину и несёт прежнее значение до подъёма пина.
//
// Запись объявляет ровно ОДНУ подстановку: у края в записи `FQN` поле `Field`
// равно `EdgeValue`, у нас — `OwnValue`. Сверка применяет подстановку к блоку
// края и сравнивает остаток ПОБАЙТОВО, как прежде: всякое иное расхождение той
// же записи остаётся находкой. Держит себя во все стороны: край несёт новое
// значение либо глагола у края нет — предикат снятия наступил; у края нет
// прежнего значения, у нас нет нового либо самой записи — ведомость утверждает
// о дереве неправду.

// CatalogRevisedEntry — объявленная смена значения одного поля записи, которую
// край ещё не породил.
type CatalogRevisedEntry struct {
	// FQN — полное имя метода; у обеих копий одно.
	FQN string
	// Field — имя поля записи в форме генератора.
	Field string
	// EdgeValue — значение поля в копии края (прежнее).
	EdgeValue string
	// OwnValue — значение поля в нашей копии (новое, порождённое из контракта).
	OwnValue string
	// Why — почему расхождение не дефект.
	Why string
	// Removal — ПРЕДИКАТ СНЯТИЯ, внешний по отношению к этому дереву.
	Removal string
	// Refs — где предмет ведётся.
	Refs string
}

// catalogRevisedEntries — ЗАКРЫТЫЙ перечень смен значения, ждущих края.
//
// Записи заведены 2026-10-12 (kaname#720, приёмка
// `own-account-and-identity-are-removed-in-order.md` ред. 4, Р12): контракт
// службы поднял порог уровня сессии у необратимого снятия личности и
// сервисного аккаунта. Наша копия порождена генератором края над деревом, где
// `kaname/` — контракт службы этой ревизии: выход отличается от прежней копии
// ровно значением этого поля в двух записях. Край увидит смену после подъёма
// пина службы и перегенерации каталога; тогда сверка объявит записи находкой
// сама, и они снимаются отдельным изменением службы.
//
// Ещё три записи заведены 2026-10-12 (kaname#747, приёмка
// `level-two-is-enrolled-at-level-two.md`, Р3): пол уровня у обоих глаголов
// регистрации ключа доступа и у его снятия поднят контрактом службы до «2».
//
// Самоистечение сработало 2026-10-14: ствол платформы `dd9739fe6d` (посадка
// эпика kacho#1266) несёт у всех пяти записей значение «2» — записи сняты тем
// же изменением, перечень пуст (kaname#819; перепись до снятия: смен значения
// объявлено 5 · применено 0). Пустой перечень — цель, а не отказ:
// TestDeclaredRevisedEntriesCarryASubject проходит на пустом, а способность
// записи истечь доказывается синтетикой (TestDeclaredRevisedEntryExpiresOnItsOwn).
//
// Запись заведена 2026-10-26 (kaname#1003, приёмка
// `service-account-creation-is-its-own-right.md`, Р1, §7): контракт службы сменил
// отношение `ServiceAccountService/Create` с `editor` на `service_account_creator`
// (`[service_account] or editor` — шире прежнего). До подъёма пина край требует
// `editor`, то есть строже службы: отказ создателю через край уже, а не шире
// (fail-closed, §7 приёмки), и svc-registry ходит к службе напрямую.
var catalogRevisedEntries = []CatalogRevisedEntry{
	{
		FQN:       "kaname.cloud.iam.v1.ServiceAccountService/Create",
		Field:     "required_relation",
		EdgeValue: "editor",
		OwnValue:  "service_account_creator",
		Why: "контракт службы сменил отношение создания учётки на отдельное право " +
			"service_account_creator (kaname#1003, Р1): оно выводится и из editor, поэтому прежние " +
			"создатели права не теряют; край порождает свою копию по пину службы и несёт прежнее " +
			"значение до подъёма пина — строже службы, а не мягче (§7 приёмки)",
		Removal: "копия края на стволе платформы несёт у ServiceAccountService/Create " +
			"required_relation service_account_creator — платформа подняла пин службы до ревизии " +
			"kaname#1003 и перегенерировала каталог; тогда запись снимается",
		Refs: "PRO-Robotech/kaname#1003",
	},
}

// CatalogRevisedEntries — объявленный перечень (копия, см. CatalogFoundationRenames).
func CatalogRevisedEntries() []CatalogRevisedEntry {
	out := make([]CatalogRevisedEntry, len(catalogRevisedEntries))
	copy(out, catalogRevisedEntries)
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// ПЯТЫЙ ВИД ЗАПИСИ — ЗАПИСЬ, КОТОРУЮ СЛУЖБА ПЕРЕАННОТИРОВАЛА ЦЕЛИКОМ (kaname#986)
//
// Тот же класс окна, что у смены значения одного поля, но служба сменила ВИД
// аннотации глагола: охраняемый глагол (право, отношение, область) стал
// решаемым обработчиком (`<exempt>` с причиной). Порождённая запись расходится
// не одним полем — сменились значения четырёх полей и появилось поле
// `exempt_reason`, которого прежняя форма не несла вовсе. Четвёртый вид
// объясняет ровно одну подстановку значения и такого расхождения не покрывает
// by construction: появление поля подстановкой значения не выражается.
//
// Запись объявляет ОБЕ стороны дословно: у края запись `FQN` побайтово равна
// `EdgeBody`, у нас — `OwnBody`. Только при обеих совпавших сторонах блок края
// заменяется нашим, и ровно он один; всё прочее судится побайтово, как прежде.
// Держит себя во все стороны: край несёт новую запись либо глагола у края нет —
// предикат снятия наступил; у края запись иная, чем объявленная прежней, у нас
// иная, чем объявленная новой, либо нашей записи нет — ведомость утверждает о
// дереве неправду. Послабления сверх объявленного нет: обе стороны пришпилены
// побайтово, и любая иная правка любой из них — находка.

// CatalogReannotatedEntry — объявленная смена вида аннотации записи, которую
// край ещё не породил.
type CatalogReannotatedEntry struct {
	// FQN — полное имя метода; у обеих копий одно.
	FQN string
	// EdgeBody — запись в копии края (прежняя) дословно, в форме генератора.
	EdgeBody string
	// OwnBody — запись в нашей копии (новая, порождённая из контракта) дословно.
	OwnBody string
	// Why — почему расхождение не дефект.
	Why string
	// Removal — ПРЕДИКАТ СНЯТИЯ, внешний по отношению к этому дереву.
	Removal string
	// Refs — где предмет ведётся.
	Refs string
}

// catalogReannotatedEntries — ЗАКРЫТЫЙ перечень переаннотированных записей,
// ждущих края.
//
// Записи заведены 2026-10-26 (kaname#986, приёмка делегированных выдач, Р1а):
// контракт службы перевёл `AccessBindingService/Delete` и `/Revoke` из глаголов,
// охраняемых отношением `v_delete` на привязке, в глаголы, решаемые
// обработчиком (`HANDLER_DECIDES`): право снять выдачу теперь даёт и
// делегирование, а его край по одному отношению на объекте не выразит. Наша
// копия несёт обе записи в форме генератора края (обход
// `catalog_covers_contract.go` сверяет их с аннотациями метода по каждой оси),
// копия края на стволе платформы `41d7edad9b` — прежние (перепись против этого
// ствола: «запись расходится содержимым» — ровно эти две). До подъёма пина край
// требует у этих глаголов прежнего отношения — то есть строже службы, а не
// мягче: окно закрыто, а не открыто.
var catalogReannotatedEntries = []CatalogReannotatedEntry{
	{
		FQN: "kaname.cloud.iam.v1.AccessBindingService/Delete",
		EdgeBody: `  {
    "fqn": "kaname.cloud.iam.v1.AccessBindingService/Delete",
    "permission": "iam.access_bindings.delete",
    "required_relation": "v_delete",
    "scope_extractor": {
      "object_type": "iam_access_binding",
      "from_request_field": "access_binding_id"
    },
    "required_acr_min": "2"
  }`,
		OwnBody: `  {
    "fqn": "kaname.cloud.iam.v1.AccessBindingService/Delete",
    "permission": "\u003cexempt\u003e",
    "required_relation": "",
    "scope_extractor": {
      "object_type": "",
      "from_request_field": ""
    },
    "required_acr_min": "2",
    "exempt_reason": "HANDLER_DECIDES"
  }`,
		Why:     accessBindingReannotatedWhy,
		Removal: accessBindingReannotatedRemoval,
		Refs:    "PRO-Robotech/kaname#986",
	},
	{
		FQN: "kaname.cloud.iam.v1.AccessBindingService/Revoke",
		EdgeBody: `  {
    "fqn": "kaname.cloud.iam.v1.AccessBindingService/Revoke",
    "permission": "iam.access_bindings.revoke",
    "required_relation": "v_delete",
    "scope_extractor": {
      "object_type": "iam_access_binding",
      "from_request_field": "access_binding_id"
    },
    "required_acr_min": "2"
  }`,
		OwnBody: `  {
    "fqn": "kaname.cloud.iam.v1.AccessBindingService/Revoke",
    "permission": "\u003cexempt\u003e",
    "required_relation": "",
    "scope_extractor": {
      "object_type": "",
      "from_request_field": ""
    },
    "required_acr_min": "2",
    "exempt_reason": "HANDLER_DECIDES"
  }`,
		Why:     accessBindingReannotatedWhy,
		Removal: accessBindingReannotatedRemoval,
		Refs:    "PRO-Robotech/kaname#986",
	},
}

const (
	// accessBindingReannotatedWhy — общая причина двух записей одного предмета.
	accessBindingReannotatedWhy = "контракт службы перевёл глагол снятия выдачи из охраняемого отношением " +
		"v_delete на привязке в решаемый обработчиком (HANDLER_DECIDES, kaname#986, Р1а): право снять " +
		"выдачу даёт и делегирование; край порождает свою копию по пину службы и несёт прежнюю запись до " +
		"подъёма пина (перепись против ствола платформы 41d7edad9b: «запись расходится содержимым» — ровно " +
		"Delete и Revoke); до того край требует прежнего отношения — строже службы"
	// accessBindingReannotatedRemoval — внешний предикат снятия тех же двух записей.
	accessBindingReannotatedRemoval = "копия края на стволе платформы несёт у глагола новую запись " +
		"(permission <exempt>, exempt_reason HANDLER_DECIDES) — платформа подняла пин службы до ревизии " +
		"с переаннотацией и перегенерировала каталог; тогда запись снимается"
)

// CatalogReannotatedEntries — объявленный перечень (копия, см. CatalogFoundationRenames).
func CatalogReannotatedEntries() []CatalogReannotatedEntry {
	out := make([]CatalogReannotatedEntry, len(catalogReannotatedEntries))
	copy(out, catalogReannotatedEntries)
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
	// RevisedDeclared — записей о смене значения поля в ведомости.
	RevisedDeclared int
	// RevisedApplied — сколько из них ДЕЙСТВИТЕЛЬНО применены к копии края:
	// у края прежнее значение, у нас новое.
	RevisedApplied int
	// ReannotatedDeclared — записей о переаннотации целиком в ведомости.
	ReannotatedDeclared int
	// ReannotatedApplied — сколько из них ДЕЙСТВИТЕЛЬНО применены к копии края:
	// у края прежняя запись дословно, у нас новая дословно.
	ReannotatedApplied int
	// BytesEqual — совпали ли копии побайтово ДО применения ведомости.
	BytesEqual bool
}

// String — перепись одной строкой, пригодной для журнала конвейера.
func (c CatalogParityCensus) String() string {
	return fmt.Sprintf(
		"перепись: записей у края %d · записей у нас %d · переименований объявлено %d · применено %d · "+
			"ожидающих края объявлено %d · применено %d · снятых службой объявлено %d · применено %d · "+
			"смен значения объявлено %d · применено %d · переаннотированных объявлено %d · применено %d · "+
			"побайтово до ведомости %v",
		c.EdgeEntries, c.OwnEntries, c.RenamesDeclared, c.RenamesApplied,
		c.PendingDeclared, c.PendingApplied, c.RetiredDeclared, c.RetiredApplied,
		c.RevisedDeclared, c.RevisedApplied, c.ReannotatedDeclared, c.ReannotatedApplied, c.BytesEqual)
}

// CompareCatalogCopies — сверка против ДЕЙСТВУЮЩЕЙ ведомости дерева. Возвращает
// перечень находок (пустой = зелёное) и перепись. Ошибка — это ТРЕТИЙ ИСХОД:
// разобрать не удалось, вердикта о совпадении копий НЕТ (не путать с находкой).
func CompareCatalogCopies(edgeRaw, ownRaw string) ([]CatalogParityFinding, CatalogParityCensus, error) {
	return compareCatalogCopiesWithEveryLedger(catalogFoundationRenames, catalogPendingEntries, catalogRetiredEntries,
		catalogRevisedEntries, catalogReannotatedEntries, edgeRaw, ownRaw)
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

// compareCatalogCopiesWithLedgers — та же сверка с тремя ЯВНЫМИ ведомостями
// (форма для проб третьего вида записи).
func compareCatalogCopiesWithLedgers(
	renames []CatalogFoundationRename, pending []CatalogPendingEntry, retired []CatalogRetiredEntry,
	edgeRaw, ownRaw string,
) ([]CatalogParityFinding, CatalogParityCensus, error) {
	return compareCatalogCopiesWithAllLedgers(renames, pending, retired, nil, edgeRaw, ownRaw)
}

// compareCatalogCopiesWithAllLedgers — та же сверка с четырьмя ЯВНЫМИ
// ведомостями (форма для проб первых четырёх видов записи).
func compareCatalogCopiesWithAllLedgers(
	renames []CatalogFoundationRename, pending []CatalogPendingEntry, retired []CatalogRetiredEntry,
	revised []CatalogRevisedEntry, edgeRaw, ownRaw string,
) ([]CatalogParityFinding, CatalogParityCensus, error) {
	return compareCatalogCopiesWithEveryLedger(renames, pending, retired, revised, nil, edgeRaw, ownRaw)
}

// compareCatalogCopiesWithEveryLedger — та же сверка со всеми пятью ЯВНЫМИ
// ведомостями. Прод-вход (`CompareCatalogCopies`) зовёт её со своими.
func compareCatalogCopiesWithEveryLedger(
	renames []CatalogFoundationRename, pending []CatalogPendingEntry, retired []CatalogRetiredEntry,
	revised []CatalogRevisedEntry, reannotated []CatalogReannotatedEntry, edgeRaw, ownRaw string,
) ([]CatalogParityFinding, CatalogParityCensus, error) {
	census := CatalogParityCensus{
		RenamesDeclared:     len(renames),
		PendingDeclared:     len(pending),
		RetiredDeclared:     len(retired),
		RevisedDeclared:     len(revised),
		ReannotatedDeclared: len(reannotated),
		BytesEqual:          edgeRaw == ownRaw,
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

	// ── СМЕНЫ ЗНАЧЕНИЯ ПОЛЯ ДЕРЖАТ СЕБЯ ВО ВСЕ СТОРОНЫ ───────────────────────
	//
	// Подстановка применяется к блоку края только тогда, когда у края стоит
	// ровно одно прежнее значение, а у нас — ровно одно новое. Край уже несёт
	// новое либо глагола у края нет → предикат снятия наступил. Прочее —
	// ведомость утверждает о дереве неправду. Остаток сравнивается побайтово.
	revisedEdge := make(map[string]string, len(revised))
	for _, e := range revised {
		edgeLit := catalogFieldLiteral(e.Field, e.EdgeValue)
		ownLit := catalogFieldLiteral(e.Field, e.OwnValue)
		eb, ok := edgeByFQN[e.FQN]
		if !ok {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"у края нет глагола %q — смене значения нечего объяснять: снимите запись. %s", e.FQN, e.Refs)})
			continue
		}
		if strings.Contains(eb.body, ownLit) && !strings.Contains(eb.body, edgeLit) {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"край уже несёт у %q новое значение %s — предикат снятия наступил: снимите запись. %s",
				e.FQN, ownLit, e.Refs)})
			continue
		}
		if strings.Count(eb.body, edgeLit) != 1 {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"запись называет у края %q прежнее значение %s, которого там нет ровно одного — "+
					"она утверждает о дереве неправду. %s", e.FQN, edgeLit, e.Refs)})
			continue
		}
		ob, ok := ownByFQN[e.FQN]
		if !ok || strings.Count(ob.body, ownLit) != 1 {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"запись называет у НАС %q новое значение %s, которого в нашей копии нет — "+
					"она утверждает о дереве неправду. %s", e.FQN, ownLit, e.Refs)})
			continue
		}
		revisedEdge[e.FQN] = strings.Replace(eb.body, edgeLit, ownLit, 1)
		census.RevisedApplied++
	}

	// ── ПЕРЕАННОТИРОВАННЫЕ ЗАПИСИ ДЕРЖАТ СЕБЯ ВО ВСЕ СТОРОНЫ ──────────────────
	//
	// Блок края заменяется нашим только тогда, когда у края стоит дословно
	// объявленная прежняя запись, а у нас — дословно объявленная новая. Край
	// уже несёт новую либо глагола у края нет → предикат снятия наступил.
	// Прочее — ведомость утверждает о дереве неправду. Остаток — побайтово.
	for _, e := range reannotated {
		if _, dup := revisedEdge[e.FQN]; dup {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"глагол %q объявлен вторым окном (сменой значения поля либо повторной "+
					"переаннотацией) — одна запись объясняется одним окном. %s", e.FQN, e.Refs)})
			continue
		}
		eb, ok := edgeByFQN[e.FQN]
		if !ok {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"у края нет глагола %q — переаннотации нечего объяснять: снимите запись. %s", e.FQN, e.Refs)})
			continue
		}
		if eb.body == e.OwnBody {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"край уже несёт у %q новую запись — предикат снятия наступил: снимите запись. %s",
				e.FQN, e.Refs)})
			continue
		}
		if eb.body != e.EdgeBody {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"запись называет у края %q прежнюю запись, а край несёт иную — "+
					"она утверждает о дереве неправду. %s", e.FQN, e.Refs)})
			continue
		}
		ob, ok := ownByFQN[e.FQN]
		if !ok || ob.body != e.OwnBody {
			findings = append(findings, CatalogParityFinding{CatalogFindingLedger, fmt.Sprintf(
				"запись называет у НАС %q новую запись, которой в нашей копии нет дословно — "+
					"она утверждает о дереве неправду. %s", e.FQN, e.Refs)})
			continue
		}
		revisedEdge[e.FQN] = e.OwnBody
		census.ReannotatedApplied++
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
		if body, ok := revisedEdge[b.fqn]; ok {
			b = catalogBlock{fqn: b.fqn, body: body}
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

// catalogFieldLiteral — строка поля записи в той форме, в какой её пишет
// генератор: `"<поле>": "<значение>"`.
func catalogFieldLiteral(field, value string) string {
	return mustJSONString(field) + ": " + mustJSONString(value)
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

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// prod_profile_test.go — проба боевого профиля ЭТОГО чарта.
//
// # Зачем она есть
//
// Требование «отдельный клон iam поднимается в боевой посадке» до сих пор было
// НЕ С ЧЕМ прогнать: все боевые профили дерева принадлежат зонтичному чарту, а у
// чарта сервиса были только `values.yaml` и `values.dev.yaml`. Профиль есть
// объявление посадки; проба судит объявление.
//
// # Чем она НЕ является — граница названа первой, чтобы её не выводил читатель
//
// Она НЕ поднимает под и НЕ доказывает, что установка проходит в кластере: это
// «не выполнилось», третья категория, а не зелёное. Она доказывает ровно одно —
// что величины, объявленные профилем, УДОВЛЕТВОРЯЮТ стражу старта. Страж —
// первое, обо что разбивается боевая установка, и до этой пробы его вердикт о
// профиле чарта не спрашивал никто.
//
// # Почему тут нет ТАБЛИЦЫ условий стража
//
// Соблазн был: выписать «условие → ручка» списком. Такой список есть второе
// место об одном предмете, и расходится он молча — страж обзаводится новым
// условием, а список о нём не знает и остаётся зелёным. Поэтому проба зовёт САМ
// страж (`config.Config.Validate`), сам предикат шифрования до базы
// (`coredb.SSLModeFromDSN` + `SSLModeSecure` — те же две функции, что зовёт
// композиционный корень) и сам разбор посадки транспорта (`config.LoadMTLS`).
// Появится у стража новое условие — профиль покраснеет, ничего здесь не правя.
//
// # Что всё же приходится повторить, и чем это удержано
//
// Чарт кладёт часть величин в `config.yaml` (шаблон `templates/configmap.yaml`),
// а часть — переменными окружения (карта `env`, шаблон `templates/deployment.yaml`
// отдаёт её пода дословно). Проба обязана собрать ровно тот вход, что увидит
// процесс, поэтому переложение «ключ значений чарта → ключ конфигурации»
// повторяет шаблон. Это ЕДИНСТВЕННОЕ повторение, оно перечислено в
// `configBridge`, и его предпосылка проверяется отдельной пробой: каждый ключ
// переложения обязан встречаться в самом шаблоне. Перестанет шаблон его
// рендерить — переложение краснеет и называет ключ.
package deploy_test

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
	"go.uber.org/multierr"
	"gopkg.in/yaml.v3"

	coredb "github.com/PRO-Robotech/kacho/pkg/db"
	"github.com/PRO-Robotech/kaname/internal/apps/kaname/config"
)

// chartProfiles — цепочка `-f`, которой ставится боевая посадка этого чарта.
// Тот же порядок, что у dev-цепочки (`values.yaml` + `values.dev.yaml`).
var chartProfiles = []string{"values.yaml", "values.prod.yaml"}

// configBridge — переложение «путь в значениях чарта → ключ конфигурации», как
// его делает `templates/configmap.yaml`.
//
// ЕДИНИЦА — ключ конфигурации, а не ключ значений: страж читает конфигурацию, и
// именно её надо собрать. Значение либо берётся из значений чарта по пути
// `valuePath`, либо вычисляется `derive` (шаблон кое-где склеивает строку —
// адрес слушателя из порта, строку подключения из полей базы).
type bridged struct {
	configKey string   // точечный путь ключа конфигурации
	valuePath []string // путь в дереве значений чарта; пуст, когда значение выводится
	derive    func(*valueReader) any
	omitEmpty bool // пустое значение шаблон не рендерит вовсе
	// gate — путь ВЫКЛЮЧАТЕЛЯ блока: шаблон рендерит ключ только при истинном
	// значении по этому пути (`{{- if $ts.enabled }}`).
	//
	// Отдельное поле, а не `omitEmpty` на самом выключателе: у блока выключатель
	// ОДИН, а ключей в нём несколько, и каждый из них при выключенном блоке
	// отсутствует ЦЕЛИКОМ — включая тот, у которого своё значение непусто.
	// Без него переложение клало бы ключи выключенного блока, вход оказался бы
	// шире рендера, и проба стерегла бы величины, которых процесс не получит.
	gate []string
}

// valueReader — доступ к дереву значений чарта, ЗАПОМИНАЮЩИЙ прочитанные пути.
//
// Заведён затем, чтобы перечень путей, которые потребляет `derive`, ВЫВОДИЛСЯ
// исполнением самой функции, а не выписывался рядом с ней. Выписанный перечень
// есть второе место об одном предмете, и расходится он молча: склейка перестаёт
// читать ключ, перечень о нём не знает, и ключ остаётся на поверхности посадки,
// которой больше не принадлежит.
type valueReader struct {
	tree map[string]any
	read [][]string
}

// text — величина по пути, в форме, годной для подстановки в строку.
//
// ОТСУТСТВУЮЩИЙ ПУТЬ ДАЁТ ПУСТОТУ, А НЕ «<nil>», и это несущее свойство, а не
// косметика. Пока склейка шла через `fmt.Sprintf("%v", …)`, снятый `db.host`
// давал строку подключения `postgres://iam@<nil>:5432/kaname`: хост НЕПУСТ,
// страж старта доволен, и снятие ручки посадку не роняло. То есть проба о такой
// ручке не утверждала ничего — при том что без хоста служба в пуск не идёт.
// Пустая величина даёт `postgres://iam@:5432/kaname`, и страж отвечает своим
// текстом: `repository.postgres.url=… names no host`.
func (r *valueReader) text(path ...string) string {
	r.read = append(r.read, append([]string{}, path...))
	v := at(r.tree, path...)
	if v == nil {
		return ""
	}
	return fmt.Sprintf("%v", v)
}

// derivedValuePathsOf — пути значений, которые потребляют вычисляющие записи
// названного переложения. Получены ИСПОЛНЕНИЕМ каждой записи на запоминающем
// читателе, а не объявлением.
//
// Переложение приходит ПАРАМЕТРОМ, чтобы способность вывода упасть доказывалась
// инъекцией: склейка, переставшая читать путь, обязана выводить ручку из
// поверхности посадки, и это проверяется подменой переложения, а не прочтением.
func derivedValuePathsOf(bridge []bridged, tree map[string]any) [][]string {
	var out [][]string
	seen := map[string]bool{}
	for _, b := range bridge {
		if b.derive == nil {
			continue
		}
		r := &valueReader{tree: tree}
		_ = b.derive(r)
		for _, path := range r.read {
			joined := strings.Join(path, ".")
			if seen[joined] {
				continue
			}
			seen[joined] = true
			out = append(out, path)
		}
	}
	return out
}

// derivedValuePaths — то же для действующего переложения чарта.
func derivedValuePaths(tree map[string]any) [][]string {
	return derivedValuePathsOf(configBridge, tree)
}

// postureValuePathsOf — ВСЕ пути значений, которые названное переложение
// доводит до файла настроек: и взятые по `valuePath`, и потреблённые склейкой.
func postureValuePathsOf(bridge []bridged, tree map[string]any) [][]string {
	var out [][]string
	for _, b := range bridge {
		if len(b.valuePath) > 0 {
			out = append(out, b.valuePath)
		}
		// ВЫКЛЮЧАТЕЛЬ БЛОКА — тоже поверхность посадки, и более несущая, чем
		// обычный путь: он решает, доедет ли до процесса блок ЦЕЛИКОМ. Не
		// назови его здесь — ручка, снятие которой уносит из входа шесть
		// ключей разом, числилась бы «эксплуатационной», то есть стражем не
		// судимой, и её снятие прошло бы молча.
		if len(b.gate) > 0 {
			out = append(out, b.gate)
		}
	}
	return append(out, derivedValuePathsOf(bridge, tree)...)
}

// postureValuePaths — то же для действующего переложения чарта.
func postureValuePaths(tree map[string]any) [][]string {
	return postureValuePathsOf(configBridge, tree)
}

var configBridge = []bridged{
	{configKey: "logger.level", valuePath: []string{"logger", "level"}},
	{configKey: "api-server.endpoint", derive: func(r *valueReader) any {
		return fmt.Sprintf("tcp://0.0.0.0:%s", r.text("ports", "grpc"))
	}},
	{configKey: "api-server.internal-endpoint", derive: func(r *valueReader) any {
		return fmt.Sprintf("tcp://0.0.0.0:%s", r.text("ports", "internalGrpc"))
	}},
	{configKey: "api-server.graceful-shutdown", valuePath: []string{"apiServer", "gracefulShutdown"}},
	{configKey: "api-server.registry-token.issuer", valuePath: []string{"apiServer", "registryToken", "issuer"}, omitEmpty: true},
	{configKey: "api-server.registry-token.service", valuePath: []string{"apiServer", "registryToken", "service"}, omitEmpty: true},
	{configKey: "repository.type", derive: func(*valueReader) any { return "POSTGRES" }},
	{configKey: "repository.postgres.url", derive: func(r *valueReader) any {
		return fmt.Sprintf("postgres://%s@%s:%s/%s",
			r.text("db", "user"), r.text("db", "host"), r.text("db", "port"), r.text("db", "name"))
	}},
	{configKey: "repository.postgres.max-conns", valuePath: []string{"repository", "postgres", "maxConns"}},
	{configKey: "repository.postgres.ssl-mode", valuePath: []string{"repository", "postgres", "sslMode"}},
	{configKey: "repository.postgres.password-from-env", derive: func(*valueReader) any { return "KANAME_DB_PASSWORD" }},
	{configKey: "authn.mode", valuePath: []string{"authMode"}},
	// Доменное имя установки: из него выводится клеймо адресата, уезжающее в
	// каждом выпущенном токене. Умолчания у ключа нет (задача #2127), поэтому
	// профиль обязан его назвать, а страж — отказать без него.
	{configKey: "authn.domain", valuePath: []string{"authn", "domain"}, omitEmpty: true},
	{configKey: "authn.identity-provider", valuePath: []string{"authn", "identityProvider"}, omitEmpty: true},
	{configKey: "authn.trusted-forwarder-sans", valuePath: []string{"authn", "trustedForwarderSANs"}, omitEmpty: true},
	{configKey: "authn.trust-domain", valuePath: []string{"authn", "trustDomain"}, omitEmpty: true},
	// СОБСТВЕННЫЕ REST-ФРОНТЫ. Умолчания у адресов нет намеренно: адрес,
	// приходящий умолчанием процесса, непуст всегда — профиль, о ребре
	// умолчавший, поднимал бы его молча.
	//
	// Обеих записей здесь НЕ БЫЛО, и вход переложения был уже чарта ровно на
	// них; первая при этом несёт отказ стража старта, поэтому проба боевого
	// профиля оставалась зелёной при профиле, который не поднимается
	// (задача #2334). Класс держит `TestConfigBridge_CoversEveryKeyTheChartRenders`.
	{configKey: "api-server.rest-endpoint", valuePath: []string{"apiServer", "restEndpoint"}, omitEmpty: true},
	{configKey: "api-server.internal-rest-endpoint", valuePath: []string{"apiServer", "internalRestEndpoint"}, omitEmpty: true},
	// СВОЯ ЧЕКАНКА ТОКЕНОВ. Блок целиком за выключателем: шаблон не рендерит его
	// ни одним ключом, пока чеканка выключена.
	{configKey: "authn.token-signing.enabled", gate: tokenSigningGate, derive: func(*valueReader) any { return true }},
	{configKey: "authn.token-signing.issuer", gate: tokenSigningGate, valuePath: []string{"authn", "tokenSigning", "issuer"}},
	{configKey: "authn.token-signing.algorithm", gate: tokenSigningGate, valuePath: []string{"authn", "tokenSigning", "algorithm"}},
	{configKey: "authn.token-signing.allowed-algorithms", gate: tokenSigningGate, valuePath: []string{"authn", "tokenSigning", "allowedAlgorithms"}},
	{configKey: "authn.token-signing.key-set-path", gate: tokenSigningGate, valuePath: []string{"authn", "tokenSigning", "keySetPath"}},
	{configKey: "authn.token-signing.key-lifetime", gate: tokenSigningGate, valuePath: []string{"authn", "tokenSigning", "keyLifetime"}},
	// ЧИТАТЕЛЬ ПРЕДЪЯВЛЕННОГО УДОСТОВЕРЕНИЯ. Тот же выключатель блока.
	{configKey: "authn.presented-credential.enabled", gate: presentedCredentialGate, derive: func(*valueReader) any { return true }},
	{configKey: "authn.presented-credential.audience", gate: presentedCredentialGate, valuePath: []string{"authn", "presentedCredential", "audience"}},
	{configKey: "authn.presented-credential.revocation-cache-ttl", gate: presentedCredentialGate, valuePath: []string{"authn", "presentedCredential", "revocationCacheTtl"}},
}

// Выключатели блоков — названы ОДИН раз: путь, повторённый у каждого ключа
// блока, разошёлся бы с шаблоном по одной записи из шести.
var (
	tokenSigningGate        = []string{"authn", "tokenSigning", "enabled"}
	presentedCredentialGate = []string{"authn", "presentedCredential", "enabled"}
)

// restatedDeliberately — ручки боевого профиля, чьё СНЯТИЕ страж не замечает, и
// причина, по которой они всё равно объявлены.
//
// Перечень утверждается В ОБЕ СТОРОНЫ: запись, чью ручку страж начал читать,
// становится находкой и подлежит удалению. Иначе послабление переживает свой
// предмет и начинает прощать ту ручку, которая в него следующей провалится.
var restatedDeliberately = map[string]string{
	"authMode": "базовые значения чарта уже несут production, поэтому снятие этой строки " +
		"посадку не роняет. Строка стоит затем, чтобы будущая правка умолчания чарта не " +
		"уронила посадку МОЛЧА: профиль называет её сам",
	// СОБСТВЕННЫЕ REST-ФРОНТЫ. Снятие любой из двух ручек посадку не роняет — и
	// это верное поведение стража, а не пробел в нём: ручка не НАСТРАИВАЕТ
	// фронт, она его ПОДНИМАЕТ. Снятая, она фронт опускает, то есть даёт
	// посадку уже, а не слабее, и требовать от стража отказа на сужении
	// поверхности значило бы требовать, чтобы служба без REST не поднималась
	// вовсе.
	"apiServer.restEndpoint": "ручка НЕСУЩАЯ, и страж её читает — как АНТЕЦЕДЕНТ " +
		"связывания: поднятый собственный публичный фронт требует читателя предъявленного " +
		"удостоверения (PresentedCredentialConfig.ValidateBinding), и отказ прямо называет " +
		"оба выхода — поднять читателя ЛИБО не объявлять фронт. Снятие ручки выбирает " +
		"второй выход, поэтому отказа и нет. Что снятие меняет: у отдельно поставленной " +
		"службы исчезает REST-поверхность арендатора — то, ради чего её ставят. Пара " +
		"«фронт + читатель» держится тем же связыванием и проверяется отсюда: снятие " +
		"authn.presentedCredential.enabled посадку РОНЯЕТ",
	"apiServer.internalRestEndpoint": "ручка НЕСУЩАЯ и, как публичный фронт рядом, " +
		"ПОДНИМАЕТ поверхность, а не настраивает её: снятая, она опускает внутренний " +
		"REST-фронт. Читателя предъявленного удостоверения этот фронт не требует — до него " +
		"дотягивается не арендатор, а сосед по кластеру, приходящий со своим сертификатом, " +
		"— поэтому связывания на нём нет и отказу взяться неоткуда. Транспорт фронта " +
		"судится ручками env.KANAME_INTERNALREST_* рядом",
	// Две величины своей чеканки, у которых встроенное умолчание процесса
	// НЕПУСТО и годно: страж на снятии молчит по построению.
	"authn.tokenSigning.keySetPath": "встроенное умолчание процесса непусто и годно " +
		"(/.well-known/kaname/jwks.json), поэтому страж на снятии молчит. Величина объявлена " +
		"потому, что это АДРЕС, по которому всякий проверяющий наш токен читает набор " +
		"ключей: оставленный умолчанием, он верен ровно до первого решения сменить путь — и " +
		"тогда смена окажется невидимой в профиле",
	"authn.tokenSigning.keyLifetime": "встроенное умолчание процесса непусто (90 суток), " +
		"поэтому страж на снятии молчит. Величина объявлена потому, что это ПОЛИТИКА " +
		"РОТАЦИИ ключа подписи — решение установки, а не наше; оставленная умолчанием, она " +
		"не видна тому, кто ставит, и потому не пересматривается",
	"apiServer.registryToken.issuer": "встроенное умолчание процесса непусто (локальное имя), " +
		"поэтому страж на снятии молчит. Величина объявлена потому, что это realm, который " +
		"докерный клиент слышит от нас: оставленное умолчание отправило бы его на хост, " +
		"которого у этой установки нет",
	// Три HTTP-ребра, чей транспорт задавал ЗОНТИЧНЫЙ чарт монорепо: у отдельно
	// поставленной службы его нет, а адреса всех трёх приходят умолчанием
	// процесса и потому непусты всегда. Причина у всех трёх одна и та же, что у
	// докерной полосы ниже: страж живёт в композиционном корне, отсюда
	// недостижимом by construction.
	"env.KANAME_HOOKS_SERVER_MTLS_ENABLE": "ручка НЕСУЩАЯ, но её страж живёт в " +
		"композиционном корне (requireHTTPEdgeTLS в cmd/kaname), а не в Config.Validate, " +
		"который зовёт эта проба, — то есть недостижим отсюда by construction: пакет main не " +
		"импортируется. Снятие ручки роняет не посадку, а СТАРТ: слушатель вебхуков " +
		"поднимается умолчанием процесса, и боевой режим отказывается пускать открытым текстом " +
		"хоп, по которому идёт общий секрет поставщика личности. Держит это " +
		"TestProductionProfileSatisfiesTheStartupGuards в services/iam/cmd/kaname",
	"env.KANAME_JWKSPROXY_SERVER_MTLS_ENABLE": "ручка НЕСУЩАЯ, но её страж живёт в " +
		"композиционном корне (requireHTTPEdgeTLS в cmd/kaname) и отсюда недостижим. " +
		"Снятие роняет СТАРТ: аутентификация с этой поверхности снята задокументированно, и " +
		"обоснование опирается на одностороннюю TLS — без неё предпосылка собственного " +
		"исключения ложна. Держит это TestProductionProfileSatisfiesTheStartupGuards",
	"env.KANAME_METRICS_SERVER_MTLS_ENABLE": "ручка НЕСУЩАЯ, но её страж живёт в " +
		"композиционном корне (requireHTTPEdgeTLS в cmd/kaname) и отсюда недостижим. " +
		"Снятие роняет СТАРТ: счётчики процесса суть внутренняя кардинальность, и открытый " +
		"текст выносит её всякому, кто слушает сеть пода. Держит это " +
		"TestProductionProfileSatisfiesTheStartupGuards",
	// Собственные REST-фронты службы (KAN-REST-1). Причина у обеих пар ручек та
	// же, что у четырёх рёбер рядом: страж живёт в композиционном корне.
	"env.KANAME_REST_SERVER_MTLS_ENABLE": "ручка НЕСУЩАЯ, но её страж живёт в " +
		"композиционном корне (requireHTTPEdgeTLS в cmd/kaname) и отсюда недостижим. " +
		"Снятие роняет СТАРТ: по этому проводу идёт ПРЕДЪЯВЛЕННОЕ УДОСТОВЕРЕНИЕ " +
		"арендатора — снятое с провода, оно предъявляется повторно кем угодно до " +
		"истечения срока, и отличить такой вызов от настоящего нечем: подпись верна. " +
		"Держит это TestProductionProfileSatisfiesTheStartupGuards",
	"env.KANAME_INTERNALREST_SERVER_MTLS_ENABLE": "ручка НЕСУЩАЯ, но её страж живёт в " +
		"композиционном корне (requireHTTPEdgeTLS в cmd/kaname) и отсюда недостижим. " +
		"Снятие роняет СТАРТ: внутренний периметр доверенным не считается, и открытый " +
		"текст выносит служебные поверхности всякому, кто слушает сеть пода. " +
		"Держит это TestProductionProfileSatisfiesTheStartupGuards",
	"env.KANAME_REST_UPSTREAM_MTLS_ENABLE": "ручка НЕСУЩАЯ, но её страж живёт в " +
		"композиционном корне (requireRESTUpstreamCredential в cmd/kaname) и отсюда " +
		"недостижим. Снятие роняет СТАРТ: фронт идёт к СОБСТВЕННОМУ слушателю обычным " +
		"клиентом, а тот в боевой посадке требует проверенного сертификата — без " +
		"удостоверения он отвергнет фронт на КАЖДОМ запросе, и снаружи исправная служба " +
		"будет выглядеть недоступной. Разбор пары (сертификат, ключ, корни) достижим " +
		"отсюда и держится MTLSConfig.Validate",
	// Три величины ниже исхода НЕ меняют: ребро объявлено односторонним, и при
	// нём набор корней клиента не требуется, а пустой режим и есть
	// server-tls-only. Объявлены ЯВНО, чтобы перевод ребра в двустороннее был
	// правкой значения, а не открытием, что величины не было вовсе.
	"env.KANAME_REST_SERVER_MTLS_CLIENTAUTHMODE": "исхода не меняет: пустое значение " +
		"resolveClientAuthMode и есть server-tls-only, то есть ровно то, что объявлено. " +
		"Ребро одностороннее НАМЕРЕННО — арендатор приходит обычным HTTP-клиентом и " +
		"клиентского сертификата не носит; требование предъявить его отвергло бы каждого " +
		"на рукопожатии",
	// ЗДЕСЬ СТОЯЛО «исхода не меняет по той же причине, что у публичного фронта».
	// Довод публичного фронта был перенесён на внутренний целиком, и обе его
	// половины здесь неверны: вызывающие внутренней поверхности — модули,
	// называющиеся сертификатом, а предъявленное удостоверение внутренний
	// слушатель не читает вовсе. Ребро переведено во взаимный режим (#2335).
	"env.KANAME_INTERNALREST_SERVER_MTLS_CLIENTAUTHMODE": "ручка НЕСУЩАЯ, но её страж " +
		"живёт в композиционном корне (requireInternalRESTMutualClientAuth в cmd/kaname) " +
		"и отсюда недостижим — как и у соседней ручки транспорта этого же ребра. Снятие " +
		"роняет СТАРТ: пустое значение процесс читает как server-tls-only, а на нём " +
		"вызывающий не назван ничем — рубеж у этой поверхности бывает только транспортный. " +
		"Держит это TestProductionProfileSatisfiesTheStartupGuards",
	"env.KANAME_REST_SERVER_MTLS_CLIENTCAFILES": "исхода не меняет: при одностороннем " +
		"ребре набор корней КЛИЕНТА не требуется — validateServerEdge спрашивает его " +
		"только у двустороннего. Объявлен затем, чтобы перевод ребра в mutual был правкой " +
		"одного значения",
	// Записи про env.KANAME_INTERNALREST_SERVER_MTLS_CLIENTCAFILES здесь БОЛЬШЕ
	// НЕТ, и это не пропуск: ребро переведено во взаимный режим (#2335), а он
	// набор корней клиента ТРЕБУЕТ — снятие ручки роняет посадку, и послабление
	// истекло вместе со своим предметом. Раньше профиль объявлял корни рядом с
	// односторонним режимом, который их не читает, — то есть ВЫГЛЯДЕЛ взаимным,
	// не будучи им.
	"env.KANAME_REGISTRYTOKEN_SERVER_MTLS_ENABLE": "ручка НЕСУЩАЯ, но её страж живёт в " +
		"композиционном корне (requireRegistryTokenTLS в cmd/kaname), а не в Config.Validate, " +
		"который зовёт эта проба, — то есть недостижим отсюда by construction: пакет main не " +
		"импортируется. Снятие ручки роняет не посадку, а СТАРТ: слушатель докерной полосы " +
		"поднимается умолчанием процесса, и боевой режим отказывается пускать его открытым " +
		"текстом. Держит это TestProductionProfileSatisfiesTheStartupGuards в " +
		"services/iam/cmd/kaname — она зовёт того самого стража. Соседние две ручки этой " +
		"ноги (CERTFILE/KEYFILE) записи не требуют: их снятие ловит разбор посадки транспорта, " +
		"достижимый отсюда",
}

// secretStandIns — ЗАМЕНИТЕЛИ величин, которые живут в объекте Secret и в дерево
// не попадают ни разу.
//
// Профиль объявляет ИМЯ переменной и координату в секрете; ЗНАЧЕНИЕ приезжает в
// под из объекта, которого в git нет. Проба судит объявление, поэтому подставляет
// синтаксически годный заменитель — иначе страж отказывал бы на пустой величине,
// и проба меряла бы отсутствие секрета, а не полноту профиля.
//
// ГРАНИЦА НАЗВАНА ПРЯМО: заменитель годен ВСЕГДА, поэтому проба не может поймать
// негодную настоящую величину. Ловить там нечего — настоящей величины в профиле
// нет by construction; проба утверждает, что объявление о ней СТОИТ.
//
// Перечень утверждается в обе стороны: заменитель без объявленной переменной —
// находка, а не запас.
var secretStandIns = map[string]string{
	"KANAME_HOOK_TOKEN": "stand-in-not-a-secret",
	// Ключ обёртки разбирается как шестнадцатеричная строка объявленной длины,
	// поэтому заменитель обязан быть годен по форме.
	"KANAME_JWKS_ENC_KEY": "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f",
}

// ── несущая проба ────────────────────────────────────────────────────────────

func TestProdProfile_SatisfiesTheBootGuard(t *testing.T) {
	merged := mergeChartProfiles(t, chartProfiles)

	envCount, keyCount, posture := evaluatePosture(t, merged)
	require.NoError(t, posture,
		"боевой профиль чарта не удовлетворяет стражу старта: под с этими значениями "+
			"не поднимется — процесс откажет в пуске ещё до первого слушателя")

	t.Logf("перепись: профилей в цепочке %d · ключей конфигурации %d · переменных окружения %d",
		len(chartProfiles), keyCount, envCount)
}

// TestProdProfile_TheGuardIsLiveWithoutIt — отрицательный контроль несущей
// пробы: без боевого профиля страж ОБЯЗАН отказать.
//
// Без этой половины зелёное выше не значит ничего: страж, разучившийся падать,
// на любом профиле выглядит довольным.
func TestProdProfile_TheGuardIsLiveWithoutIt(t *testing.T) {
	merged := mergeChartProfiles(t, []string{"values.yaml"})

	_, _, posture := evaluatePosture(t, merged)
	require.Error(t, posture,
		"одни базовые значения чарта прошли стража боевой посадки — значит зелёное "+
			"боевого профиля не доказывает ничего: падать стражу не на чем")
	t.Logf("отрицательный контроль: без боевого профиля страж отказал — %d упрёк(ов)",
		len(multierr.Errors(posture)))
}

// TestProdProfile_EveryKnobIsLoadBearing — вторая половина предиката: профиль
// падает, КОГДА РУЧКА ПРОПАЛА.
//
// Снимает по одной ручке боевого профиля и требует отказа посадки. Ручка, чьё
// снятие никто не замечает, — либо украшение (профиль обязан быть объявлением
// посадки, а не сборником пожеланий), либо признак того, что страж её не читает
// и она никогда не действовала.
func TestProdProfile_EveryKnobIsLoadBearing(t *testing.T) {
	prod := readChartProfile(t, "values.prod.yaml")
	knobs := leafPaths(prod, nil)
	require.NotEmpty(t, knobs, "боевой профиль не объявляет ни одной ручки — "+
		"перепись прочитала бы ноль и отчиталась успехом при любом содержимом")

	// Поверхность считается ОДИН РАЗ и по ПОЛНОЙ цепочке: снятие ручки идёт
	// дальше по циклу, и поверхность, пересчитанная на усечённом дереве, судила
	// бы ручку по дереву без неё.
	surface := postureValuePaths(mergeChartProfiles(t, chartProfiles))

	seenRestated := map[string]bool{}
	inSurface := 0
	var outsideKnobs []string
	for _, knob := range knobs {
		joined := strings.Join(knob, ".")
		if !inPostureSurface(surface, knob) {
			outsideKnobs = append(outsideKnobs, joined)
			continue
		}
		inSurface++
		t.Run(joined, func(t *testing.T) {
			merged := mergeChartProfiles(t, chartProfiles)
			removeAt(merged, knob)
			_, _, posture := evaluatePosture(t, merged)

			if _, restated := restatedDeliberately[joined]; restated {
				seenRestated[joined] = true
				require.NoError(t, posture,
					"ручка %q числится восстановленной намеренно (страж её снятия не "+
						"замечает), но посадка без неё отказала — запись перечня лжёт "+
						"о предмете; удалите её", joined)
				return
			}
			require.Error(t, posture,
				"снятие ручки %q не уронило посадку, хотя ручка стоит на поверхности "+
					"посадки — либо страж её не читает вовсе и она не действовала ни "+
					"разу, либо она восстановлена намеренно и это надо СКАЗАТЬ: запись "+
					"в restatedDeliberately с причиной. Молчаливое украшение на этой "+
					"поверхности неотличимо от мёртвой ручки", joined)
		})
	}

	// Послабление живёт, пока у него есть предмет.
	for joined := range restatedDeliberately {
		require.True(t, seenRestated[joined],
			"перечень восстановленных намеренно называет %q, но такой ручки в боевом "+
				"профиле нет — запись пережила свой предмет и начнёт прощать ту ручку, "+
				"которая следующей провалится в неё", joined)
	}

	require.NotZero(t, inSurface,
		"ни одна ручка боевого профиля не попала в поверхность посадки — перепись "+
			"прочитала бы ноль и отчиталась успехом при любом содержимом")

	// ВНЕ ПОВЕРХНОСТИ — ДВА РОДА, и они РАЗДЕЛЯЮТСЯ, а не сваливаются в одно
	// число со словом «эксплуатационные».
	//
	//  1. координаты, которые судит ДРУГОЙ судья — страж рендера чарта
	//     (`kaname-svc.requireOperatorSuppliedNames`): имя секрета с паролем,
	//     ключ в нём, координата образа. Страж старта их не видит вовсе, и это
	//     ВЕРНО: до процесса они не доезжают, а без них не проходит установка;
	//  2. собственно эксплуатационные величины (число реплик, пределы): их не
	//     читает ни один из двух судей, и предметом этой пробы они не являются.
	//
	// Прежде оба рода назывались «эксплуатационными» одной строкой, и в ту же
	// строку попадал `db.host`, который посадку НЕСЁТ. Разделение выводится, а
	// не выписывается: перечень первого рода читается из самого перечня отказа
	// рендера.
	refused, guardCensus, err := renderRefusalPaths(filepath.Join(serviceRoot(t), "deploy"))
	require.NoError(t, err, "перечень отказа рендера не прочитан — вторая половина "+
		"классификации не с чем сверяется")

	var judgedByRender, operational []string
	for _, joined := range outsideKnobs {
		if refused[joined] {
			judgedByRender = append(judgedByRender, joined)
			continue
		}
		operational = append(operational, joined)
	}

	t.Logf("перепись: ручек боевого профиля %d · на поверхности посадки %d · вне её %d "+
		"(судимых стражем рендера %d: %s · эксплуатационных %d: %s) · "+
		"восстановленных намеренно %d · %s",
		len(knobs), inSurface, len(outsideKnobs),
		len(judgedByRender), strings.Join(judgedByRender, ", "),
		len(operational), strings.Join(operational, ", "),
		len(restatedDeliberately), guardCensus)
}

// renderRefusalPaths — пути значений, которые перечисляет ОТКАЗ РЕНДЕРА чарта.
//
// Читается тело именованного шаблона `kaname-svc.requireOperatorSuppliedNames`
// и берутся пути, названные его ветвями. Перечень ВЫВОДИТСЯ, а не выписывается:
// выписанный разошёлся бы с шаблоном молча — новая координата появляется
// коммитом в шаблон, перечень о ней не знает, и ручка уезжает в «эксплуатационные».
//
// ПРЕДПОСЫЛКА ПРОВЕРЯЕТСЯ, А НЕ ПОДРАЗУМЕВАЕТСЯ: не найден сам шаблон или ни
// одного пути в нём — это ОШИБКА, а не пустой перечень. Пустой перечень отнёс бы
// все координаты чужого кластера к эксплуатационным, то есть вернул бы ровно ту
// неправду, ради которой классификация заведена.
func renderRefusalPaths(chartDir string) (map[string]bool, string, error) {
	raw, err := os.ReadFile(filepath.Join(chartDir, templatesDir, helpersFile))
	if err != nil {
		return nil, "", fmt.Errorf("файл именованных шаблонов не читается: %w", err)
	}
	text := string(raw)

	const marker = `{{- define "kaname-svc.requireOperatorSuppliedNames" -}}`
	start := strings.Index(text, marker)
	if start < 0 {
		return nil, "", fmt.Errorf(
			"в %s нет объявления %s — перечень отказа рендера переименован или снят, "+
				"и классификация ручек вне поверхности посадки судила бы по пустому множеству",
			helpersFile, marker)
	}
	// Тело кончается СЛЕДУЮЩИМ объявлением, а не первым `{{- end -}}`: ветви
	// перечня закрываются своими `end`, и обрыв по первому из них прочитал бы
	// одну ветвь из четырёх — перепись показала бы одну координату вместо всех.
	body := text[start+len(marker):]
	if next := strings.Index(body, "{{- define "); next >= 0 {
		body = body[:next]
	}

	aliases := templateAliases(body)
	out := map[string]bool{}
	lines := strings.Split(body, "\n")
	for _, line := range lines {
		for _, m := range actionRe.FindAllStringSubmatch(line, -1) {
			action := strings.TrimSpace(m[1])
			if !strings.HasPrefix(action, "if ") {
				continue
			}
			for _, path := range resolveRefs(action, aliases) {
				out[path] = true
			}
		}
	}
	if len(out) == 0 {
		return nil, "", fmt.Errorf(
			"перечень отказа рендера прочитан (%d строк), но не назвал ни одного пути "+
				"значений — распознаватель не знает формы его ветвей", len(lines))
	}

	named := make([]string, 0, len(out))
	for p := range out {
		named = append(named, p)
	}
	sort.Strings(named)
	return out, fmt.Sprintf("перечень отказа рендера называет %d координат(ы): %s",
		len(named), strings.Join(named, ", ")), nil
}

// inPostureSurface — принадлежит ли ручка ПОВЕРХНОСТИ ПОСАДКИ.
//
// Поверхность выводится из устройства чарта, а не выписывается перечнем условий
// стража: это карта переменных окружения, карта величин из секрета, материал TLS
// и те ключи значений, которые шаблон кладёт в файл настроек. Всё прочее —
// эксплуатационные величины (число реплик, пределы): они законны в боевом
// профиле, посадки не несут и в вердикт этой пробы не входят.
//
// ПУТИ ПРИХОДЯТ ПАРАМЕТРОМ, А НЕ БЕРУТСЯ ИЗ `configBridge` НАПРЯМУЮ, и это
// несущее различие, а не стиль. Прежде поверхность выводилась ТОЛЬКО из
// `valuePath`, а записи, которые значение ВЫЧИСЛЯЮТ (`derive`, `valuePath`
// пуст), пропускались целиком. Строку подключения к базе шаблон СКЛЕИВАЕТ из
// `db.user`, `db.host`, `db.port`, `db.name` — поэтому `db.host` поверхности не
// принадлежал, хотя страж старта его читает и без него отказывает в пуске
// (`repository.postgres.url=… names no host`). Ручка, которую страж читает,
// числилась не несущей посадки, а перепись относила её к эксплуатационным.
// Теперь потреблённые пути ВЫВОДЯТСЯ исполнением самой склейки
// (`derivedValuePaths`), и второго места об одном предмете не заводится.
func inPostureSurface(paths [][]string, knob []string) bool {
	switch knob[0] {
	case "env", "secrets", "tls":
		return true
	}
	for _, path := range paths {
		if len(path) == 0 || len(path) > len(knob) {
			continue
		}
		match := true
		for i, seg := range path {
			if knob[i] != seg {
				match = false
				break
			}
		}
		if match {
			return true
		}
	}
	return false
}

// TestConfigBridge_MirrorsTheChartTemplate — предпосылка переложения.
//
// Переложение верно ровно пока шаблон рендерит те же ключи. Проба судит ТЕКСТ
// шаблона, и это её граница: она отвечает на вопрос «ключ ещё рендерится», а не
// «рендерится тем же значением». Второй вопрос закрыт бы рендером, а рендер
// требует helm и потому пропускается ровно на той машине, где он нужен.
func TestConfigBridge_MirrorsTheChartTemplate(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("templates", "configmap.yaml"))
	require.NoError(t, err)
	text := string(raw)

	for _, b := range configBridge {
		segs := strings.Split(b.configKey, ".")
		leaf := segs[len(segs)-1] + ":"
		require.Contains(t, text, leaf,
			"переложение называет ключ конфигурации %q, а шаблон configmap.yaml его "+
				"больше не рендерит — переложение собирает вход, которого процесс не "+
				"увидит, и вердикт пробы относится к чужому дереву", b.configKey)
	}

	// ВТОРАЯ ПОЛОВИНА ПРЕДПОСЫЛКИ — пути, которые потребляет СКЛЕЙКА.
	//
	// Они выводятся исполнением самой склейки, но склейка всё-таки повторяет
	// шаблон, и повторение обязано быть удержано так же, как повторение ключей
	// выше: путь, который шаблон перестал читать, делает поверхность посадки
	// шире действительной — ручка стерегомая, а читателя у неё нет.
	merged := mergeChartProfiles(t, chartProfiles)
	derived := derivedValuePaths(merged)
	require.NotEmpty(t, derived,
		"ни одна запись переложения не потребляет путей значений — либо склейки не "+
			"осталось, либо читатель перестал их запоминать; поверхность посадки "+
			"собралась бы из одних `valuePath`, то есть вернулась бы к пробелу задачи #2095")

	named := make([]string, 0, len(derived))
	for _, path := range derived {
		joined := strings.Join(path, ".")
		named = append(named, joined)
		require.Contains(t, text, ".Values."+joined,
			"склейка читает %q, а шаблон configmap.yaml на этот путь больше не "+
				"ссылается — поверхность посадки шире действительной, и проба стережёт "+
				"ручку, у которой нет читателя", joined)
	}
	sort.Strings(named)

	t.Logf("перепись: ключей переложения %d · путей, потреблённых склейкой %d (%s) · "+
		"шаблон прочитан (%d байт)", len(configBridge), len(named), strings.Join(named, ", "), len(raw))
}

// ── сборка входа и вердикт ───────────────────────────────────────────────────

// bootGuardVerdict — ВЕРДИКТ стражей боевой посадки о СОБРАННОМ входе.
//
// Вход приходит параметрами — путь файла настроек и карта окружения, — потому
// что производителей входа ДВА: переложение значений чарта (быстрое, без helm)
// и настоящий рендер чарта (`prod_profile_render_test.go`). Вердикт при этом
// обязан быть ОДИН: два места об одном предмете разошлись бы молча, и тогда
// сравнивать производителей было бы не с чем — а именно расхождение
// производителей и есть предмет задачи #2334.
//
// Три стража, и каждый зовётся САМ, а не пересказывается:
//   - `config.Config.Validate` — страж старта службы;
//   - `coredb.SSLModeFromDSN` + `SSLModeSecure` — ось шифрования до своей базы
//     (О8 центрального дескриптора посадки; те же две функции зовёт
//     композиционный корень, `cmd/kaname/posture.go`);
//   - `config.LoadMTLS` + `MTLSConfig.Validate` — посадка транспорта обоих
//     слушателей (О8, поля PublicCreds/InternalCreds).
//
// # ЗОВЁТСЯ НЕ БОЛЕЕ ОДНОГО РАЗА НА ПРОБУ, и это не стиль
//
// `requireCleanEnv` требует, чтобы в окружении не было НИ ОДНОЙ переменной
// службы: иначе вердикт становится свойством машины, а не профиля. Переменные,
// поставленные `t.Setenv`, живут до конца ПРОБЫ, а не до конца вызова, — поэтому
// второй вызов внутри той же пробы падает на предпосылке, и падает сообщением
// про «окружение прогона», которое на эту причину не указывает.
//
// Нужно два вердикта — заводи две пробы. Измерено: цикл по двум профилям внутри
// одной пробы даёт ровно этот отказ на втором обороте.
func bootGuardVerdict(t *testing.T, cfgPath string, envs map[string]string) error {
	t.Helper()
	requireCleanEnv(t)
	for k, v := range envs {
		t.Setenv(k, v)
	}

	cfg, loadErr := config.Load(cfgPath)
	if loadErr != nil {
		return fmt.Errorf("конфигурация не загрузилась: %w", loadErr)
	}

	var errs error
	errs = multierr.Append(errs, cfg.Validate())

	mode := coredb.SSLModeFromDSN(cfg.DSN())
	if !coredb.SSLModeSecure(mode) {
		errs = multierr.Append(errs, fmt.Errorf(
			"боевая посадка с sslmode=%q; допустимы %s (ось О8 центрального дескриптора)",
			mode, strings.Join(coredb.SecureSSLModes(), ", ")))
	}

	mtls, mtlsErr := config.LoadMTLS()
	switch {
	case mtlsErr != nil:
		errs = multierr.Append(errs, fmt.Errorf("посадка транспорта не разобралась: %w", mtlsErr))
	default:
		if !mtls.PublicServerMTLS.Enable {
			errs = multierr.Append(errs, fmt.Errorf(
				"боевая посадка с непроверенным транспортом публичного слушателя: "+
					"KANAME_PUBLIC_SERVER_MTLS_ENABLE не объявлен"))
		}
		if !mtls.InternalServerMTLS.Enable {
			errs = multierr.Append(errs, fmt.Errorf(
				"боевая посадка с непроверенным транспортом внутреннего слушателя: "+
					"KANAME_INTERNAL_SERVER_MTLS_ENABLE не объявлен; внутренний периметр не доверенный"))
		}
		errs = multierr.Append(errs, mtls.Validate())
	}
	return errs
}

// evaluatePosture собирает вход ПЕРЕЛОЖЕНИЕМ значений чарта и возвращает
// сводный вердикт стражей боевой посадки.
//
// # ЧЕМ ЭТО НЕ ЯВЛЯЕТСЯ — названо первым, чтобы вердикт не читали шире
//
// Переложение — не рендер. Оно повторяет шаблон на Go, поэтому о ключе, который
// шаблон рендерит, а переложение не несёт, эта проба не утверждает НИЧЕГО.
// Ровно так вход оказался уже чарта на два ключа, и один из них нёс отказ
// стража (#2334). Авторитетный вердикт даёт `prod_profile_render_test.go`,
// собирающий вход настоящим `helm template`; здесь переложение остаётся ради
// шестидесяти прогонов «снятой ручки», которым рендер на каждую итерацию стоил
// бы helm в PATH и десятка секунд.
//
// Верность переложения РЕНДЕРУ держит `TestConfigBridge_CoversEveryKeyTheChartRenders`
// (там же): перепись «ключей рендера N · записей переложения M» печатается, и
// расхождение роняет прогон, называя недостающий ключ. Пока она зелена, вход
// отсюда и вход из рендера совпадают по составу ключей.
//
// Плюс одно утверждение о ДОСЯГАЕМОСТИ: файл, названный ручкой, обязан лежать
// под каталогом, который чарт монтирует. Путь к материалу, которого под не
// несёт, — объявленная и неисполнимая возможность.
func evaluatePosture(t *testing.T, merged map[string]any) (envCount, keyCount int, verdict error) {
	t.Helper()

	cfgPath, keys := writeRenderedConfig(t, merged)
	envs := envEntries(merged)
	secretErr := applySecretStandIns(merged, envs)

	errs := multierr.Append(secretErr, bootGuardVerdict(t, cfgPath, envs))
	errs = multierr.Append(errs, filesAreMountable(merged, envs))
	return len(envs), keys, errs
}

// applySecretStandIns кладёт в карту окружения заменители тех величин, что
// профиль объявил приезжающими из объекта Secret, и заодно судит САМО
// объявление: шаблон развёртывания отказывается рендерить координату без имени
// объекта и без ключа в нём.
func applySecretStandIns(merged map[string]any, envs map[string]string) error {
	declared, _ := merged["secrets"].(map[string]any)

	var errs error
	seen := map[string]bool{}
	names := make([]string, 0, len(declared))
	for name := range declared {
		names = append(names, name)
	}
	sort.Strings(names)

	for _, name := range names {
		coord, ok := declared[name].(map[string]any)
		if !ok {
			errs = multierr.Append(errs, fmt.Errorf(
				"secrets.%s объявлен без координаты — шаблон развёртывания рендерить его откажет", name))
			continue
		}
		for _, field := range []string{"secretName", "secretKey"} {
			if v, _ := coord[field].(string); strings.TrimSpace(v) == "" {
				errs = multierr.Append(errs, fmt.Errorf(
					"secrets.%s.%s не задан — шаблон развёртывания рендерить координату "+
						"откажет, и переменная до пода не доедет вовсе", name, field))
			}
		}
		standIn, ok := secretStandIns[name]
		if !ok {
			errs = multierr.Append(errs, fmt.Errorf(
				"профиль объявляет переменную %s приезжающей из секрета, а у пробы нет для "+
					"неё заменителя — вердикт о полноте профиля вынести не с чем", name))
			continue
		}
		if _, clash := envs[name]; clash {
			errs = multierr.Append(errs, fmt.Errorf(
				"переменная %s объявлена и в карте env, и в secrets — величина выразима "+
					"двумя способами, и какой из них действует, решает шаблон, а не оператор", name))
			continue
		}
		envs[name] = standIn
		seen[name] = true
	}

	// Заменитель живёт, пока у него есть предмет.
	for name := range secretStandIns {
		if !seen[name] {
			errs = multierr.Append(errs, fmt.Errorf(
				"у пробы есть заменитель для %s, но профиль такой переменной из секрета "+
					"не объявляет — запись пережила свой предмет", name))
		}
	}
	return errs
}

// filesAreMountable — каждый путь к файлу, названный ручкой, лежит под
// каталогом, который чарт монтирует, И этот каталог обеспечен ОБЪЯВЛЕННЫМ
// секретом.
//
// Ручка, называющая путь, которого под не несёт, — объявленная и неисполнимая
// возможность: процесс отказывает в пуске на нечитаемом файле, а профиль
// читается как настроенный.
//
// # ПРЕДПОСЫЛКА ПЕРЕСМОТРЕНА ПРИ РАСШИРЕНИИ ПОПУЛЯЦИИ (задача #2186)
//
// Проверка писалась, когда у службы был ОДИН лист. На такой популяции «путь
// начинается с tls.mountPath» и «секрет объявлен» совпадали, и допущение было
// невидимо. Листов стало два — слушателя и клиента, в соседних подкаталогах
// одного монтирования, — и прежний предикат стал пропускать ровно тот класс,
// ради которого написан: путь под `<mount>/client` проходил проверку префикса,
// хотя секрета клиента профиль не объявлял и каталога в поде не было.
//
// Подкаталоги названы ЗДЕСЬ по одному ключу секрета на каждый, и это
// fail-closed: переименует шаблон подкаталог — путь под неизвестным именем
// станет находкой, а не молчанием.
func filesAreMountable(merged map[string]any, envs map[string]string) error {
	mount, _ := at(merged, "tls", "mountPath").(string)

	// подкаталог монтирования → ключ значений, объявляющий его секрет.
	leafSecretKey := map[string]string{
		"server": "secretName",
		"client": "clientSecretName",
	}

	var named []string
	for k, v := range envs {
		if !strings.HasSuffix(k, "_CERTFILE") && !strings.HasSuffix(k, "_KEYFILE") &&
			!strings.HasSuffix(k, "_CLIENTCAFILES") && !strings.HasSuffix(k, "_CA_FILE") &&
			!strings.HasSuffix(k, "_CAFILES") {
			continue
		}
		for _, p := range strings.Split(v, ",") {
			if p = strings.TrimSpace(p); p != "" {
				named = append(named, k+"="+p)
			}
		}
	}
	if len(named) == 0 {
		return nil
	}
	sort.Strings(named)

	var errs error
	if strings.TrimSpace(mount) == "" {
		errs = multierr.Append(errs, fmt.Errorf(
			"профиль называет %d путь(ей) к материалу TLS и не объявляет tls.mountPath — "+
				"проверить досягаемость не с чем", len(named)))
		return errs
	}
	prefix := strings.TrimSuffix(mount, "/") + "/"
	for _, n := range named {
		path := n[strings.Index(n, "=")+1:]
		if !strings.HasPrefix(path, prefix) {
			errs = multierr.Append(errs, fmt.Errorf(
				"ручка %s называет путь вне каталога, который монтирует чарт (tls.mountPath=%s) — "+
					"файла по этому пути в поде не будет", n, mount))
			continue
		}
		rest := strings.TrimPrefix(path, prefix)
		leaf := rest
		if i := strings.Index(rest, "/"); i >= 0 {
			leaf = rest[:i]
		}
		key, known := leafSecretKey[leaf]
		if !known {
			errs = multierr.Append(errs, fmt.Errorf(
				"ручка %s называет подкаталог %q монтирования, которого чарт не заводит — "+
					"известны %s; файла по этому пути в поде не будет",
				n, leaf, strings.Join(sortedKeys(leafSecretKey), ", "))) //nolint:gocritic
			continue
		}
		secret, _ := at(merged, "tls", key).(string)
		if strings.TrimSpace(secret) == "" {
			errs = multierr.Append(errs, fmt.Errorf(
				"ручка %s называет путь под %s%s, а tls.%s не объявлен — том не заводится, "+
					"каталога в поде нет, и процесс откажет в пуске на нечитаемом файле",
				n, prefix, leaf, key))
		}
	}
	return errs
}

// sortedKeys — детерминизм текста находки.
func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// writeRenderedConfig собирает config.yaml так, как его собирает шаблон чарта,
// и возвращает путь к нему плюс число положенных ключей.
func writeRenderedConfig(t *testing.T, merged map[string]any) (string, int) {
	t.Helper()
	tree := map[string]any{}
	keys := 0
	for _, b := range configBridge {
		if len(b.gate) > 0 && !isTruthy(at(merged, b.gate...)) {
			continue
		}
		var val any
		switch {
		case b.derive != nil:
			val = b.derive(&valueReader{tree: merged})
		default:
			val = at(merged, b.valuePath...)
		}
		if b.omitEmpty && isEmptyValue(val) {
			continue
		}
		if val == nil {
			continue
		}
		setAt(tree, strings.Split(b.configKey, "."), val)
		keys++
	}
	raw, err := yaml.Marshal(tree)
	require.NoError(t, err)

	path := filepath.Join(t.TempDir(), "config.yaml")
	require.NoError(t, os.WriteFile(path, raw, 0o600))
	return path, keys
}

// envEntries — карта `env` профиля, которую шаблон развёртывания отдаёт поду
// дословно.
func envEntries(merged map[string]any) map[string]string {
	out := map[string]string{}
	m, ok := merged["env"].(map[string]any)
	if !ok {
		return out
	}
	for k, v := range m {
		out[k] = fmt.Sprintf("%v", v)
	}
	return out
}

// requireCleanEnv — предпосылка пробы: в процессе нет посторонних KANAME_*.
//
// Оставшаяся переменная сделала бы вердикт свойством машины, а не профиля, и
// зелёное читалось бы как утверждение о дереве.
func requireCleanEnv(t *testing.T) {
	t.Helper()
	var stray []string
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "KANAME_") {
			stray = append(stray, kv[:strings.Index(kv, "=")])
		}
	}
	require.Empty(t, stray,
		"в окружении прогона уже стоят переменные %v — вердикт стал бы свойством "+
			"машины, а не профиля", stray)
}

// ── чтение профилей чарта ────────────────────────────────────────────────────

func readChartProfile(t *testing.T, name string) map[string]any {
	t.Helper()
	raw, err := os.ReadFile(name)
	require.NoErrorf(t, err, "чтение профиля %s", name)
	var tree map[string]any
	require.NoErrorf(t, yaml.Unmarshal(raw, &tree), "разбор профиля %s", name)
	return tree
}

func mergeChartProfiles(t *testing.T, chain []string) map[string]any {
	t.Helper()
	merged := map[string]any{}
	for _, name := range chain {
		merged = mergeInto(merged, readChartProfile(t, name))
	}
	return merged
}

// at достаёт значение по пути; отсутствующий путь даёт nil.
func at(tree map[string]any, path ...string) any {
	var cur any = tree
	for _, key := range path {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		if cur, ok = m[key]; !ok {
			return nil
		}
	}
	return cur
}

func setAt(tree map[string]any, path []string, val any) {
	cur := tree
	for _, key := range path[:len(path)-1] {
		next, ok := cur[key].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[key] = next
		}
		cur = next
	}
	cur[path[len(path)-1]] = val
}

// removeAt снимает лист по пути, оставляя опустевшие ветви на месте: снятие
// ветви целиком сняло бы больше одной ручки за раз, и упрёк относился бы не к
// названной.
func removeAt(tree map[string]any, path []string) {
	cur := tree
	for _, key := range path[:len(path)-1] {
		next, ok := cur[key].(map[string]any)
		if !ok {
			return
		}
		cur = next
	}
	delete(cur, path[len(path)-1])
}

// leafPaths перечисляет листья дерева значений. Список — тоже лист: снять из
// него один элемент значило бы менять величину, а не ручку.
func leafPaths(tree map[string]any, prefix []string) [][]string {
	var out [][]string
	keys := make([]string, 0, len(tree))
	for k := range tree {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		path := append(append([]string{}, prefix...), k)
		if sub, ok := tree[k].(map[string]any); ok {
			out = append(out, leafPaths(sub, path)...)
			continue
		}
		out = append(out, path)
	}
	return out
}

// isTruthy — та же истинность, что у `{{- if }}` шаблона: отсутствие, `false`,
// пустая строка и ноль ложны, прочее истинно.
func isTruthy(v any) bool {
	switch t := v.(type) {
	case nil:
		return false
	case bool:
		return t
	case string:
		return strings.TrimSpace(t) != ""
	case int:
		return t != 0
	case float64:
		return t != 0
	default:
		return true
	}
}

func isEmptyValue(v any) bool {
	if v == nil {
		return true
	}
	s, ok := v.(string)
	return ok && strings.TrimSpace(s) == ""
}

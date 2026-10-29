// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// Package moduleidentity — ЛИЧНОСТЬ МОДУЛЯ установки и ЕДИНСТВЕННОЕ её признание
// по клиентскому сертификату (kaname#984).
//
// # Предмет: модулем признаётся только объявленная пара
//
// Личность модуля — пара (пространство имён, служебная учётка), которую объявила
// установка kaname. Прежде модулем признавался любой проверенный лист нашего
// домена доверия, чья учётка несла приставку модулей, — в ЛЮБОМ пространстве.
// Пространство, которого установка не заводила, давало ту же личность, что и
// настоящее: владелец любого пространства кластера, получивший лист внутреннего
// центра на учётку нужного имени, становился модулем.
//
// Теперь признание — поиск пары в перечне ([Roster]). Пара вне перечня не
// модуль ни на одном пути: ни на ярусах вызывающего обоих слушателей, ни у
// посредника записи отношений, ни у пола системного читателя, ни у допуска пира
// без переданной личности.
//
// # У каждой личности — профиль
//
// Профиль ([Profile]) называет закрытый перечень методов внутреннего слушателя,
// которые личности позволено звать. Перечни методов живут у стража
// (`authzguard`), здесь — только словарь имён профилей: его спрашивает страж
// старта, чтобы отвергнуть запись с неизвестным профилем до подъёма.
//
// # Почему разбор один и живёт здесь
//
// Признание спрашивают шесть читателей. Разбор, написанный у каждого свой,
// расходится молча: правка одного не доезжает до другого, и второй продолжает
// признавать то, что первый уже отвергает. Здесь он один ([ParseSAN]), и
// перечень спрашивает ТОТ ЖЕ разбор, которым его записи проверены на старте.
package moduleidentity

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"sort"
	"strings"

	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/peer"

	"github.com/PRO-Robotech/corelib/grpcsrv"

	"github.com/PRO-Robotech/kaname/internal/servicesan"
)

// Profile — имя закрытого перечня методов внутреннего слушателя.
type Profile string

// Профили. Словарь ЗАКРЫТ: запись с иным именем страж старта отвергает.
const (
	// ProfileEdge — край платформы: фронтируемые им глаголы администрирования и
	// горячие пути, которые он спрашивает на каждом запросе.
	ProfileEdge Profile = "edge"
	// ProfileModuleWriter — модуль-владелец ресурсов: регистрирует свои объекты
	// и спрашивает решения о доступе.
	ProfileModuleWriter Profile = "module-writer"
	// ProfileDataPlane — плоскость данных: только вопрос о доступе.
	ProfileDataPlane Profile = "data-plane"
)

// Profiles — словарь профилей в порядке объявления.
func Profiles() []Profile {
	return []Profile{ProfileEdge, ProfileModuleWriter, ProfileDataPlane}
}

// known — знает ли словарь профиль p.
func (p Profile) known() bool {
	for _, q := range Profiles() {
		if p == q {
			return true
		}
	}
	return false
}

// saInfix — сегмент пути идентификатора, за которым стоит учётка.
const saInfix = "/sa/"

// Identity — признанная личность модуля.
type Identity struct {
	// Namespace — пространство имён, как его назвал сертификат.
	Namespace string
	// Account — служебная учётка целиком.
	Account string
	// Service — короткое имя службы, выведенное из учётки объявленной формой
	// имени службы (`vpc`, `api-gateway`).
	Service string
	// Profile — профиль, объявленный установкой для этой пары.
	Profile Profile
	// Issuer — имя доверенного удостоверяющего центра, который ВПРАВЕ выпускать
	// лист этой личности (kaname#988). Пусто — привязки нет: такая запись
	// законна только вне боевого режима ([Roster.RequireIssuerBinding]).
	Issuer string
}

// IssuerSet — доверенные удостоверяющие центры установки: имя → якоря.
// Лист признаётся личностью с привязкой, только если его проверенная цепочка
// оканчивается якорем именно её центра.
type IssuerSet map[string][]*x509.Certificate

// ParseSAN — ЕДИНСТВЕННЫЙ разбор SPIFFE-идентификатора рабочей нагрузки:
// `spiffe://<домен>/ns/<пространство>/sa/<учётка>`.
//
// Домен — АРГУМЕНТ: разбор спрашивает тот домен, который впустил эту личность.
// Необъявленный домен не узнаёт никого. Пространство и учётка — по одному
// сегменту пути: идентификатор с лишними сегментами формы не имеет, и принять
// его значило бы признать хвост чужого пути.
func ParseSAN(d grpcsrv.TrustDomain, san string) (namespace, account string, ok bool) {
	nsPrefix := d.NamespacePrefix()
	if nsPrefix == "" || !strings.HasPrefix(san, nsPrefix) {
		return "", "", false
	}
	rest := san[len(nsPrefix):]
	ns, acc, found := strings.Cut(rest, saInfix)
	if !found || !isDNSLabel(ns) || !isAccountName(acc) {
		return "", "", false
	}
	return ns, acc, true
}

// ServiceFromAccount — короткое имя службы, которое учётка модуля несёт в
// форме имени службы, объявленной установкой (kaname#308). Ложь — учётка этой
// формы не имеет, имя службы в ней пусто либо форма не объявлена.
//
// Форма — величина установки, а не литерал разбора: как учётка складывается из
// имени службы, решает тот, кто ставит. Пока приставка стояла здесь литералом,
// это было имя другого продукта, и установка, называвшая учётки иначе, не
// признавала ни одного своего модуля.
func (r Roster) ServiceFromAccount(account string) (string, bool) {
	return r.form.Service(account)
}

// Form — форма имени службы, которой перечень читает учётки своих записей.
func (r Roster) Form() servicesan.Form { return r.form }

// Roster — перечень личностей модулей, объявленный установкой.
//
// Значение неизменяемо после сборки. Нулевое значение — «не объявлен»: по нему
// не признаётся никто.
type Roster struct {
	byPair map[string]Identity
	// anchors — сырые якоря центров по имени: сравнение цепочки — побайтовое,
	// по `Raw`, а не по имени субъекта, которое повторить может кто угодно.
	anchors map[string][][]byte
	// form — форма имени службы установки (kaname#308): ею из учётки каждой
	// записи читается короткое имя службы.
	form servicesan.Form
}

// pairKey — ключ пары. Косая черта в пространстве и учётке невозможна (их
// разбор её не пропускает), поэтому ключ однозначен.
func pairKey(namespace, account string) string { return namespace + "/" + account }

// EntryShape — форма записи перечня для текстов отказа и справки.
const EntryShape = "<namespace>/<service-account>=<profile>[@<issuer>]"

// Parse собирает перечень из записей установки без доверенных центров: запись,
// называющая центр, отвергается как называющая необъявленный.
//
// Форма имени службы — первый и обязательный довод у каждой сборки перечня:
// учётка записи читается ею, и сборка, забывшая её подставить, не соберётся
// вовсе, тогда как умолчание признало бы модулями учётки чужой формы.
func Parse(form servicesan.Form, entries []string) (Roster, error) {
	return ParseWithIssuers(form, entries, nil)
}

// ParseDeclared — суд записей БЕЗ чтения центров: форма каждой записи, единство
// пары и то, что названный записью центр объявлен по имени (issuerNames).
//
// Это суд стража настройки: он не читает файлов и потому судит профиль
// посадки на любой машине. Перечень, собранный им, якорей не несёт, и личность
// с привязкой по нему не признаётся — признаёт перечень [ParseWithIssuers],
// собранный из прочитанных центров.
func ParseDeclared(form servicesan.Form, entries []string, issuerNames []string) (Roster, error) {
	declared := make(map[string]bool, len(issuerNames))
	for _, n := range issuerNames {
		declared[n] = true
	}
	return parseRoster(form, entries, func(issuer string) bool { return declared[issuer] }, nil)
}

// ParseWithIssuers собирает перечень из записей установки и её прочитанных
// доверенных центров.
//
// Запись — [EntryShape]. Пробелы по краям срезаются, пустые записи
// отбрасываются: случайно пустая величина (`""` в переменной окружения) не
// должна становиться записью. Всякая иная неисправность — ошибка с названной
// записью: страж старта отвергает установку, а не признаёт меньше, чем она
// объявила. Центр, названный записью, обязан быть объявлен и нести хотя бы
// один якорь.
func ParseWithIssuers(form servicesan.Form, entries []string, issuers IssuerSet) (Roster, error) {
	anchors := make(map[string][][]byte, len(issuers))
	for name, certs := range issuers {
		for _, c := range certs {
			if c != nil && len(c.Raw) > 0 {
				anchors[name] = append(anchors[name], c.Raw)
			}
		}
	}
	return parseRoster(form, entries, func(issuer string) bool { return len(anchors[issuer]) > 0 }, anchors)
}

// parseRoster — общий разбор записей: known отвечает, объявлен ли центр.
//
// Запись при необъявленной либо незаконной форме имени службы — отказ: имя
// службы из её учётки прочесть нечем, а перечень, собранный мимо формы,
// признавал бы личность без домена записи. Отказ о самой форме выносит её
// страж (`servicesan.Form.Require`); здесь он лишь не даёт собрать перечень.
func parseRoster(form servicesan.Form, entries []string, known func(issuer string) bool, anchors map[string][][]byte) (Roster, error) {
	byPair := make(map[string]Identity, len(entries))
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		if !form.Valid() {
			return Roster{}, fmt.Errorf("module identity %q cannot be read: the service name form %s is "+
				"not declared or not valid, so no service name can be read from its account", entry, form.String())
		}
		id, err := parseEntry(form, entry)
		if err != nil {
			return Roster{}, err
		}
		if id.Issuer != "" && !known(id.Issuer) {
			return Roster{}, fmt.Errorf("module identity %q names the issuer %q, which the installation "+
				"has not declared (or declared without a single certificate): its leaf could never be "+
				"bound to the authority that issued it", entry, id.Issuer)
		}
		key := pairKey(id.Namespace, id.Account)
		if prev, dup := byPair[key]; dup {
			return Roster{}, fmt.Errorf("module identity %q is declared twice (profiles %q and %q): "+
				"one pair names one identity, and a second entry would leave its method list "+
				"undecided", key, prev.Profile, id.Profile)
		}
		byPair[key] = id
	}
	if len(byPair) == 0 {
		return Roster{}, nil
	}
	return Roster{byPair: byPair, anchors: anchors, form: form}, nil
}

// parseEntry разбирает одну непустую запись: учётку читает форма form.
func parseEntry(form servicesan.Form, entry string) (Identity, error) {
	pair, rest, found := strings.Cut(entry, "=")
	if !found {
		return Identity{}, fmt.Errorf("module identity %q carries no profile: write it as %s", entry, EntryShape)
	}
	ns, account, found := strings.Cut(pair, "/")
	if !found {
		return Identity{}, fmt.Errorf("module identity %q carries no namespace: write it as %s", entry, EntryShape)
	}
	if !isDNSLabel(ns) {
		return Identity{}, fmt.Errorf("module identity %q: namespace %q is not a cluster namespace name "+
			"(lower-case latin letters, digits and '-', starting and ending with a letter or a digit)", entry, ns)
	}
	if !isAccountName(account) {
		return Identity{}, fmt.Errorf("module identity %q: service account %q is not a cluster account name "+
			"(lower-case latin letters, digits, '-' and '.', starting and ending with a letter or a digit)", entry, account)
	}
	svc, ok := form.Service(account)
	if !ok {
		return Identity{}, fmt.Errorf("module identity %q: service account %q is not of the declared "+
			"service name form %q, so no service name can be read from it", entry, account, form.String())
	}
	profile, issuer, bound := strings.Cut(rest, "@")
	p := Profile(profile)
	if !p.known() {
		return Identity{}, fmt.Errorf("module identity %q: unknown profile %q (known: %s)", entry, profile, profileList())
	}
	if bound && !isDNSLabel(issuer) {
		return Identity{}, fmt.Errorf("module identity %q: issuer name %q is not a name "+
			"(lower-case latin letters, digits and '-', starting and ending with a letter or a digit)", entry, issuer)
	}
	return Identity{Namespace: ns, Account: account, Service: svc, Profile: p, Issuer: issuer}, nil
}

// profileList — словарь профилей строкой для текста отказа.
func profileList() string {
	names := make([]string, 0, len(Profiles()))
	for _, p := range Profiles() {
		names = append(names, string(p))
	}
	return strings.Join(names, ", ")
}

// IsDeclared — объявила ли установка хотя бы одну личность.
func (r Roster) IsDeclared() bool { return len(r.byPair) > 0 }

// Identities — объявленные личности в порядке пары: для самоотчёта и проб.
func (r Roster) Identities() []Identity {
	out := make([]Identity, 0, len(r.byPair))
	for _, id := range r.byPair {
		out = append(out, id)
	}
	sort.Slice(out, func(i, j int) bool {
		return pairKey(out[i].Namespace, out[i].Account) < pairKey(out[j].Namespace, out[j].Account)
	})
	return out
}

// pair — личность по разобранному идентификатору, без суда о выпустившем.
func (r Roster) pair(d grpcsrv.TrustDomain, san string) (Identity, bool) {
	ns, account, ok := ParseSAN(d, san)
	if !ok {
		return Identity{}, false
	}
	id, ok := r.byPair[pairKey(ns, account)]
	return id, ok
}

// Lookup — признание идентификатора san, впущенного доменом d, когда цепочки
// листа под рукой нет.
//
// Личность с привязкой к центру (kaname#988) здесь НЕ признаётся: без
// проверенной цепочки нечем доказать, что лист выпустил её центр, а признать её
// по одному имени значило бы снять привязку на этом пути. Ложь — идентификатор
// формы не имеет, его пары нет в перечне либо личность привязана к центру.
func (r Roster) Lookup(d grpcsrv.TrustDomain, san string) (Identity, bool) {
	id, ok := r.pair(d, san)
	if !ok || id.Issuer != "" {
		return Identity{}, false
	}
	return id, true
}

// Declares — объявлена ли установкой пара идентификатора san домена d: суд
// стража старта над записью конфигурации, а не признание вызывающего.
//
// Привязку к выпустившему центру здесь не судят: на старте листа нет, и
// записанный в настройке идентификатор ничьей цепочки не несёт. Ложь —
// идентификатор формы не имеет либо его пары нет в перечне.
func (r Roster) Declares(d grpcsrv.TrustDomain, san string) bool {
	_, ok := r.pair(d, san)
	return ok
}

// FromContext — признание вызывающего gRPC-слушателя: идентификатор
// ПРОВЕРЕННОГО клиентского листа, разобранный доменом, который его впустил, и —
// у личности с привязкой — проверенная цепочка, оканчивающаяся якорем её
// центра (kaname#988).
//
// Непроверенный пир, пустой идентификатор, пара вне перечня и лист чужого
// доверенного центра — не модуль.
func (r Roster) FromContext(ctx context.Context) (Identity, bool) {
	san, verified := grpcsrv.CertIdentityFromContext(ctx)
	if !verified || san == "" {
		return Identity{}, false
	}
	id, ok := r.pair(grpcsrv.CertIdentityDomainFromContext(ctx), san)
	if !ok {
		return Identity{}, false
	}
	if id.Issuer == "" {
		return id, true
	}
	if !r.issuedBy(id.Issuer, peerVerifiedChains(ctx)) {
		return Identity{}, false
	}
	return id, true
}

// FromTLSState — признание пира HTTP-слушателя: URI SAN нашего домена с
// проверенного листа и — у личности с привязкой — цепочка до якоря её центра.
// Тот же суд, что [Roster.FromContext], на состоянии рукопожатия.
func (r Roster) FromTLSState(d grpcsrv.TrustDomain, st *tls.ConnectionState) (Identity, bool) {
	if st == nil || len(st.VerifiedChains) == 0 || len(st.VerifiedChains[0]) == 0 {
		return Identity{}, false
	}
	san := d.CertIdentity(st.VerifiedChains[0][0])
	if san == "" {
		return Identity{}, false
	}
	id, ok := r.pair(d, san)
	if !ok {
		return Identity{}, false
	}
	if id.Issuer != "" && !r.issuedBy(id.Issuer, st.VerifiedChains) {
		return Identity{}, false
	}
	return id, true
}

// issuedBy — оканчивается ли хотя бы одна проверенная цепочка якорем центра
// issuer. Якорь — последний сертификат цепочки, которую построил слушатель от
// своего пула доверенных центров; сравнение побайтовое.
func (r Roster) issuedBy(issuer string, chains [][]*x509.Certificate) bool {
	anchors := r.anchors[issuer]
	for _, chain := range chains {
		if len(chain) == 0 {
			continue
		}
		root := chain[len(chain)-1]
		for _, a := range anchors {
			if bytes.Equal(root.Raw, a) {
				return true
			}
		}
	}
	return false
}

// peerVerifiedChains — проверенные слушателем цепочки пира gRPC-вызова.
// Пусто — пира без проверенной цепочки нет (открытый текст, лист не
// предъявлен либо не проверен).
func peerVerifiedChains(ctx context.Context) [][]*x509.Certificate {
	p, ok := peer.FromContext(ctx)
	if !ok || p.AuthInfo == nil {
		return nil
	}
	info, ok := p.AuthInfo.(credentials.TLSInfo)
	if !ok {
		return nil
	}
	return info.State.VerifiedChains
}

// Gate — вход стража перечня: имя ручки для текста отказа.
type Gate struct {
	Knob string
}

// Require — страж перечня боевой посадки: отказ старта, когда установка не
// объявила ни одной личности.
//
// По пустому перечню не признаётся никто: каждый вызов модуля, край в том
// числе, отвергается отказом, неотличимым от вызова без личности. Поднявшийся в
// таком состоянии процесс выглядел бы исправным и не обслуживал бы никого.
func (r Roster) Require(g Gate) error {
	if r.IsDeclared() {
		return nil
	}
	return fmt.Errorf("%s is empty: the installation has not declared its module identities, so no "+
		"client certificate is recognized as a module — every module call is refused, the edge "+
		"included; list each module as %s (profiles: %s)", g.Knob, EntryShape, profileList())
}

// RequireIssuerBinding — страж привязки боевой посадки (kaname#988): каждая
// объявленная личность называет центр, который вправе выпускать её лист.
//
// Без привязки доверие ко всем объявленным центрам общее: лист с допустимым
// SAN признаётся, какой бы из доверенных центров его ни выпустил, и разделение
// «лист края — только от центра края» держится на порядке выпуска, а не на
// проверке. Отказ называет каждую непривязанную личность.
func (r Roster) RequireIssuerBinding(g Gate) error {
	var unbound []string
	for _, id := range r.Identities() {
		if id.Issuer == "" {
			unbound = append(unbound, pairKey(id.Namespace, id.Account))
		}
	}
	if len(unbound) == 0 {
		return nil
	}
	return fmt.Errorf("%s: module identities %s name no issuer, so a leaf carrying their SAN is "+
		"recognized whichever trusted authority issued it; bind each one to its authority as %s",
		g.Knob, strings.Join(unbound, ", "), EntryShape)
}

// isDNSLabel — имя пространства кластера: строчные латинские, цифры и `-`, на
// краях буква или цифра, не длиннее 63.
func isDNSLabel(s string) bool {
	if s == "" || len(s) > 63 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isAlnum(c):
		case c == '-' && i > 0 && i < len(s)-1:
		default:
			return false
		}
	}
	return true
}

// isAccountName — имя учётки кластера: строчные латинские, цифры, `-` и `.`, на
// краях буква или цифра, не длиннее 253.
func isAccountName(s string) bool {
	if s == "" || len(s) > 253 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case isAlnum(c):
		case (c == '-' || c == '.') && i > 0 && i < len(s)-1:
		default:
			return false
		}
	}
	return true
}

// isAlnum — строчная латинская буква или цифра.
func isAlnum(c byte) bool {
	return (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
}

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
	"context"
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/corelib/grpcsrv"
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

// AccountPrefix — приставка учётки модуля: `<приставка><служба>`. Из учётки,
// а не из отдельной величины, выводится короткое имя службы — по нему решают
// домен записи отношений и идентификатор служебной учётки модуля.
const AccountPrefix = "kacho-"

// saInfix — сегмент пути идентификатора, за которым стоит учётка.
const saInfix = "/sa/"

// Identity — признанная личность модуля.
type Identity struct {
	// Namespace — пространство имён, как его назвал сертификат.
	Namespace string
	// Account — служебная учётка целиком.
	Account string
	// Service — короткое имя службы, выведенное из учётки (`vpc`, `api-gateway`).
	Service string
	// Profile — профиль, объявленный установкой для этой пары.
	Profile Profile
}

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

// ServiceFromAccount — короткое имя службы, которое несёт учётка модуля. Ложь —
// учётка приставки модулей не несёт либо имя службы в ней пусто.
func ServiceFromAccount(account string) (string, bool) {
	svc, ok := strings.CutPrefix(account, AccountPrefix)
	if !ok || svc == "" {
		return "", false
	}
	return svc, true
}

// Roster — перечень личностей модулей, объявленный установкой.
//
// Значение неизменяемо после сборки. Нулевое значение — «не объявлен»: по нему
// не признаётся никто.
type Roster struct {
	byPair map[string]Identity
}

// pairKey — ключ пары. Косая черта в пространстве и учётке невозможна (их
// разбор её не пропускает), поэтому ключ однозначен.
func pairKey(namespace, account string) string { return namespace + "/" + account }

// EntryShape — форма записи перечня для текстов отказа и справки.
const EntryShape = "<namespace>/<service-account>=<profile>"

// Parse собирает перечень из записей установки.
//
// Запись — [EntryShape]. Пробелы по краям срезаются, пустые записи
// отбрасываются: случайно пустая величина (`""` в переменной окружения) не
// должна становиться записью. Всякая иная неисправность — ошибка с названной
// записью: страж старта отвергает установку, а не признаёт меньше, чем она
// объявила.
func Parse(entries []string) (Roster, error) {
	byPair := make(map[string]Identity, len(entries))
	for _, raw := range entries {
		entry := strings.TrimSpace(raw)
		if entry == "" {
			continue
		}
		id, err := parseEntry(entry)
		if err != nil {
			return Roster{}, err
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
	return Roster{byPair: byPair}, nil
}

// parseEntry разбирает одну непустую запись.
func parseEntry(entry string) (Identity, error) {
	pair, profile, found := strings.Cut(entry, "=")
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
	svc, ok := ServiceFromAccount(account)
	if !ok {
		return Identity{}, fmt.Errorf("module identity %q: service account %q does not carry the module "+
			"prefix %q followed by the service name, so no service name can be read from it", entry, account, AccountPrefix)
	}
	p := Profile(profile)
	if !p.known() {
		return Identity{}, fmt.Errorf("module identity %q: unknown profile %q (known: %s)", entry, profile, profileList())
	}
	return Identity{Namespace: ns, Account: account, Service: svc, Profile: p}, nil
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

// Lookup — признание идентификатора san, впущенного доменом d.
//
// Ложь — идентификатор формы не имеет либо его пары нет в перечне.
func (r Roster) Lookup(d grpcsrv.TrustDomain, san string) (Identity, bool) {
	ns, account, ok := ParseSAN(d, san)
	if !ok {
		return Identity{}, false
	}
	id, ok := r.byPair[pairKey(ns, account)]
	return id, ok
}

// FromContext — признание вызывающего gRPC-слушателя: идентификатор
// ПРОВЕРЕННОГО клиентского листа, разобранный доменом, который его впустил.
//
// Непроверенный пир, пустой идентификатор и пара вне перечня — не модуль.
func (r Roster) FromContext(ctx context.Context) (Identity, bool) {
	san, verified := grpcsrv.CertIdentityFromContext(ctx)
	if !verified || san == "" {
		return Identity{}, false
	}
	return r.Lookup(grpcsrv.CertIdentityDomainFromContext(ctx), san)
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

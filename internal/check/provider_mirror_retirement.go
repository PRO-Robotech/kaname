// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// provider_mirror_retirement.go — ГЕЙТ КЛАССА: поле контракта и вид словаря,
// живущие только ради снимаемого внешнего OAuth-сервера, ОБЪЯВЛЕНЫ уходящими
// ДО ломающего изменения, а решение об их снятии записано и привязано к
// измеримому окну (эпик kacho#2564, линия B).
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ
//
// Имя прежнего издателя стоит ПОЛЕМ в двух сообщениях (`hydra_client_id`) и
// ВИДОМ в закрытом словаре (`CREDENTIAL_KIND_LEGACY`). Снять их — ломающее
// изменение с резервированием номера и имени, и идёт оно ПОСЛЕДНИМ в линии:
// пока в базе есть строки, чьё зеркало у прежнего издателя ещё предъявимо,
// снятие лишает эти строки имени, которым их резолвит его хук.
//
// «Последним» не значит «когда-нибудь». Подготовка снятия — три вещи, и все три
// проверяемы уже сегодня:
//
//  1. контракт ГОВОРИТ, что поле и вид уходят (`deprecated = true`): порождённые
//     клиенты видят это в типах, а не узнают из ломающего выпуска;
//  2. решение ЗАПИСАНО страницей архитектуры и называет окно, порядок и то, что
//     снимать НЕ будут;
//  3. окно ИЗМЕРЯЕТСЯ, а не оценивается: у строк с зеркалом есть ряд на витрине,
//     и страница называет его по имени константы производителя.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ СУДЯТСЯ ДЕСКРИПТОРЫ, А НЕ ТЕКСТ `.proto`
//
// `deprecated` живёт в опциях поля; текст `.proto` его несёт, но несёт и в
// комментариях («поле не deprecated намеренно»), и в чужих файлах того же
// каталога. Порождённый дескриптор — то, что видит клиент, и то, что
// регистрируется при `init`; судить его значит судить контракт, а не его
// написание. Поле, снятое из сообщения вовсе (а не помеченное), — ТОЖЕ находка:
// снятие без резервирования и есть ломающее изменение, которое гейт стережёт.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧЕГО ГЕЙТ НЕ УТВЕРЖДАЕТ
//
// Он не судит, что окно закрыто, и не судит правильность самого решения: первое
// — величина базы стенда, второе — прочтение человеком. Он держит согласие трёх
// мест (контракт · страница · производитель величины) и краснеет, когда любое
// из них разойдётся с двумя другими.
package check

import (
	"fmt"
	"sort"
	"strings"

	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// ProviderMirrorRetirementPageRel — страница решения о снятии.
const ProviderMirrorRetirementPageRel = "docs/engineering/architecture/provider-mirror-column-retirement.md"

// ProviderMirrorFieldName — поле контракта, несущее имя прежнего издателя.
const ProviderMirrorFieldName = "hydra_client_id"

// ProviderMirrorMessages — сообщения, несущие это поле. Оба, поимённо: перечень
// закрыт, и появление третьего носителя — находка соседней оси (само поле там
// быть не должно), а не пополнение этого перечня.
var ProviderMirrorMessages = []protoreflect.FullName{
	"kaname.cloud.iam.v1.ServiceAccountOAuthClient",
	"kaname.cloud.iam.v1.UserOAuthClient",
}

// ProviderMirrorEnum и ProviderMirrorLegacyValue — вид словаря, описывающий
// строку прежнего потока.
const (
	ProviderMirrorEnum        protoreflect.FullName = "kaname.cloud.iam.v1.CredentialKind"
	ProviderMirrorLegacyValue protoreflect.Name     = "CREDENTIAL_KIND_LEGACY"
)

// ProviderMirrorFinding — одно расхождение трёх мест.
type ProviderMirrorFinding struct {
	// Kind — вид расхождения: `field-missing` · `field-not-deprecated` ·
	// `enum-missing` · `value-missing` · `value-not-deprecated` · `page-missing` ·
	// `page-silent`.
	Kind    string
	Subject string
	Detail  string
}

func (f ProviderMirrorFinding) String() string {
	return fmt.Sprintf("%s: %s — %s", f.Kind, f.Subject, f.Detail)
}

// ProviderMirrorCensus — объём осмотренного.
type ProviderMirrorCensus struct {
	MessagesFound int
	FieldsFound   int
	EnumFound     bool
	ValueFound    bool
	PageBytes     int
	TermsRequired int
	TermsNamed    int
}

func (c ProviderMirrorCensus) String() string {
	return fmt.Sprintf("перепись: сообщений найдено %d из %d · полей %d · словарь %v · вид %v · "+
		"страница %d байт · терминов обязательных %d, названо %d",
		c.MessagesFound, len(ProviderMirrorMessages), c.FieldsFound, c.EnumFound, c.ValueFound,
		c.PageBytes, c.TermsRequired, c.TermsNamed)
}

// JudgeProviderMirrorContract — контракт ОБЪЯВЛЯЕТ уходящее уходящим.
//
// Дескрипторы приходят реестром, а не именами файлов: инъекция подаёт
// синтетический реестр, дерево — глобальный.
func JudgeProviderMirrorContract(files *protoregistry.Files) ([]ProviderMirrorFinding, ProviderMirrorCensus) {
	var (
		out    []ProviderMirrorFinding
		census ProviderMirrorCensus
	)
	for _, name := range ProviderMirrorMessages {
		d, err := files.FindDescriptorByName(name)
		if err != nil {
			out = append(out, ProviderMirrorFinding{"message-missing", string(name),
				"сообщение не зарегистрировано — контракт переехал или переименован"})
			continue
		}
		md, ok := d.(protoreflect.MessageDescriptor)
		if !ok {
			out = append(out, ProviderMirrorFinding{"message-missing", string(name), "имя занято не сообщением"})
			continue
		}
		census.MessagesFound++
		fd := md.Fields().ByName(protoreflect.Name(ProviderMirrorFieldName))
		if fd == nil {
			out = append(out, ProviderMirrorFinding{"field-missing", string(name) + "." + ProviderMirrorFieldName,
				"поле снято из сообщения — это ломающее изменение, и идёт оно последним, с " +
					"резервированием номера и имени; пока окно не закрыто, поле обязано остаться"})
			continue
		}
		census.FieldsFound++
		if !fd.Options().(interface{ GetDeprecated() bool }).GetDeprecated() {
			out = append(out, ProviderMirrorFinding{"field-not-deprecated", string(name) + "." + ProviderMirrorFieldName,
				"поле не объявлено уходящим (`deprecated = true`): порождённый клиент узнает о " +
					"снятии только из ломающего выпуска"})
		}
	}

	ed, err := files.FindDescriptorByName(ProviderMirrorEnum)
	if err != nil {
		out = append(out, ProviderMirrorFinding{"enum-missing", string(ProviderMirrorEnum), "словарь не зарегистрирован"})
		return out, census
	}
	enum, ok := ed.(protoreflect.EnumDescriptor)
	if !ok {
		out = append(out, ProviderMirrorFinding{"enum-missing", string(ProviderMirrorEnum), "имя занято не словарём"})
		return out, census
	}
	census.EnumFound = true
	vd := enum.Values().ByName(ProviderMirrorLegacyValue)
	if vd == nil {
		out = append(out, ProviderMirrorFinding{"value-missing", string(ProviderMirrorEnum) + "." + string(ProviderMirrorLegacyValue),
			"вид снят из словаря — снятие идёт вместе с полем, последним, с резервированием " +
				"номера и имени; пока строки этого вида есть, вид обязан остаться"})
		return out, census
	}
	census.ValueFound = true
	if !vd.Options().(interface{ GetDeprecated() bool }).GetDeprecated() {
		out = append(out, ProviderMirrorFinding{"value-not-deprecated", string(ProviderMirrorEnum) + "." + string(ProviderMirrorLegacyValue),
			"вид не объявлен уходящим (`deprecated = true`)"})
	}
	return out, census
}

// JudgeProviderMirrorPage — страница решения СУЩЕСТВУЕТ и называет каждый
// обязательный термин: таблицы окна, поле, вид и ряд витрины по имени константы
// производителя.
//
// Термины приходят параметром, а не выписываются здесь: имя ряда — константа
// пакета величин, и второе место об одном имени разошлось бы молча.
func JudgeProviderMirrorPage(body string, required []string) ([]ProviderMirrorFinding, ProviderMirrorCensus) {
	census := ProviderMirrorCensus{PageBytes: len(body), TermsRequired: len(required)}
	if strings.TrimSpace(body) == "" {
		return []ProviderMirrorFinding{{"page-missing", ProviderMirrorRetirementPageRel,
			"страницы решения нет либо она пуста — снятие без записанного решения неотличимо от забытого"}}, census
	}
	terms := append([]string(nil), required...)
	sort.Strings(terms)
	var out []ProviderMirrorFinding
	for _, term := range terms {
		if !strings.Contains(body, term) {
			out = append(out, ProviderMirrorFinding{"page-silent", term,
				"страница решения не называет этот предмет — окно, ряд или снимаемое имя остаются без записи"})
			continue
		}
		census.TermsNamed++
	}
	return out, census
}

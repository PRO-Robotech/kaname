// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// catalog_covers_contract.go — своя копия каталога прав покрывает СВОЙ контракт.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДМЕТ (kaname#184)
//
// Копия каталога прав в этом дереве — порождённый артефакт: её строки край
// порождает из контрактов всех доменов, и строки ЭТОЙ службы — из её же
// контракта по пину модуля. Сверка копий (`catalog_copy_parity.go`) судит
// равенство ДВУХ копий, и только его; о том, покрывает ли наша копия наш
// собственный контракт, она не утверждает ничего — пока край пинит ревизию без
// нового глагола, обе копии его не несут, и сверка зелена.
//
// Ровно так строка `InternalHumanSessionService/Resolve` осталась без предмета:
// контракт объявил глагол (kaname#179), обе копии молчали, обе сверки были
// зелены, и красное ждало подъёма пина платформой — то есть наступило бы в
// ЧУЖОМ дереве, чужим прогоном, на всяком следующем PR этой службы.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО УТВЕРЖДАЕТСЯ — В ОБЕ СТОРОНЫ, И ТОЛЬКО О СВОЁМ
//
//  1. У каждого RPC, объявленного файлами контракта службы, есть строка в копии,
//     и строка совпадает с аннотациями метода по каждой оси, которую каталог
//     несёт. Строка без источника — находка: она пережила свой RPC.
//  2. Строки ЧУЖИХ доменов не судятся вовсе: их источник живёт в чужом дереве,
//     и «строка без RPC» для них означает лишь, что стабы чужого домена в этот
//     двоичный файл не слинкованы. Судить их отсюда было бы утверждением о
//     дереве, которого здесь нет.
//
// Перечень своих пакетов ВЫВОДИТСЯ из обхода (пакет каждого файла контракта), а
// не выписывается: выписанный был бы вторым объявлением того же предмета.
//
// Обход, не нашедший НИ ОДНОГО метода, — не «ноль находок», а ТРЕТИЙ ИСХОД:
// стабы не слинкованы либо приставка пути названа неверно, и гейт в таком
// состоянии не утверждает ничего. То же — пустая копия.
//
// ─────────────────────────────────────────────────────────────────────────────
// ЧТО ДЕЛАТЬ НА НАХОДКЕ — И ПОЧЕМУ НЕ РУКАМИ
//
// Строка ПОРОЖДАЕТСЯ генератором края над контрактом службы (в дереве платформы
// `gateway/scripts/gen-permission-catalog.sh` с модулем службы, разрешённым на
// нужную ревизию), кладётся в копию и, пока край её не несёт, объявляется
// записью ведомости ожидающих края (`CatalogPendingEntries`,
// `catalog_copy_parity.go`). Правка JSON руками исходом не является: копия —
// порождаемый артефакт, и рукописная строка разошлась бы с тем, что край породит
// по пину, ровно на первой сверке после подъёма.
package check

import (
	"fmt"
	"sort"
	"strings"

	"github.com/PRO-Robotech/corelib/authz/catalogderive"
	"google.golang.org/protobuf/reflect/protoreflect"
	"google.golang.org/protobuf/reflect/protoregistry"
)

// ContractMethod — один RPC контракта: полное имя в форме каталога
// (`<пакет>.<Служба>/<Метод>`, без ведущей косой черты) и его аннотации.
type ContractMethod struct {
	FullMethod  string
	Package     string
	Annotations catalogderive.Annotations
}

// OwnContractMethods — RPC всех файлов контракта, зарегистрированных в этом
// двоичном файле под названной приставкой пути (`kaname/` — корень контрактов
// службы в её дереве `proto/`). Возвращает методы, отсортированные по имени, и
// число осмотренных файлов — отдельно, чтобы «ноль методов» было отличимо от
// «ноль файлов».
func OwnContractMethods(pathPrefix string) (methods []ContractMethod, files int) {
	protoregistry.GlobalFiles.RangeFiles(func(fd protoreflect.FileDescriptor) bool {
		if !strings.HasPrefix(fd.Path(), pathPrefix) {
			return true
		}
		files++
		for i := 0; i < fd.Services().Len(); i++ {
			sd := fd.Services().Get(i)
			for j := 0; j < sd.Methods().Len(); j++ {
				md := sd.Methods().Get(j)
				methods = append(methods, ContractMethod{
					FullMethod:  string(sd.FullName()) + "/" + string(md.Name()),
					Package:     string(fd.Package()),
					Annotations: catalogderive.AnnotationsOf(md),
				})
			}
		}
		return true
	})
	sort.Slice(methods, func(i, j int) bool { return methods[i].FullMethod < methods[j].FullMethod })
	return methods, files
}

// CatalogCoverageCensus — объём осмотренного. Печатается независимо от исхода.
type CatalogCoverageCensus struct {
	// Methods — RPC контракта, осмотренных обходом.
	Methods int
	// Packages — своих proto-пакетов, выведенных из обхода.
	Packages int
	// Rows — строк в копии всего.
	Rows int
	// OwnRows — из них строк своих пакетов (только они и судятся).
	OwnRows int
}

// String — перепись одной строкой.
func (c CatalogCoverageCensus) String() string {
	return fmt.Sprintf("перепись: RPC контракта %d в %d пакетах · строк в копии %d · из них своих %d",
		c.Methods, c.Packages, c.Rows, c.OwnRows)
}

// CompareCatalogWithContract — сверка копии с контрактом. Возвращает находки
// (пустой перечень = зелёное) и перепись. Ошибка — ТРЕТИЙ ИСХОД: сверять было
// нечего, вердикта о покрытии НЕТ.
func CompareCatalogWithContract(rows []catalogderive.Entry, methods []ContractMethod) ([]string, CatalogCoverageCensus, error) {
	census := CatalogCoverageCensus{Methods: len(methods), Rows: len(rows)}
	if len(methods) == 0 {
		return nil, census, fmt.Errorf("обход контракта не дал ни одного RPC — стабы не слинкованы либо приставка пути названа неверно; о покрытии вердикта нет")
	}
	if len(rows) == 0 {
		return nil, census, fmt.Errorf("копия каталога пуста — о покрытии вердикта нет")
	}

	ownPackages := make(map[string]bool, 1)
	for _, m := range methods {
		ownPackages[m.Package] = true
	}
	census.Packages = len(ownPackages)

	byFQN := make(map[string]catalogderive.Entry, len(rows))
	for _, r := range rows {
		byFQN[r.FQN] = r
		if ownPackages[packageOfFQN(r.FQN)] {
			census.OwnRows++
		}
	}

	var findings []string
	seen := make(map[string]bool, len(methods))
	for _, m := range methods {
		seen[m.FullMethod] = true
		row, ok := byFQN[m.FullMethod]
		if !ok {
			findings = append(findings, fmt.Sprintf(
				"%s: RPC объявлен контрактом службы, а строки в нашей копии нет — копия отстала от "+
					"СОБСТВЕННОГО контракта. Строка порождается генератором края над этим контрактом и, "+
					"пока край её не несёт, объявляется записью ведомости ожидающих края "+
					"(CatalogPendingEntries, internal/check/catalog_copy_parity.go); правка JSON руками "+
					"исходом не является. kaname#184", m.FullMethod))
			continue
		}
		findings = append(findings, diffAnnotationsAgainstRow(m.FullMethod, m.Annotations, row)...)
	}
	for _, r := range rows {
		if ownPackages[packageOfFQN(r.FQN)] && !seen[r.FQN] {
			findings = append(findings, fmt.Sprintf(
				"%s: строка в нашей копии есть, а RPC с таким именем контракт службы не объявляет — "+
					"строка пережила свой источник; перегенерировать копию, а не править руками", r.FQN))
		}
	}
	sort.Strings(findings)
	return findings, census, nil
}

// packageOfFQN — proto-пакет по полному имени метода формы каталога:
// `a.b.v1.Service/Method` → `a.b.v1`. Имя без косой черты либо без точки в
// сегменте службы пакета не имеет — возвращается пустая строка, и такая строка
// своей не считается.
func packageOfFQN(fqn string) string {
	slash := strings.IndexByte(fqn, '/')
	if slash < 0 {
		return ""
	}
	service := fqn[:slash]
	dot := strings.LastIndexByte(service, '.')
	if dot < 0 {
		return ""
	}
	return service[:dot]
}

// diffAnnotationsAgainstRow — одна аннотация против одной строки по всем осям,
// которые каталог несёт; та же форма, что у гейта края.
func diffAnnotationsAgainstRow(fqn string, a catalogderive.Annotations, row catalogderive.Entry) []string {
	var out []string
	add := func(axis, want, got string) {
		out = append(out, fmt.Sprintf("%s: %s — аннотация %q, копия %q", fqn, axis, want, got))
	}
	if a.Permission != row.Permission {
		add("permission", a.Permission, row.Permission)
	}
	if a.RequiredRelation != row.RequiredRelation {
		add("required_relation", a.RequiredRelation, row.RequiredRelation)
	}
	if a.ScopeObjectType != row.ScopeExtractor.ObjectType {
		add("scope_extractor.object_type", a.ScopeObjectType, row.ScopeExtractor.ObjectType)
	}
	if a.ScopeFromRequestField != row.ScopeExtractor.FromRequestField {
		add("scope_extractor.from_request_field", a.ScopeFromRequestField, row.ScopeExtractor.FromRequestField)
	}
	if a.ScopeObjectTypeFromRequest != row.ScopeExtractor.ObjectTypeFromRequestField {
		add("scope_extractor.object_type_from_request_field",
			a.ScopeObjectTypeFromRequest, row.ScopeExtractor.ObjectTypeFromRequestField)
	}
	if a.HideExistence != row.HideExistence {
		add("hide_existence", fmt.Sprint(a.HideExistence), fmt.Sprint(row.HideExistence))
	}
	if a.ScopeFiltered != row.ScopeFiltered {
		add("scope_filtered", fmt.Sprint(a.ScopeFiltered), fmt.Sprint(row.ScopeFiltered))
	}
	return out
}

// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// servicesubjectwriter_injection_test.go — гейт писателя служебного субъекта
// краснеет на ВТОРОМ писателе каждой законной формы производства и молчит на
// законных близнецах той же формы.
package check_test

import (
	"strings"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/check"
)

func serviceSubjectScan(t *testing.T, rel, src string) ([]check.ServiceSubjectSite, check.ServiceSubjectCensus) {
	t.Helper()
	sites, census, err := check.ScanServiceSubjectProducers(rel, []byte(src))
	if err != nil {
		t.Fatalf("разбор инъекции %s: %v", rel, err)
	}
	return sites, census
}

// secondWriter — тенантская поверхность, куда инъекция кладёт второго писателя.
const secondWriter = "internal/apps/kaname/api/access_binding/tuples.go"

func TestServiceSubjectWriterGateRedsOnEverySecondWriterForm(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name, form, src string
	}{
		{
			name: "вызов authz.ServiceSubject",
			form: check.FormServiceSubjectCall,
			src: `package access_binding
import "github.com/PRO-Robotech/corelib/authz"
func subject(n string) string { return authz.ServiceSubject(grpcsrv.ServiceName(n)) }
`,
		},
		{
			name: "вызов под другим именем импорта",
			form: check.FormServiceSubjectCall,
			src: `package access_binding
import coreauthz "github.com/PRO-Robotech/corelib/authz"
func subject(n string) string { return coreauthz.ServiceSubject(grpcsrv.ServiceName(n)) }
`,
		},
		{
			name: "функция как значение",
			form: check.FormServiceSubjectCall,
			src: `package access_binding
import "github.com/PRO-Robotech/corelib/authz"
var make = authz.ServiceSubject
`,
		},
		{
			name: "тип субъекта authz.ServiceSubjectType",
			form: check.FormServiceSubjectType,
			src: `package access_binding
import "github.com/PRO-Robotech/corelib/authz"
func subject(n string) string { return authz.ServiceSubjectType + ":" + n }
`,
		},
		{
			name: "литерал service:",
			form: check.FormServiceLiteral,
			src: `package access_binding
func subject(n string) string { return "service:" + n }
`,
		},
		{
			name: "точечный импорт authz",
			form: check.FormDotImport,
			src: `package access_binding
import . "github.com/PRO-Robotech/corelib/authz"
func subject(n string) string { return ServiceSubject(n) }
`,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sites, census := serviceSubjectScan(t, secondWriter, tc.src)
			f := serviceSubjectFindings(sites)
			if len(f) == 0 {
				t.Fatalf("второй писатель формы %q НЕ стал находкой (перепись %+v)", tc.name, census)
			}
			if !strings.Contains(f[0], secondWriter) || !strings.Contains(f[0], tc.form) {
				t.Fatalf("находка не называет координату и форму %q: %v", tc.form, f)
			}
		})
	}
}

func TestServiceSubjectWriterGateStaysSilentOnLegalTwins(t *testing.T) {
	t.Parallel()

	t.Run("та же форма в РАЗРЕШЁННОМ файле применителя", func(t *testing.T) {
		sites, _ := serviceSubjectScan(t, check.ServiceSubjectWriterFile, `package moduleseed
import "github.com/PRO-Robotech/corelib/authz"
func tuple(n string) string { return authz.ServiceSubject(grpcsrv.ServiceName(n)) }
`)
		if len(sites) == 0 {
			t.Fatal("положительный контроль не выполнен: место производства в применителе не опознано")
		}
		if f := serviceSubjectFindings(sites); len(f) != 0 {
			t.Fatalf("гейт краснеет на разрешённом писателе: %v", f)
		}
	})

	t.Run("читатель authz.CallerSubject — не писатель", func(t *testing.T) {
		sites, census := serviceSubjectScan(t, secondWriter, `package access_binding
import "github.com/PRO-Robotech/corelib/authz"
func who(ctx context.Context) string { c, _ := authz.CallerSubject(ctx); return c.Subject() }
`)
		if census.AuthzSelectors == 0 {
			t.Fatalf("обращение к authz не прочитано — контроль не выполнен: %+v", census)
		}
		if f := serviceSubjectFindings(sites); len(f) != 0 {
			t.Fatalf("гейт краснеет на читателе второго носителя: %v", f)
		}
	})

	t.Run("сравнение с authz.ServiceSubjectType — чтение, не производство", func(t *testing.T) {
		sites, census := serviceSubjectScan(t, secondWriter, `package access_binding
import "github.com/PRO-Robotech/corelib/authz"
func refused(kind string) bool { return kind == authz.ServiceSubjectType }
`)
		if census.AuthzSelectors == 0 {
			t.Fatalf("обращение к authz не прочитано — контроль не выполнен: %+v", census)
		}
		if f := serviceSubjectFindings(sites); len(f) != 0 {
			t.Fatalf("гейт краснеет на сравнении со словом типа: %v", f)
		}
	})

	t.Run("слово service без разделителя и в комментарии", func(t *testing.T) {
		sites, census := serviceSubjectScan(t, secondWriter, `package access_binding
// Субъект "service:notify" производит только фундамент.
const kind = "service"
const account = "service_account:sva1"
`)
		if census.Strings == 0 {
			t.Fatalf("литералы не прочитаны — контроль не выполнен: %+v", census)
		}
		if f := serviceSubjectFindings(sites); len(f) != 0 {
			t.Fatalf("гейт краснеет на законном близнеце формы: %v", f)
		}
	})

	t.Run("чужой пакет с тем же именем authz", func(t *testing.T) {
		sites, _ := serviceSubjectScan(t, secondWriter, `package access_binding
import "github.com/PRO-Robotech/kaname/internal/authz"
func subject(n string) string { return authz.ServiceSubject(n) }
`)
		if f := serviceSubjectFindings(sites); len(f) != 0 {
			t.Fatalf("гейт судит имя пакета, а не путь импорта: %v", f)
		}
	})
}

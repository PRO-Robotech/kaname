// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

package publicauthzcensus_test

// census_injection_test.go — доказательство того, что гейт СПОСОБЕН упасть.
//
// Инъекция подаёт синтетический контракт и синтетическую точку регистрации,
// оставляя карту прав настоящей: подменить её нельзя by construction — она
// выводится из дескрипторов, влинкованных в процесс. Это и делает инъекцию
// одно-фактной: между двумя мирами меняется РОВНО ОДНО — покрыт ли подаваемый
// RPC дверью.
//
// Обе стороны обязательны. Без законного близнеца «краснеет» было бы неотличимо
// от гейта, краснеющего на всём; без дефекта — от гейта, молчащего на всём.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПРЕДПОСЫЛКА — ТА ЖЕ, ЧТО У СУДИМЫХ ГЕЙТОВ, И ЭТО ПОЧИНКА (#2479)
//
// Синтетическими здесь бывают только контракт и точка регистрации; ОБСЛУЖИВАЮЩИЙ
// ПАКЕТ разбор резолвит от корня дерева платформы координатой, которой в
// самостоятельном клоне нет. Корень брался собственным подъёмом до самого
// внешнего `go.mod`, и в клоне он находился — то есть инъекция ШЛА, но по
// обеднённому миру: файлов Go разобрано 0, а вердикт всё равно «PASS».
//
// Для службы, уезжающей отдельным продуктом, это худший из исходов: снаружи
// остаётся ЗЕЛЁНОЕ ДОКАЗАТЕЛЬСТВО БЕЗ ПРЕДМЕТА — оно утверждает, что гейт
// способен упасть, проверив это на входе, которого в той посадке не бывает.
//
// Чинится с обеих сторон, и обе половины несущие:
//
//	корень берётся `platformtree.Require` — тем же резолвом, что у судимых
//	гейтов, поэтому в клоне инъекция ПРОПУСКАЕТСЯ вместе с ними, а не идёт
//	по пустому миру;
//	обе оси переписи стерегутся — «осмотрено» И «разобрано». Первая одна
//	молчит ровно о том случае, ради которого перепись печатает обе величины.

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/PRO-Robotech/kaname/internal/publicauthzcensus"

	"github.com/PRO-Robotech/kaname/internal/testsupport/platformtree"
)

// synthTree кладёт синтетический контракт и точку регистрации в свой каталог и
// возвращает пути к ним.
//
// Служба называется параметром: имя решает всё. Настоящая (`ProjectService`)
// покрыта выведенной картой, выдуманная — нет.
func synthTree(t *testing.T, service, method string) (protoDir, cmdDir string) {
	t.Helper()
	base := t.TempDir()
	protoDir = filepath.Join(base, "proto")
	cmdDir = filepath.Join(base, "cmd")
	for _, d := range []string{protoDir, cmdDir} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("создать %s: %v", d, err)
		}
	}
	proto := "syntax = \"proto3\";\npackage kaname.cloud.iam.v1;\n\n" +
		"service " + service + " {\n  rpc " + method + "(Req) returns (Res);\n}\n"
	if err := os.WriteFile(filepath.Join(protoDir, "synth.proto"), []byte(proto), 0o644); err != nil {
		t.Fatalf("записать контракт: %v", err)
	}
	// Точка регистрации: та же форма, что читает перепись у настоящей.
	reg := "package main\n\n" +
		// Импорт обязателен: перепись разрешает поле сборки в каталог пакета
		// через алиас, и без него обработчик не резолвится — то есть фикстура
		// подала бы «не разрешилось» вместо предмета инъекции.
		"import (\n\tsynthapp \"github.com/PRO-Robotech/kaname/internal/apps/kaname/api/project\"\n)\n\n" +
		"type services struct {\n\tsynthHandler *synthapp.Handler\n}\n\n" +
		"func registerPublicServices(srv grpc.ServiceRegistrar, svcs *services) {\n" +
		"\tiamv1.Register" + service + "Server(srv, svcs.synthHandler)\n}\n"
	if err := os.WriteFile(filepath.Join(cmdDir, "register.go"), []byte(reg), 0o644); err != nil {
		t.Fatalf("записать регистрацию: %v", err)
	}
	return protoDir, cmdDir
}

// ДЕФЕКТ: публичный RPC, которого выведенная карта не знает, — находка.
func TestCensusGateFiresOnAnRPCTheDoorDoesNotCover(t *testing.T) {
	protoDir, cmdDir := synthTree(t, "SynthTenantService", "StealTheNeighboursProject")

	c, err := publicauthzcensus.CollectFrom(protoDir, cmdDir, platformtree.Require(t))
	if err != nil {
		t.Fatalf("перепись не состоялась: %v", err)
	}
	t.Log(c.Summary())

	if c.Inspected == 0 {
		t.Fatal("обход пуст: инъекция не подана — вердикт беспредметен")
	}
	if c.GoFiles == 0 {
		t.Fatal("обход пуст: файлов Go разобрано 0 — обслуживающий пакет не резолвится, " +
			"и красное пришло бы по обеднённому миру, а не по поданному дефекту")
	}
	found := false
	for _, r := range c.InCategory(publicauthzcensus.CategoryUngated) {
		if r.String() == "SynthTenantService/StealTheNeighboursProject" {
			found = true
		}
	}
	if !found {
		t.Fatalf("гейт НЕ назвал RPC без двери: категория «БЕЗ двери» = %v",
			c.InCategory(publicauthzcensus.CategoryUngated))
	}
	// Находка обязана НАЗЫВАТЬ координату, а не только считаться: разбор по
	// числу невозможен, и гейт, печатающий одно число, снимают как непонятный.
	for _, v := range c.Verdicts {
		if v.RPC.String() == "SynthTenantService/StealTheNeighboursProject" && v.Evidence == "" {
			t.Error("находка не называет причину")
		}
	}
}

// ЗАКОННЫЙ БЛИЗНЕЦ: та же форма у службы, которую дверь покрывает, — молчание.
//
// Отличается от мира выше РОВНО ОДНИМ фактом — именем службы, то есть тем,
// покрыта ли она выведенной картой. Всё прочее (форма контракта, форма
// регистрации, каталоги) побайтово то же.
func TestCensusGateStaysSilentOnACoveredRPC(t *testing.T) {
	protoDir, cmdDir := synthTree(t, "ProjectService", "Get")

	c, err := publicauthzcensus.CollectFrom(protoDir, cmdDir, platformtree.Require(t))
	if err != nil {
		t.Fatalf("перепись не состоялась: %v", err)
	}
	t.Log(c.Summary())

	if c.Inspected == 0 {
		t.Fatal("обход пуст: близнец не подан — молчание беспредметно")
	}
	if c.GoFiles == 0 {
		t.Fatal("обход пуст: файлов Go разобрано 0 — обслуживающий пакет не резолвится, " +
			"и молчание близнеца доказывало бы лишь то, что судить было нечего")
	}
	if n := c.Count(publicauthzcensus.CategoryUngated); n != 0 {
		t.Errorf("гейт краснеет на покрытом RPC: «БЕЗ двери» = %d (%v)",
			n, c.InCategory(publicauthzcensus.CategoryUngated))
	}
	if c.Count(publicauthzcensus.CategoryDoor) == 0 {
		t.Error("покрытый RPC не отнесён к двери: гейт молчит не поэтому")
	}
}

// ПУСТОЙ ОБХОД — беспредметен, а не чист.
//
// Без этого утверждения перепись без единого RPC печатала бы «БЕЗ двери 0» и
// читалась бы как достижение: «ноль находок» обязано быть отличимо от «ноль
// прочитанного».
func TestCensusRefusesAnEmptyContract(t *testing.T) {
	base := t.TempDir()
	protoDir := filepath.Join(base, "proto")
	if err := os.MkdirAll(protoDir, 0o755); err != nil {
		t.Fatalf("создать каталог: %v", err)
	}
	_, err := publicauthzcensus.CollectFrom(protoDir, filepath.Join(base, "cmd"), platformtree.Require(t))
	if err == nil {
		t.Fatal("перепись без контракта не отказала: пустой обход принят за чистый")
	}
}

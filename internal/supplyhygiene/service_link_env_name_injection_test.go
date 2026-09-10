// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// service_link_env_name_injection_test.go — способность меры упасть и смолчать
// доказывается ИНЪЕКЦИЕЙ, а не прочтением.
//
// Осей четыре, и по каждой стоит ЗАКОННЫЙ БЛИЗНЕЦ, отличающийся от дефекта
// РОВНО ОДНИМ фактом:
//
//	имя         — то же имя, но объявленное в перечне ручек → молчит;
//	разделитель — то же имя с `__` (выведено из пути ключа) → молчит;
//	охват       — то же имя в тестовом файле → молчит;
//	узел        — то же имя в КОММЕНТАРИИ, а не в литерале → молчит.
//
// Последняя ось несущая: без неё мера могла бы искать подстроку, и тогда она
// краснела бы на собственном объяснении — в этом дереве такие имена стоят в
// комментариях, разбирающих этот самый класс.
package supplyhygiene

import (
	"os"
	"path/filepath"
	"testing"
)

// synthModule — синтетический модуль: один файл с заданным телом. Один факт
// различия задаётся параметрами.
func synthModule(t *testing.T, fileName, body string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, "internal", "wiring")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("фикстура не собрана: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, fileName), []byte(body), 0o600); err != nil {
		t.Fatalf("фикстура не собрана: %v", err)
	}
	return root
}

// readsEnv — тело прод-файла, читающего названную переменную.
func readsEnv(name string) string {
	return "package wiring\n\nimport \"os\"\n\nfunc knob() string { return os.Getenv(\"" + name + "\") }\n"
}

// TestInjection_UndeclaredCollidingNameIsFound — ДЕФЕКТ.
//
// `KANAME_SIDECAR_PORT` подставит кластер сам, как только в пространстве имён
// появится служба `kaname-sidecar`, — а формы значения у ручки не объявлено.
func TestInjection_UndeclaredCollidingNameIsFound(t *testing.T) {
	const name = "KANAME_SIDECAR_PORT"
	findings, census, err := judgeServiceLinkEnvNames(synthModule(t, "wiring.go", readsEnv(name)))
	if err != nil {
		t.Fatalf("обход сорвался: %v", err)
	}
	if len(findings) != 1 {
		t.Fatalf("находок %d, ожидалась 1 (осмотрено файлов %d, литералов %d): мера не видит "+
			"плоского имени, которое подставляет кластер", len(findings), census.FilesRead, census.LitsSeen)
	}
	if findings[0].name != name {
		t.Errorf("находка называет %q вместо %q", findings[0].name, name)
	}
	if findings[0].file == "" || findings[0].line == 0 {
		t.Errorf("находка не называет координату: %+v — читатель пойдёт искать сам", findings[0])
	}
	if findings[0].form == "" {
		t.Errorf("находка не называет ФОРМУ кластера: оператор не поймёт, откуда значение")
	}
}

// TestInjection_DeclaredNameIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ по оси ИМЕНИ.
//
// Отличается от дефекта ровно одним фактом: ручка объявлена в перечне службы с
// формой значения, то есть загрузка отвергает подстановку кластера сама.
func TestInjection_DeclaredNameIsSilent(t *testing.T) {
	findings, census, err := judgeServiceLinkEnvNames(
		synthModule(t, "wiring.go", readsEnv("KANAME_INTERNAL_PORT")))
	if err != nil {
		t.Fatalf("обход сорвался: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("находок %d на ОБЪЯВЛЕННОЙ ручке: %+v — ложный срабат, после которого "+
			"меру отключат", len(findings), findings)
	}
	if census.Colliding != 1 || census.Declared != 1 {
		t.Errorf("перепись не разделила совпавшее и объявленное: совпало %d, объявлено %d — "+
			"без этого «находок ноль» неотличимо от «мера не смотрела»",
			census.Colliding, census.Declared)
	}
}

// TestInjection_PathDerivedNameIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ по оси РАЗДЕЛИТЕЛЯ.
//
// То же имя с `__`: кластер двойного подчёркивания не производит, поэтому
// столкновение невыразимо by construction.
func TestInjection_PathDerivedNameIsSilent(t *testing.T) {
	findings, census, err := judgeServiceLinkEnvNames(
		synthModule(t, "wiring.go", readsEnv("KANAME_API_SERVER__SIDECAR_PORT")))
	if err != nil {
		t.Fatalf("обход сорвался: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("находок %d на имени, выведенном из пути ключа: %+v", len(findings), findings)
	}
	if census.OwnPrefix == 0 {
		t.Errorf("литерал корневого сегмента не осмотрен вовсе — мера промолчала не потому, " +
			"что имя законно, а потому что не дошла до него")
	}
}

// TestInjection_NameInATestFileIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ по оси ОХВАТА.
//
// Предмет меры — что читает ПРОЦЕСС. Фикстуры доказательств предъявляют
// распознавателю все формы кластера поимённо, и судить их значило бы требовать
// от проверки не пользоваться тем, что она проверяет.
func TestInjection_NameInATestFileIsSilent(t *testing.T) {
	findings, census, err := judgeServiceLinkEnvNames(
		synthModule(t, "wiring_test.go", readsEnv("KANAME_SIDECAR_PORT")))
	if err != nil {
		t.Fatalf("обход сорвался: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("находок %d в тестовом файле: %+v", len(findings), findings)
	}
	if census.FilesRead != 0 {
		t.Errorf("тестовый файл попал в перепись прочитанного: %d", census.FilesRead)
	}
}

// TestInjection_NameInACommentIsSilent — ЗАКОННЫЙ БЛИЗНЕЦ по оси УЗЛА, и он
// несущий.
//
// Имя стоит в КОММЕНТАРИИ, объясняющем этот же класс. Поиск по подстроке
// покраснел бы здесь — то есть на собственном объяснении меры.
func TestInjection_NameInACommentIsSilent(t *testing.T) {
	body := "package wiring\n\n" +
		"// Кластер подставляет поду KANAME_SIDECAR_PORT=tcp://<адрес>:<порт>,\n" +
		"// как только рядом появится служба `kaname-sidecar`.\n" +
		"func knob() string { return \"\" }\n"
	findings, census, err := judgeServiceLinkEnvNames(synthModule(t, "wiring.go", body))
	if err != nil {
		t.Fatalf("обход сорвался: %v", err)
	}
	if len(findings) != 0 {
		t.Errorf("находок %d на имени В КОММЕНТАРИИ: %+v — мера ищет подстроку, а не узел "+
			"литерала, и краснеет на собственном объяснении", len(findings), findings)
	}
	if census.FilesRead != 1 {
		t.Errorf("файл не прочитан (%d): молчание меры ничего не означает", census.FilesRead)
	}
}

// TestInjection_EmptyTraversalIsNotAPass — АНТИМАСКА.
//
// Пустой обход обязан быть отличим от чистого дерева. Сама проба на этом
// объёме ОСТАНАВЛИВАЕТСЯ (t.Fatalf) — здесь предъявляется величина, по которой
// она это делает.
func TestInjection_EmptyTraversalIsNotAPass(t *testing.T) {
	findings, census, err := judgeServiceLinkEnvNames(t.TempDir())
	if err != nil {
		t.Fatalf("обход сорвался: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("на пустом дереве найдено %d", len(findings))
	}
	if census.FilesRead != 0 || census.OwnPrefix != 0 || census.Colliding != 0 {
		t.Fatalf("перепись пустого обхода непуста: %+v", census)
	}
	// Именно по этим трём нулям проба объявляет вердикт беспредметным и
	// ОСТАНАВЛИВАЕТСЯ, а не отчитывается чистым деревом.
}

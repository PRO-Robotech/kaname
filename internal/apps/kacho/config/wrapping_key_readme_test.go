// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// wrapping_key_readme_test.go — пример, которым оператор чеканит ключ обёртки,
// ПРОГОНЯЕТСЯ и скармливается настоящему резолву (задача #1065).
//
// # Что ловит
//
// Раздел о выдаче этого секрета в README чарта чеканил значение в base64
// (`openssl rand -base64 32 | tr -d '='`), тогда как резолв принимает hex.
// Идущий по примеру получает отказ старта и ищет дефект не там: ручка задана,
// секрет создан, а служба говорит про длину ключа.
//
// # Почему ПРОГОН, а не чтение
//
// Прочитанный пример утверждает о себе то, что о нём думает читатель. Прогон
// утверждает то, что пример ПРОИЗВОДИТ, — и производимое проверяется тем же
// кодом, который прочтёт его в производстве. Между «выглядит как 32 байта» и
// «принимается резолвом» умещается ровно этот дефект.
//
// # Чего НЕ утверждает
//
// Что секрет доедет до пода (это чарт), что значение годится по стойкости
// (источник случайности не наш) и что оператор пошёл именно этим путём.
package config

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"testing"

	"github.com/PRO-Robotech/kacho-iam/internal/keywrap"
)

// chartREADME — координата раздела о выдаче этого секрета.
const chartREADME = "deploy/helm/umbrella/charts/kacho-iam/README.md"

// sealedSecretHeading — заголовок раздела. Раздел, а не весь файл: в README
// чарта чеканятся и другие величины, у которых своя форма.
const sealedSecretHeading = "## Sealed-secret integration"

// mintingCommand — что считается чеканкой значения. Предикат НАЗВАН и узок:
// широкий («любая строка с openssl») втянул бы выпуск сертификатов, у которого
// форма другая, и гейт стал бы падать на чужом предмете.
//
// Захват обрывается на трубе, кавычке, обратной кавычке, перенаправлении и
// переносе строки: прогоняется ЧЕКАНКА, а не вся строка примера — та ведёт
// значение дальше, в утилиту запечатывания, которой на машине прогона нет.
var mintingCommand = regexp.MustCompile("openssl\\s+rand\\b[^\n|\"'`>\\\\]*")

// hexRun — длинный прогон шестнадцатеричных знаков. Вырезается ПЕРЕД поиском
// упоминания чужой кодировки: строка hex вполне может содержать «b64» внутри
// себя, и без этого гейт краснел бы на законном примере значения — то есть на
// первом же ложном срабатывании его сняли бы.
var hexRun = regexp.MustCompile(`(?i)[0-9a-f]{16,}`)

// encodingClaim — слово о кодировке, которого в этом разделе быть не может:
// резолв читает hex. Пример из этого класса — имя удалённого свойства
// `aes_gcm_b64url`: командой оно не является, поэтому прогоном не ловится,
// а оператор заводит по нему значение ровно той негодной формы.
var encodingClaim = regexp.MustCompile(`(?i)base64|b64`)

// moduleRoot поднимается от каталога пробы до go.mod модуля.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("рабочий каталог: %v", err)
	}
	// Корнем берётся САМЫЙ ВНЕШНИЙ `go.mod`, а не первый встречный: у службы
	// теперь СВОЙ модуль (она выносится отдельным репозиторием), и подъём «до
	// первого» останавливался бы в её каталоге. Пути, которые ниже склеиваются с
	// этим корнем, называют место В ДЕРЕВЕ МОНОРЕПО — от корня, — поэтому
	// остановка внутри службы удваивала сегмент и обход искал `services/iam/
	// services/iam/…`, которого не существует.
	outermost := ""
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			outermost = dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			if outermost != "" {
				return outermost
			}
			t.Fatalf("go.mod не найден вверх от каталога пробы")
		}
		dir = parent
	}
}

// sealedSecretSection возвращает строки раздела о выдаче секрета.
func sealedSecretSection(t *testing.T) []string {
	t.Helper()
	path := filepath.Join(moduleRoot(t), chartREADME)
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("README чарта не прочитан (%s): %v", chartREADME, err)
	}
	var out []string
	in := false
	for _, ln := range strings.Split(string(raw), "\n") {
		switch {
		case strings.HasPrefix(ln, sealedSecretHeading):
			in = true
		case in && strings.HasPrefix(ln, "## "):
			in = false
		case in:
			out = append(out, ln)
		}
	}
	if len(out) == 0 {
		// Перепись беспредметна: раздел переименован либо снят. «Ноль находок»
		// здесь неотличимо от «ноль прочитанного», поэтому это отказ.
		t.Fatalf("раздел %q в %s не найден — предикат перестал видеть свой предмет",
			sealedSecretHeading, chartREADME)
	}
	return out
}

// TestREADMEExampleMintsAValueTheResolverAccepts — каждая команда чеканки из
// раздела ПРОГОНЯЕТСЯ, и произведённое принимается резолвом.
func TestREADMEExampleMintsAValueTheResolverAccepts(t *testing.T) {
	if _, err := exec.LookPath("openssl"); err != nil {
		// Условие прогона не создано, и это НЕ вердикт о дереве. Названо
		// отказом, а не пропуском: «пример не прогонялся» обязано быть видно,
		// иначе гейт зелен на машине, где он ничего не делал.
		t.Fatalf("условие прогона не создано: openssl отсутствует в PATH (%v)", err)
	}

	lines := sealedSecretSection(t)
	var ran int
	for i, ln := range lines {
		for _, cmd := range mintingCommand.FindAllString(ln, -1) {
			cmd = strings.TrimSpace(strings.TrimSuffix(strings.TrimSpace(cmd), "\\"))
			out, err := exec.Command("sh", "-c", cmd).Output()
			if err != nil {
				t.Fatalf("%s: команда чеканки не исполнилась (%q): %v", chartREADME, cmd, err)
			}
			minted := strings.TrimSpace(string(out))
			cfg := AuthNConfig{JWKSEncryptionKeyHex: minted, JWKSEncryptionKeyHexEnv: absentEnv}
			keys, rerr := cfg.ResolveJWKSEncryptionKeys()
			if rerr != nil {
				t.Fatalf("%s (строка раздела %d): значение, отчеканенное примером %q, резолвом НЕ ПРИНИМАЕТСЯ: %v",
					chartREADME, i+1, cmd, rerr)
			}
			if len(keys) != 1 || len(keys[0]) != keywrap.KeySize {
				t.Fatalf("%s: пример %q дал %d ключ(ей) — не один ключ в %d байт",
					chartREADME, cmd, len(keys), keywrap.KeySize)
			}
			ran++
		}
	}

	// Перепись печатается всегда: «ноль находок» обязано быть отличимо от
	// «ноль прочитанного».
	t.Logf("перепись: строк раздела %d · команд чеканки прогнано %d", len(lines), ran)
	if ran == 0 {
		t.Fatalf("%s: в разделе %q не найдено ни одной команды чеканки — либо пример снят, "+
			"либо предикат перестал его видеть; вердикта о примере нет",
			chartREADME, sealedSecretHeading)
	}
}

// TestREADMESectionNamesTheEncodingTheResolverReads — раздел не описывает
// значение кодировкой, которой резолв не читает.
//
// Вторая половина того же предмета: имя удалённого свойства командой не
// является и прогоном не ловится, а оператор заводит по нему значение ровно
// той формы, которую служба отвергнет при старте.
func TestREADMESectionNamesTheEncodingTheResolverReads(t *testing.T) {
	lines := sealedSecretSection(t)
	var found []string
	for i, ln := range lines {
		if encodingClaim.MatchString(hexRun.ReplaceAllString(ln, "")) {
			found = append(found, strings.TrimSpace(ln)+"  ← строка раздела "+strconv.Itoa(i+1))
		}
	}
	t.Logf("перепись: строк раздела %d · упоминаний чужой кодировки %d", len(lines), len(found))
	if len(found) > 0 {
		t.Fatalf("%s: раздел описывает значение ключа обёртки в base64, а резолв читает hex "+
			"(authn.jwks-encryption-key-hex). Идущий по этому README получит отказ старта и будет "+
			"искать дефект не там:\n  %s", chartREADME, strings.Join(found, "\n  "))
	}
}

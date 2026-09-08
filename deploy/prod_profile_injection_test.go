// Copyright (c) PRO-Robotech
// SPDX-License-Identifier: AGPL-3.0-or-later

// prod_profile_injection_test.go — доказательство того, что проба боевого
// профиля СПОСОБНА упасть, и падает ровно на своём предмете.
//
// ─────────────────────────────────────────────────────────────────────────────
// ПОЧЕМУ ЭТА ОСНАСТКА ЗАВЕДЕНА ТОЛЬКО СЕЙЧАС
//
// У пробы её не было, и переустройство ядра (задача #2095) без неё было бы
// правкой вслепую: перепись, сошедшаяся с прежней, доказывает, что не сузился
// ПРЕДМЕТ, и не говорит ничего о том, сохранилась ли СПОСОБНОСТЬ ПАДАТЬ.
//
// ─────────────────────────────────────────────────────────────────────────────
// ОСЕЙ ТРИ, И У КАЖДОЙ СВОЙ СЛУЧАЙ — плюс близнец, на котором проба молчит
//
//  1. ПОВЕРХНОСТЬ. Пути, потреблённые склейкой, принадлежат поверхности
//     посадки. Инъекция: склейка перестала их читать — ручка обязана из
//     поверхности ВЫЙТИ. Близнец: ручка, взятая по `valuePath`, остаётся.
//  2. ПУСТОТА. Отсутствующий путь даёт пустую величину, а не «<nil>». Инъекция:
//     снять `db.host` — строка подключения обязана назвать ПУСТОЙ хост, и страж
//     старта обязан отказать. Близнец: с хостом страж молчит.
//  3. КЛАССИФИКАЦИЯ. Перечень отказа рендера выводится из шаблона. Инъекция:
//     ветвь снята — координата уходит из перечня; предпосылка нарушена —
//     ОТКАЗ, а не пустой перечень (пустой отнёс бы все координаты чужого
//     кластера к эксплуатационным).
package deploy_test

import (
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

// bridgedByKey — запись переложения по ключу конфигурации. Отсутствие записи —
// отказ: случай, опирающийся на запись, которой нет, ничего не доказывает.
func bridgedByKey(t *testing.T, key string) bridged {
	t.Helper()
	for _, b := range configBridge {
		if b.configKey == key {
			return b
		}
	}
	t.Fatalf("инъекция беспредметна: в переложении нет записи %q", key)
	return bridged{}
}

// ── ось 1: поверхность посадки ───────────────────────────────────────────────

func TestPostureSurfaceCoversWhatTheTemplateGluesTogether(t *testing.T) {
	merged := mergeChartProfiles(t, chartProfiles)

	// КОНТРОЛЬ: на действующем переложении склеенный ключ поверхности
	// принадлежит, а прежний вывод (только `valuePath`) его не видел.
	full := postureValuePaths(merged)
	require.True(t, inPostureSurface(full, []string{"db", "host"}),
		"db.host не на поверхности посадки — а страж старта без него отказывает в пуске; "+
			"именно этот пробел закрывала задача #2095")
	require.True(t, inPostureSurface(full, []string{"logger", "level"}),
		"ключ, взятый по valuePath, выпал из поверхности — вывод сузился не там")
	require.False(t, inPostureSurface(full, []string{"replicas"}),
		"число реплик попало на поверхность посадки — поверхность шире действительной, "+
			"и проба начнёт требовать отказа от ручки, которой страж не читает")

	// ИНЪЕКЦИЯ, РОВНО ОДИН ФАКТ: склейка строки подключения перестала читать
	// поля базы. Пути обязаны выйти из поверхности — иначе вывод не выводится,
	// а выписан, и расхождение с шаблоном пройдёт молча.
	blinded := make([]bridged, len(configBridge))
	copy(blinded, configBridge)
	for i := range blinded {
		if blinded[i].configKey == "repository.postgres.url" {
			blinded[i].derive = func(*valueReader) any { return "postgres://фикстура/база" }
		}
	}
	narrowed := postureValuePathsOf(blinded, merged)
	require.False(t, inPostureSurface(narrowed, []string{"db", "host"}),
		"склейка перестала читать db.host, а ключ остался на поверхности посадки — "+
			"значит перечень потреблённых путей не выводится исполнением, а выписан рядом")
	require.True(t, inPostureSurface(narrowed, []string{"logger", "level"}),
		"инъекция задела соседнюю ось: ключ по valuePath обязан остаться на поверхности")

	t.Logf("перепись: путей поверхности на действующем переложении %d · после ослепления "+
		"склейки %d", len(full), len(narrowed))
}

// ── ось 2: отсутствующий путь даёт пустоту, а не «<nil>» ─────────────────────

// ПОДСЛУЧАИ, А НЕ ОДНО ТЕЛО: страж вызывается через `evaluatePosture`, а тот
// раскладывает переменные окружения и требует, чтобы посторонних `KANAME_*` в
// процессе не было. Восстанавливаются они по КОНЦУ пробы, поэтому два вызова в
// одном теле дают вердикт о машине, а не о профиле — предпосылка самой пробы
// это ловит, и ловит верно.
func TestMissingKnobYieldsEmptinessNotTheWordNil(t *testing.T) {
	dsn := bridgedByKey(t, "repository.postgres.url")

	whole := mergeChartProfiles(t, chartProfiles)
	intact := fmt.Sprintf("%v", dsn.derive(&valueReader{tree: whole}))
	require.Contains(t, intact, "postgres.example.invalid",
		"строка подключения не называет хост боевого профиля — контроль недействителен")

	withoutHost := mergeChartProfiles(t, chartProfiles)
	removeAt(withoutHost, []string{"db", "host"})
	broken := fmt.Sprintf("%v", dsn.derive(&valueReader{tree: withoutHost}))

	require.NotContains(t, broken, "<nil>",
		"снятый db.host вернулся в строку подключения словом «<nil>»: хост НЕПУСТ, страж "+
			"старта доволен, и снятие ручки посадку не роняет — проба о такой ручке не "+
			"утверждает ничего")
	require.Contains(t, broken, "@:",
		"снятый db.host обязан давать ПУСТОЙ хост в строке подключения")
	t.Logf("ось подтверждена на строке подключения: с хостом %q · без хоста %q", intact, broken)

	t.Run("контроль: целый профиль проходит стража", func(t *testing.T) {
		_, _, posture := evaluatePosture(t, mergeChartProfiles(t, chartProfiles))
		require.NoError(t, posture, "целый боевой профиль не проходит стража — "+
			"инъекция ниже доказывала бы отказ, который был и без неё")
	})

	t.Run("инъекция: снят db.host — страж отказывает", func(t *testing.T) {
		injected := mergeChartProfiles(t, chartProfiles)
		removeAt(injected, []string{"db", "host"})

		_, _, posture := evaluatePosture(t, injected)
		require.Error(t, posture,
			"посадка без db.host прошла стража — ручка, которую страж читает, числилась бы "+
				"не несущей посадки")
		require.Contains(t, posture.Error(), "names no host",
			"отказ есть, но не тот: ждали упрёка стража про неназванный хост базы")
		t.Logf("отказ подтверждён: %v", posture)
	})
}

// ── ось 3: перечень отказа рендера выводится из шаблона ──────────────────────

func TestRenderRefusalPathsAreDerivedFromTheTemplate(t *testing.T) {
	// КОНТРОЛЬ: на целом чарте перечень называет все четыре координаты.
	whole := copyChartDeliveryFixture(t)
	refused, census, err := renderRefusalPaths(whole)
	require.NoError(t, err, "перечень отказа рендера не прочитан на целом чарте")
	for _, path := range []string{"image", "db.host", "db.passwordSecretName", "db.passwordSecretKey"} {
		require.True(t, refused[path],
			"перечень отказа рендера не называет %q — классификация отнесёт координату "+
				"чужого кластера к эксплуатационным, то есть вернёт неправду задачи #2095", path)
	}
	t.Logf("контроль: %s", census)

	t.Run("ветвь снята — координата уходит из перечня", func(t *testing.T) {
		chartDir := copyChartDeliveryFixture(t)
		b := readChartFile(t, chartDir, "templates/_helpers.tpl")
		start := strings.Index(b, "{{- if not .Values.image -}}")
		require.GreaterOrEqual(t, start, 0, "инъекция беспредметна: во входе нет ветви образа")
		tail := b[start:]
		end := strings.Index(tail, "{{- end -}}\n")
		require.GreaterOrEqual(t, end, 0, "инъекция беспредметна: ветвь образа не закрыта")
		writeChartFile(t, chartDir, "templates/_helpers.tpl",
			b[:start]+tail[end+len("{{- end -}}\n"):])

		shrunk, _, injErr := renderRefusalPaths(chartDir)
		require.NoError(t, injErr)
		require.False(t, shrunk["image"], "ветвь снята, а координата осталась в перечне — "+
			"перечень не выводится из шаблона, а выписан")
		require.True(t, shrunk["db.host"],
			"инъекция задела соседние координаты: изменён должен быть ровно один факт")
	})

	t.Run("объявление переименовано — ОТКАЗ, а не пустой перечень", func(t *testing.T) {
		chartDir := copyChartDeliveryFixture(t)
		b := readChartFile(t, chartDir, "templates/_helpers.tpl")
		b = replaceOnceIn(t, b, `{{- define "kaname-svc.requireOperatorSuppliedNames" -}}`,
			`{{- define "kaname-svc.requireOperatorSuppliedCoordinates" -}}`)
		writeChartFile(t, chartDir, "templates/_helpers.tpl", b)

		_, _, injErr := renderRefusalPaths(chartDir)
		require.Error(t, injErr, "перечень переименован, а вердикт вынесен по пустому "+
			"множеству — все координаты чужого кластера ушли бы в эксплуатационные молча")
		require.Contains(t, injErr.Error(), "переименован")
	})

	t.Run("ветвей не осталось — ОТКАЗ, а не пустой перечень", func(t *testing.T) {
		chartDir := copyChartDeliveryFixture(t)
		b := readChartFile(t, chartDir, "templates/_helpers.tpl")
		start := strings.Index(b, `{{- define "kaname-svc.requireOperatorSuppliedNames" -}}`)
		require.GreaterOrEqual(t, start, 0)
		head, body := b[:start], b[start:]
		body = strings.ReplaceAll(body, "{{- if not ", "{{- unless ")
		writeChartFile(t, chartDir, "templates/_helpers.tpl", head+body)

		_, _, injErr := renderRefusalPaths(chartDir)
		require.Error(t, injErr, "распознаватель не узнал ни одной ветви и отдал пустой "+
			"перечень как вердикт")
		require.Contains(t, injErr.Error(), "не назвал ни одного пути")
	})

	t.Run("каталога шаблонов нет — ОТКАЗ", func(t *testing.T) {
		_, _, injErr := renderRefusalPaths(filepath.Join(t.TempDir(), "нет-такого"))
		require.Error(t, injErr)
	})
}

// ── ось 4: страж монтирования различает ЛИСТЫ, а не только корень каталога ───
//
// Заведена задачей #2186. Прежний предикат спрашивал одно: «путь начинается с
// tls.mountPath». На популяции из ОДНОГО листа это совпадало с «секрет
// объявлен», и допущение было невидимо. Листов стало два — слушателя и
// клиента, — и путь под `<mount>/client` проходил проверку префикса при
// необъявленном секрете клиента: каталога в поде нет, а профиль читается как
// настроенный.
//
// Каждый случай меняет РОВНО ОДИН факт против законного близнеца.
func TestMountGuardDistinguishesTheLeaves(t *testing.T) {
	// Законная посадка: оба листа объявлены, пути под своими подкаталогами.
	legal := func() map[string]any {
		return map[string]any{"tls": map[string]any{
			"mountPath":        "/etc/kaname/tls",
			"secretName":       "kaname-server-tls",
			"clientSecretName": "kaname-client-tls",
		}}
	}
	envs := map[string]string{
		"KANAME_PUBLIC_SERVER_MTLS_CERTFILE": "/etc/kaname/tls/server/tls.crt",
		"KANAME_REST_UPSTREAM_MTLS_CERTFILE": "/etc/kaname/tls/client/tls.crt",
		"KANAME_REST_UPSTREAM_MTLS_CAFILES":  "/etc/kaname/tls/client/ca.crt",
	}

	t.Run("законный близнец: оба листа объявлены — молчит", func(t *testing.T) {
		require.NoError(t, filesAreMountable(legal(), envs),
			"верная посадка обязана молчать, иначе первый ложный срабат снимет проверку")
	})

	t.Run("СЕКРЕТ КЛИЕНТА НЕ ОБЪЯВЛЕН — находка называет ручку и ключ", func(t *testing.T) {
		merged := legal()
		delete(merged["tls"].(map[string]any), "clientSecretName") // единственное отличие
		err := filesAreMountable(merged, envs)
		require.Error(t, err, "путь под <mount>/client при необъявленном секрете клиента — "+
			"каталога в поде нет; прежний предикат это пропускал, потому что префикс совпадал")
		require.Contains(t, err.Error(), "KANAME_REST_UPSTREAM_MTLS_CERTFILE")
		require.Contains(t, err.Error(), "tls.clientSecretName")
		require.NotContains(t, err.Error(), "KANAME_PUBLIC_SERVER_MTLS_CERTFILE",
			"снятие секрета КЛИЕНТА не вправе обвинять путь под листом слушателя")
	})

	t.Run("СЕКРЕТ СЛУШАТЕЛЯ НЕ ОБЪЯВЛЕН — зеркало того же класса", func(t *testing.T) {
		merged := legal()
		delete(merged["tls"].(map[string]any), "secretName") // единственное отличие
		err := filesAreMountable(merged, envs)
		require.Error(t, err)
		require.Contains(t, err.Error(), "KANAME_PUBLIC_SERVER_MTLS_CERTFILE")
		require.Contains(t, err.Error(), "tls.secretName")
	})

	t.Run("ПОДКАТАЛОГ, КОТОРОГО ЧАРТ НЕ ЗАВОДИТ — находка, а не молчание", func(t *testing.T) {
		err := filesAreMountable(legal(), map[string]string{
			"KANAME_REST_UPSTREAM_MTLS_CERTFILE": "/etc/kaname/tls/сторонний/tls.crt",
		})
		require.Error(t, err, "переименует шаблон подкаталог — путь под неизвестным именем "+
			"обязан стать находкой, а не пройти молча")
		require.Contains(t, err.Error(), "client, server")
	})

	t.Run("ПУТЬ ВНЕ МОНТИРОВАНИЯ — прежняя ось не потеряна", func(t *testing.T) {
		err := filesAreMountable(legal(), map[string]string{
			"KANAME_REST_UPSTREAM_MTLS_CERTFILE": "/чужой/каталог/tls.crt",
		})
		require.Error(t, err)
		require.Contains(t, err.Error(), "вне каталога")
	})
}

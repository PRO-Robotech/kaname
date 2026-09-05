# Copyright (c) PRO-Robotech
# SPDX-License-Identifier: AGPL-3.0-or-later

# Нагрузочные цели kacho-iam.
#
# ПОЧЕМУ ЭТОТ ФАЙЛ ПОЯВИЛСЯ. Сценарий `authz_check.js` лежал в дереве и не
# вызывался НИОТКУДА: цели у каталога не было (в отличие от services/nlb/tests/k6),
# в сборку он не входил, и результатов его прогона в дереве ноль. Сценарий, который
# нечем запустить, — это объявление намерения, а не проверка: он не может
# покраснеть, поэтому его пороги ничего не удерживают.
#
# ЧТО ЧЕМ МЕРИТСЯ (два сценария, РАЗНЫЕ предметы — не дубли):
#   internal_check.js — InternalIAMService.Check по gRPC+mTLS, НАПРЯМУЮ в службу
#     прав, мимо края. Это глагол, который per-RPC интерсепторы vpc/compute/nlb
#     тратят на каждом запросе платформы. Мерит СЛУЖБУ.
#   authz_check.js    — публичный AuthorizeService.Check по REST через край.
#     Мерит ПУТЬ ЦЕЛИКОМ (разбор токена краем, его кэш вердиктов, внутренняя
#     калитка). Требует Bearer; без него край ответит 401 и сценарий померит
#     скорость отказа в доступе, а не проверку прав.
K6           ?= k6
NS           ?= kacho
K6_POD       ?= k6-iam-runner
TARGET_RPS   ?= 200
DURATION     ?= 60s
ALLOW_RATIO  ?= 0.9
STEPS        ?= 100,200,300,400,600,900
REPEATS      ?= 2
LABEL        ?= adhoc

.PHONY: help
help:
	@echo "Нагрузочные сценарии kacho-iam:"
	@echo "  make k6-dry-run        — разбор обоих сценариев, стенд НЕ нужен"
	@echo "  make k6-runner-up      — поднять генератор в кластере (сертификат+фикстура)"
	@echo "  make k6-internal-check — одиночный прогон InternalIAMService.Check (TARGET_RPS/DURATION)"
	@echo "  make k6-step           — ступенчатый поиск точки насыщения (STEPS/REPEATS)"
	@echo "  make k6-runner-down    — снять генератор"
	@echo ""
	@echo "Переменные: TARGET_RPS=$(TARGET_RPS) DURATION=$(DURATION) STEPS=$(STEPS) REPEATS=$(REPEATS)"

# k6-dry-run — единственная цель, НЕ требующая стенда: разбирает сценарии.
# Она и есть то, что может стоять в конвейере: синтаксическая порча сценария
# перестаёт обнаруживаться прогоном, которого никто не делает.
.PHONY: k6-dry-run
k6-dry-run:
	@for s in internal_check authz_check; do \
	  echo "==> $$s.js"; \
	  $(K6) inspect --address '' $$s.js >/dev/null || exit $$?; \
	done
	@echo "оба сценария разбираются"

.PHONY: k6-runner-up
k6-runner-up:
	@bash ../../../../deploy/load-tests/iam-check-runner.sh up

.PHONY: k6-runner-down
k6-runner-down:
	@bash ../../../../deploy/load-tests/iam-check-runner.sh down

.PHONY: k6-internal-check
k6-internal-check:
	kubectl -n $(NS) exec $(K6_POD) -- k6 run --quiet \
	  -e TARGET_RPS=$(TARGET_RPS) -e DURATION=$(DURATION) -e ALLOW_RATIO=$(ALLOW_RATIO) \
	  /scripts/internal_check.js

.PHONY: k6-step
k6-step:
	@bash ../../../../deploy/load-tests/iam-check-rps-step.sh $(LABEL) "$(STEPS)" $(DURATION) $(REPEATS)

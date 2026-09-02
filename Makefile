.PHONY: deploy stop reset validate logs

deploy:
	./scripts/deploy.sh

stop:
	./scripts/stop.sh

reset:
	./scripts/reset.sh

validate:
	./scripts/validate.sh

logs:
	docker compose logs --follow --tail=100


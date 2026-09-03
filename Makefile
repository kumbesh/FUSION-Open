.PHONY: deploy stop reset validate validate-detections validate-rules logs

deploy:
	./scripts/deploy.sh

stop:
	./scripts/stop.sh

reset:
	./scripts/reset.sh

validate:
	./scripts/validate.sh

validate-detections:
	./scripts/validate-detections.sh

validate-rules:
	docker compose run --rm --no-deps fusion-detection-engine validate-rules

logs:
	docker compose logs --follow --tail=100

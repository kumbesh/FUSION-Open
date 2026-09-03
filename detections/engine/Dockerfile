FROM python:3.12.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid 10001 fusion \
    && useradd --uid 10001 --gid fusion --no-create-home --shell /usr/sbin/nologin fusion

WORKDIR /app
COPY requirements.txt pyproject.toml ./
COPY fusion_detection ./fusion_detection
RUN pip install --requirement requirements.txt \
    && pip install --no-deps .

USER 10001:10001
ENTRYPOINT ["fusion-detection"]
CMD ["run"]

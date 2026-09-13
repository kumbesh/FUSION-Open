FROM python:3.12.12-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    PIP_NO_CACHE_DIR=1

RUN groupadd --gid 10002 fusion-correlation \
    && useradd --uid 10002 --gid fusion-correlation --no-create-home --shell /usr/sbin/nologin fusion-correlation

WORKDIR /app
COPY requirements.txt pyproject.toml ./
COPY fusion_correlation ./fusion_correlation
RUN pip install --requirement requirements.txt \
    && pip install --no-deps .

USER 10002:10002
ENTRYPOINT ["fusion-correlation"]
CMD ["run"]

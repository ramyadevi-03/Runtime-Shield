FROM openpolicyagent/opa:1.4.2 AS opa
FROM python:3.12.10-slim
COPY --from=opa /opa /usr/local/bin/opa
WORKDIR /policies
USER 10001:10001
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=5 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8181/health?bundles', timeout=2).read()"]
ENTRYPOINT ["opa"]
CMD ["run", "--server", "--addr=0.0.0.0:8181", "/policies"]

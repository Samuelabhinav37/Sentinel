# First Dockerfile in this repo -- every other stack uses a stock upstream
# image with mounted config/scripts. This service needs the `mcp` package
# (see requirements.txt), so a build step is unavoidable; kept as small and
# boring as possible rather than reaching for a base image with extras we
# don't need.
FROM python:3.12-slim
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY mcp_server.py healthcheck.py ./
HEALTHCHECK --interval=15s --timeout=5s --retries=5 --start-period=10s \
  CMD ["python", "healthcheck.py"]
CMD ["python", "mcp_server.py"]

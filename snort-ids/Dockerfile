FROM python:3.11-slim

WORKDIR /app

RUN pip install flask requests --break-system-packages

COPY snort_ids.py .
COPY rules/ ./rules/

EXPOSE 9090

CMD ["python", "snort_ids.py"]

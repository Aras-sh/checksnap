FROM python:latest
ENV DB_PASSWORD=hunter2
COPY . /app
RUN pip install -r /app/requirements.txt
CMD ["python", "/app/app.py"]

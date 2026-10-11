FROM python:latest
ENV DB_PASSWORD=hunter2hunter2
ADD app.py /app/app.py
COPY . /app
RUN apt-get update
RUN apt-get install -y curl && pip install -r /app/requirements.txt
RUN curl -fsSL https://example.com/i.sh | sh
EXPOSE 22 8000
CMD ["a"]
CMD ["b"]

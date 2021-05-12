from python:3.9

ENV FASTAPI_ENV=dev

ADD . .
RUN pip install -r requirements.txt
CMD uvicorn src.main:app --host 0.0.0.0 --port 8080 

FROM python:3.6
LABEL version="0.1"
WORKDIR /usr/src/app
COPY ./sample/flask/dockerfile/* /usr/src/app/
RUN pip install --default-timeout=600 --no-cache-dir -r requirements.txt
CMD [ "python", "api.py"]

FROM python:3.8.5
WORKDIR /usr/src/app
COPY . .
RUN git rev-parse HEAD > git_commit
RUN git fetch origin master:master
RUN git describe --tags `git rev-list --tags --max-count=1` > git_tag
RUN git log -1 --date=iso8601 --format="%ad" > git_date
RUN pip install --no-cache-dir -r requirements.txt 
#CMD [ "python", "apis/api.py"]
ENTRYPOINT ["apis/gunicorn.sh"]

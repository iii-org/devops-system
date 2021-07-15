FROM python:3.8.5
WORKDIR /usr/src/app
COPY . .
RUN mkdir /root/.kube
COPY k8s_config /root/.kube/config
RUN git rev-parse HEAD > git_commit
RUN git fetch origin master:master
RUN git describe --tags `git rev-list --tags --max-count=1` > git_tag
RUN git log -1 --date=iso8601 --format="%ad" > git_date
RUN pip install --no-cache-dir -r requirements.txt 
RUN python -c 'import sys, yaml, json; yaml.safe_dump(json.load(sys.stdin), sys.stdout, default_flow_style=False)' < k8s_config > ~/.kube/config
#CMD [ "python", "apis/api.py"]
ENTRYPOINT ["apis/gunicorn.sh"]

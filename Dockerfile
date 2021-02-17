FROM python:3.8
WORKDIR /usr/src/app
COPY . .
RUN mkdir /root/.kube
COPY k8s_config /root/.kube/config
RUN git rev-parse HEAD > git_commit
RUN pip install -i https://pypi.douban.com/simple --no-cache-dir -r requirements.txt 
RUN python -c 'import sys, yaml, json; yaml.safe_dump(json.load(sys.stdin), sys.stdout, default_flow_style=False)' < k8s_config > ~/.kube/config
CMD [ "python", "apis/api.py"]

FROM python:3.6
WORKDIR /usr/src/app
COPY . .
RUN mkdir /root/.kube
COPY k8s_config /root/.kube/config
RUN git rev-parse HEAD > git_commit
RUN pip install --no-cache-dir -r requirements.txt
CMD [ "python", "apis/api.py"]

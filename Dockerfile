FROM 10.20.0.71:5443/dockerhub/library/python:3.6
WORKDIR /usr/src/app
COPY . .
ARG environment_json
ARG k8s_config
RUN echo $environment_json > ./environment.json
RUN echo $k8s_config > ~/.kube/config
RUN mkdir /root/.kube
RUN git rev-parse HEAD > git_commit
RUN pip install -i https://pypi.douban.com/simple --no-cache-dir -r requirements.txt 
CMD [ "python", "apis/api.py"]

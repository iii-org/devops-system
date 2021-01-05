FROM 10.20.0.71:5443/dockerhub/library/python:3.6
WORKDIR /usr/src/app
COPY . .
ARG environments_json
ARG k8s_config
RUN mkdir ~/.kube
RUN echo $environments_json > ./environments.json
RUN echo $k8s_config > ~/.kube/config
RUN cat ./environments.json
RUN git rev-parse HEAD > git_commit
RUN pip install -i https://pypi.douban.com/simple --no-cache-dir -r requirements.txt 
CMD [ "python", "apis/api.py"]

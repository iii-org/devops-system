FROM 10.20.0.71:5443/dockerhub/library/python:3.6
WORKDIR /usr/src/app
COPY . .
RUN cat ./environments.json
RUN cat ~/.kube/config
RUN git rev-parse HEAD > git_commit
#RUN pip install -i https://pypi.douban.com/simple --no-cache-dir -r requirements.txt
CMD [ "python", "apis/api.py"]

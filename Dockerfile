FROM dockerhub/library/python:3.9.12-slim
RUN apt-get update && apt-get install -y --no-install-recommends git curl 
RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.19.0/bin/linux/amd64/kubectl && chmod +x ./kubectl && mv ./kubectl /usr/local/bin/kubectl
WORKDIR /root/.kube
COPY iiidevops/k8s_config ./config
WORKDIR /usr/src/app/deploy-config
COPY iiidevops/id_rsa iiidevops/id_rsa.pub ./
WORKDIR /usr/src/app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt 
RUN echo "1.20.1" > git_tag
COPY . .
#RUN LOCAL_BRANCH=`git rev-parse --abbrev-ref HEAD | grep master`
#RUN if [ -z "$LOCAL_BRANCH" ] ; then git remote add origin https://github.com/iii-org/devops-system.git; fi
#RUN if [ -z "$LOCAL_BRANCH" ] ; then git fetch origin master:master ; fi
#RUN git describe --tags `git rev-list --tags --max-count=1` > git_tag
RUN git rev-parse HEAD > git_commit
RUN git log -1 --date=iso8601 --format="%ad" > git_date
# RUN ls -la && ls -laR /root && cat /root/.kube/config
#CMD [ "python", "apis/api.py"]
ENTRYPOINT ["apis/gunicorn.sh"]

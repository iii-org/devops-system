FROM bitnami/git:latest AS buildler

WORKDIR /depends

RUN curl -LO https://storage.googleapis.com/kubernetes-release/release/v1.25.0/bin/linux/amd64/kubectl && \
    chmod +x ./kubectl && \
    curl -LO https://get.helm.sh/helm-v3.12.1-linux-amd64.tar.gz && \
    tar -zxvf helm-v3.12.1-linux-amd64.tar.gz && \
    mv linux-amd64/helm .

WORKDIR /app

COPY . .

#RUN LOCAL_BRANCH=`git rev-parse --abbrev-ref HEAD | grep master`
#RUN if [ -z "$LOCAL_BRANCH" ] ; then git remote add origin https://github.com/iii-org/devops-system.git; fi
#RUN if [ -z "$LOCAL_BRANCH" ] ; then git fetch origin master:master ; fi
#RUN git describe --tags `git rev-list --tags --max-count=1` > git_tag

RUN git rev-parse HEAD > git_commit && \
    git log -1 --date=iso8601 --format="%ad" > git_date && \
    rm -rf .git

FROM python:3.9.16-slim AS base

RUN apt-get update && apt-get install -y --no-install-recommends git curl

COPY --from=buildler /depends/kubectl /usr/local/bin/kubectl
COPY --from=buildler /depends/helm /usr/local/bin/helm
COPY iiidevops/bin/pict /usr/local/bin/pict

WORKDIR /root/.kube
COPY iiidevops/k8s_config ./config

WORKDIR /usr/src/app/deploy-config
COPY iiidevops/id_rsa iiidevops/id_rsa.pub ./

WORKDIR /usr/src/app
COPY requirements.txt .

RUN pip install --no-cache-dir -r requirements.txt

RUN echo "1.28.2" > git_tag
COPY --from=buildler /app/git_commit .
COPY --from=buildler /app/git_date .

COPY --from=buildler /app .

COPY docker-entrypoint.sh /
ENTRYPOINT ["/docker-entrypoint.sh"]

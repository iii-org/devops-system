FROM dockerhub/library/python:3.8.5
WORKDIR /root/.kube
COPY iiidevops/k8s_config .
WORKDIR /usr/src/app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt 
RUN echo "V1.12.0-dev" > git_tag
COPY . .
#RUN LOCAL_BRANCH=`git rev-parse --abbrev-ref HEAD | grep master`
#RUN if [ -z "$LOCAL_BRANCH" ] ; then git remote add origin https://github.com/iii-org/devops-system.git; fi
#RUN if [ -z "$LOCAL_BRANCH" ] ; then git fetch origin master:master ; fi
#RUN git describe --tags `git rev-list --tags --max-count=1` > git_tag
RUN git rev-parse HEAD > git_commit
RUN git log -1 --date=iso8601 --format="%ad" > git_date
#CMD [ "python", "apis/api.py"]
ENTRYPOINT ["apis/gunicorn.sh"]

FROM python:3.8.5
WORKDIR /usr/src/app
COPY . .
RUN git rev-parse HEAD > git_commit
#RUN LOCAL_BRANCH=`git rev-parse --abbrev-ref HEAD | grep master`
#RUN if [ -z "$LOCAL_BRANCH" ] ; then git remote add origin https://github.com/iii-org/devops-system.git; fi
#RUN if [ -z "$LOCAL_BRANCH" ] ; then git fetch origin master:master ; fi
#RUN git describe --tags `git rev-list --tags --max-count=1` > git_tag
RUN echo "V1.10.1" > git_tag
RUN git log -1 --date=iso8601 --format="%ad" > git_date
RUN pip install --no-cache-dir -r requirements.txt 
#CMD [ "python", "apis/api.py"]
ENTRYPOINT ["apis/gunicorn.sh"]

FROM sonarsource/sonar-scanner-cli:4.2
USER root
WORKDIR /usr/src
RUN echo 'sonar.projectKey=${CICD_GIT_REPO_NAME}' > /usr/src/sonar-project.properties
COPY . .
FROM sonarsource/sonar-scanner-cli:4.2
CMD echo "sonar.projectKey=${CICD_GIT_REPO_NAME}" >> sonar-project.properties
CMD cat sonar-project.properties
COPY . /usr/src
ENV SONAR_HOST_URL=http://10.50.1.56:31910
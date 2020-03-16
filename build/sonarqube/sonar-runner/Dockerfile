FROM sonarsource/sonar-scanner-cli:4.2
WORKDIR /usr/src
RUN echo 'sonar.projectKey=devops-flask' > /usr/src/sonar-project.properties
COPY . .
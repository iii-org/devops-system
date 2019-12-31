pipeline {
  agent none
  stage('build docker image') {
    agent {docker 'python:2.7'}
    steps{
      echo 'python 2.7 is working'
    }
  }
  stages {
    stage('Example Test') {
        agent { docker 'openjdk:8-jre' } 
        steps {
            echo 'Hello, JDK'
            sh 'java -version'
        }
    }
  }
}
pipeline {
  agent any
  triggers {
      pollSCM 'H/2 * * * *' //Empty quotes tells it to build on a push
  }
  stages{
    stage('build docker image') {
      agent {docker 'python:2.7'}
      steps{
        echo 'python 2.7 is working'
      }
    }
    stage('Example Test') {
        agent { docker 'openjdk:8-jre' } 
        steps {
            echo 'Hello, JDK'
            sh 'java -version'
        }
    }
  }
}
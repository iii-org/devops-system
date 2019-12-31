pipeline {
  agent {
    dockerfile {
      dir 'sample/flask'
      label 'demoyuw/python-flask'
      additionalBuildArgs '--build-arg version=jenkinsfilev1'
    }
  }
  stages {
    stage('step1') {
      steps {
        echo 'hello world.!'
        hostname
      }
    }
  }
}
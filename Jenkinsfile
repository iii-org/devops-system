pipeline {
  agent {
    dockerfile {
      dir 'sample/flask'
    }
  }
  stages {
    stage('step1') {
      steps {
        echo 'hello world.!'
      }
    }
  }
}
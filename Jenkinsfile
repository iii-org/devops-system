pipeline {
  agent {
    dockerfile {
      dir 'sample/flask/dockerfile'
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
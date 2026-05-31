pipeline {

    agent any

    environment {
      DEPLOY_ENV = 'staging'
    }

    stages {
        stage('Build') {
            steps {
                echo 'Building application...'
                git branch --show-current
            }
        }
        stage('Deploy to Staging') {
            when {
                environment name: 'DEPLOY_ENV', value: 'standing'
            }
            steps {
                echo 'Имя переменной DEPLOY_ENV: ${env.DEPLOY_ENV}'
            }
        }
        stage ('Deploy to Production') {
            when {
                environment name: 'DEPLOY_ENV', value: 'production'
            }
            steps {
                echo 'Имя переменной DEPLOY_ENV: ${env.DEPLOY_ENV}'
            }
        }
        stage('Test') {
            when {
                allOf {
                    branch 'main'
                    environment name: 'DEPLOY_ENV', value: 'staging'
                    expression { env.BUILD_NUMBER.toInteger() % 2 == 0 }
                }
            }
            steps {
                echo 'Deploying to the staging environment...'
             }

        }
        stage('Weekend Task') {
            when {
                expression {
                    def day = new Date().format('EEEE')
                    return day == 'Saturday' || day == 'Sunday'
                }
            }
            steps {
                echo "This is a weekend build!"
                echo "Day: ${new Date().format('EEEE, MMMM dd, yyyy')}"
            }
        }


    }
}
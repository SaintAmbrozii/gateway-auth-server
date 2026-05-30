pipeline {
    agent any
    stages {
        stage('Prepare') {
            steps {
                echo 'Preparing workspace...'
            }
            steps {
                sh 'mkdir -p build logs temp'
                sh 'mkdir -p build logs build'
                sh 'mkdir -p build logs temp'
            }

        }
        stage('Build') {
            steps {
                 echo 'Building application...'
            }
            steps {
                 echo 'Building application...'
                 sh 'echo "Build version: 1.0.0" > build/version.txt'
            }
            steps {
                sh 'date >> build/version.txt'
                echo 'Build completed'
            }
        }
        stage ('Verify') {
            steps {
                echo 'Verifying build..'
            }
            steps {
                sh 'cat build/version.txt'
            }
            steps {
                sh 'ls -la build/'
                echo 'Verification completed'
            }
        }
        stage('System Info') {
            steps {
                echo 'Информация о системе:'
                echo 'Операционная система:'
                sh 'uname -a'
                echo 'Текущая директория:'
                sh 'pwd'
                echo 'Список файлов:'
                sh 'ls -la'
            }
        }


        stage('Cleanup') {
            steps {
                echo 'Cleaning up temporary files...'
                sh 'rm -rf temp logs'
                sh 'ls -la'
                echo 'Cleanup completed'
            }
    }
}
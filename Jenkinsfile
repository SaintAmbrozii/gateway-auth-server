pipeline {
    agent any
    stages {
        stage('Hello') {
            steps {
                echo 'Привет от Jenkins!'
                echo 'Сегодняшняя дата:'
                sh 'date'
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
    }
}
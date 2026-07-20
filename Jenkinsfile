pipeline {
    agent any

    parameters {
        choice(name: 'MODULE', choices: ['root', 'vmd'], description: 'Module to build: root=publish parent pom only, vmd=parent+vmd')
    }

    environment {
        REPO_URL = "http://${env.MAVEN_URL}/repository/maven-snapshots/"
        REPO_ID = "snapshots"
    }

    tools {
        maven 'M3'
    }

    stages {
        stage('Build and Deploy') {
            steps {
                script {
                    def module = params.MODULE
                    if (module == 'root') {
                        sh '''
                            echo '============================== Publish Root POM =============================='
                            mvn clean deploy -N -DaltDeploymentRepository=${REPO_ID}::default::${REPO_URL}
                        '''
                    } else {
                        sh """
                            echo '============================== Build and Deploy =============================='
                            echo "Building module: iov-cloud-proto-${module}"
                            mvn clean deploy -pl iov-cloud-proto-${module} -am -DaltDeploymentRepository=${REPO_ID}::default::${REPO_URL}
                        """
                    }
                }
            }
        }
    }
}
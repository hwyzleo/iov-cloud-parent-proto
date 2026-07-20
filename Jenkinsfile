pipeline {
    agent any

    parameters {
        choice(name: 'MODULE', choices: ['vmd'], description: '选择要编译的模块')
    }

    environment {
        REPO_URL = "http://${env.MAVEN_URL}/repository/maven-snapshots/"
        REPO_ID = "snapshots"
    }

    tools {
        maven 'M3'
    }

    stages {
        stage('构建并发布') {
            steps {
                script {
                    def moduleName = "iov-cloud-proto-${params.MODULE}"
                    sh """
                        echo '============================== 构建并发布 =============================='
                        echo "编译模块: ${moduleName}"
                        mvn clean deploy -pl ${moduleName} -am -DaltDeploymentRepository=${REPO_ID}::default::${REPO_URL}
                    """
                }
            }
        }
    }
}
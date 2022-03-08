// This Jenkinsfile is dedicated to the jenkins job: clair-scanner
// cf: https://jenkins.toucantoco.guru/job/clair-scanner/
//
// This job is the CI for the clair-scanner project

@Library('toucan-jenkins-lib')_
import com.toucantoco.ToucanVars

RELEASE_BRANCH_NAMES = [
    'master',
]

pipeline {
    agent any

    options {
      // Enable color in logs
      ansiColor('gnome-terminal')
    }

    stages {
        stage('Prod stages') {
            when {
                expression {
                  // Only when the latest commit messages is like vX.Y.Z
                  // and the branch is declared in RELEASE_BRANCH_NAMES
                  LAST_COMMIT_MESSAGE = sh(
                    script: 'git log --format=%B -n 1',
                    returnStdout: true
                  ).trim()
                  return RELEASE_BRANCH_NAMES.contains(BRANCH_NAME) && LAST_COMMIT_MESSAGE ==~ /v\d+\.\d+\.\d+$/
                }
            }

            stages {
                stage('Build toucantoco/clair-scanner prod') {
                    steps {
                        storeStage()
                        sh 'make -f Toucan_Makefile docker-build-prod'
                    }
                }

                stage('Push toucantoco/clair-scanner prod') {
                    steps {
                        storeStage()
                        // Create tag latest on the current clair-scanner version
                        // And push on docker hub:
                        //    - toucantoco/clair-scanner:$clair-scanner_VERSION
                        //    - toucantoco/clair-scanner:latest
                        sh "make -f Toucan_Makefile push-to-registry CLAIR_IMAGE_MORE_TAGS=latest"
                    }
                }
            }
        }
    }

    post {
        failure {
          postSlackNotif()
        }

        always {
          // Store build result in a format parsable for our Elastic stack
          logKibana()
        }
      }
}

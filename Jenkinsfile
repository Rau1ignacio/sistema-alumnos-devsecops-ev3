// Jenkinsfile - Pipeline DevSecOps de "Sistema Alumnos" (SecureDev · Evaluación Parcial 3 · OCY1102)
//
// Build -> Test -> Security Review (SAST) -> Dependency Management (SCA)
//       -> Deploy Staging -> DAST - OWASP ZAP -> [gate] -> Deploy Producción
//
// Cualquier hallazgo de seguridad deja el build en UNSTABLE y la puerta (gate) impide desplegar en producción.
pipeline {
    agent any

    options {
        timestamps()
        timeout(time: 40, unit: 'MINUTES')
        disableConcurrentBuilds()
    }

    // Revisa GitHub cada ~3 minutos: cada push (tuyo o un PR de Dependabot fusionado) dispara un build.
    triggers {
        pollSCM('H/3 * * * *')
    }

    environment {
        PIP_DISABLE_PIP_VERSION_CHECK = '1'
    }

    stages {
        stage('Build') {
            steps {
                script {
                    // Versión = 1.0.<nº de build>+<commit corto>: une cada despliegue con su commit (trazabilidad)
                    def sha = sh(returnStdout: true, script: 'git rev-parse --short HEAD').trim()
                    env.APP_VERSION = "1.0.${env.BUILD_NUMBER}+${sha}"
                }
                echo "Versión de este build: ${env.APP_VERSION}"
                sh 'git log -1 --format="Commit %h de %an: %s"'
                // Cada build parte limpio: sin reportes viejos y con un entorno virtual nuevo
                sh 'rm -rf .venv reports && mkdir -p reports'
                sh 'python3 -m venv .venv'
                sh '.venv/bin/pip install --quiet -r requirements.txt -r requirements-dev.txt'
                sh '.venv/bin/python -m compileall -q app.py'
            }
        }

        stage('Test') {
            steps {
                sh '.venv/bin/python -m pytest --junitxml=reports/junit.xml'
            }
            post {
                always {
                    junit allowEmptyResults: true, testResults: 'reports/junit.xml'
                }
            }
        }

        stage('Security Review (SAST)') {
            steps {
                // Reporte completo (todas las severidades) para la trazabilidad
                sh 'bandit -f json -o reports/bandit.json app.py || true'
                sh 'bandit -f txt -o reports/bandit.txt app.py || true'
                script {
                    // Política: cualquier hallazgo Medium o High marca el build como UNSTABLE
                    def rc = sh(returnStatus: true, script: 'bandit -q -ll app.py')
                    if (rc != 0) {
                        unstable('Bandit encontró hallazgos Medium/High en app.py (ver reports/bandit.txt)')
                    }
                }
            }
        }

        stage('Dependency Management (SCA)') {
            steps {
                sh 'pip-audit -r requirements.txt -f json -o reports/pip-audit.json || true'
                script {
                    // Política: ninguna dependencia de ejecución con vulnerabilidades conocidas (CVE/GHSA/PYSEC)
                    def rc = sh(returnStatus: true, script: 'pip-audit -r requirements.txt --desc on > reports/pip-audit.txt 2>&1')
                    sh 'cat reports/pip-audit.txt'
                    if (rc != 0) {
                        unstable('pip-audit encontró dependencias vulnerables (ver reports/pip-audit.txt)')
                    }
                }
            }
        }

        stage('Deploy Staging') {
            steps {
                sh 'bash scripts/deploy.sh staging 5001'
            }
        }

        stage('DAST - OWASP ZAP') {
            steps {
                script {
                    // ZAP corre en su propio contenedor y ataca staging por la red interna de Docker
                    def rc = sh(returnStatus: true, script: 'python3 scripts/zap_scan.py http://jenkins:5001')
                    if (rc == 2) {
                        unstable('OWASP ZAP encontró alertas High/Medium (ver reports/zap-report.html)')
                    } else if (rc != 0) {
                        error("El escaneo de OWASP ZAP falló (código ${rc})")
                    }
                }
            }
        }

        stage('Deploy Producción') {
            // Puerta de seguridad: solo se despliega si TODAS las revisiones anteriores quedaron limpias
            when {
                expression { currentBuild.currentResult == 'SUCCESS' }
            }
            steps {
                sh 'bash scripts/deploy.sh produccion 5000'
                script { env.PRODUCCION = env.APP_VERSION }
            }
        }
    }

    post {
        always {
            // Registro de trazabilidad: build <-> versión <-> commit <-> pruebas <-> hallazgos <-> despliegue
            withEnv(["RESULTADO=${currentBuild.currentResult}"]) {
                sh 'python3 scripts/trazabilidad.py'
            }
            archiveArtifacts artifacts: 'reports/**', allowEmptyArchive: true
        }
        unstable {
            echo 'Build UNSTABLE: hay hallazgos de seguridad. Producción NO se actualizó (gate de seguridad).'
        }
    }
}

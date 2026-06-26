
CloudGuard

This is a cloud security dashboard that I created that scans an AWS environment for common security misconfigurations and shows the findings through a flask web app.

It performs AWS security checks using boto3, stores the scan results in PostgreSQL, and runs a dockerized app deployed on EC2 with Gunicorn.  I also included Github Actions workflow for automated deployment.


Screenshots:
Dashboard_Overview.png:
Main CloudGuard dashboard displaying scan metadata, severity summaries, risk metrics, and overall security posture through the AWS environment

Risk_overview.png:
Risk overview is a security score visualization showing total findings, open risks, critical findings, and an overall security score

Scan_History_download.png:
Allows users to review previous scans and even export findings as a PDG or CSV file

Security_Checks.png:
Detailed AWS account and S3 bucket security findings with severity classification and remediation recommendations for anything detected

Security_Trend_Over_Time.png:
Historical trend visiaulization tracking PASS, WARNING, CRITICAL, and INFO findings across multiple scans to show
    change in security posture over time


Live Features

S3 Security Checks:
Public Access Block detection
Server-side encryption validation
S3 versioning checks
Bucket logging checks
Bucket policy exposure detection

AWS Account Security Checks:
CloudTrail enabled verification
CloudTrail logging status validation
Multi-region CloudTrail validation
Root account MFA verification
IAM access key age checks
IAM access key usage checks
EC2 Security Group auditing
RDS security checks

Dashboard Features:
Severity-based findings (PASS, WARNING, CRITICAL, INFO)
Security score calculation
Scan history stored in PostgreSQL
Color-coded findings
Severity summary counters
Security score trend visualization
Historical severity trend visualization
PDF report export
CSV report export

Automation Features:
Scheduled automated scans using APScheduler
Critical finding detection
Email alert framework
GitHub Actions CI/CD deployment pipeline


Tech Stack:
Python
Flask
SQLAlchemy
PostgreSQL (Neon)
Docker
Gunicorn
AWS EC2
AWS S3
AWS IAM
AWS CloudTrail
AWS RDS
boto3
APScheduler
GitHub Actions


Architecture
User
↓
AWS EC2
↓
Docker Container
↓
Gunicorn
↓
Flask Application
↓
PostgreSQL / Neon

Flask Application
↓
boto3
↓
AWS APIs
↓
S3, IAM, CloudTrail, EC2, RDS


Deployment:

CloudGuard is deployed as a Docker container on AWS EC2 and served using Gunicorn.

Continuous deployment is performed through GitHub Actions. Every push to the main branch automatically:

Connects to the EC2 instance over SSH
Pulls the latest source code
Stops and removes the existing container
Rebuilds the Docker image
Starts the updated container


Environment Variables:

DATABASE_URL=
AWS_ACCESS_KEY_ID=
AWS_SECRET_ACCESS_KEY=
AWS_DEFAULT_REGION=us-east-1

Optional:

ALERT_EMAIL_FROM=
ALERT_EMAIL_PASSWORD=
ALERT_EMAIL_TO=

Secrets will NEVER committed to the repository.



Purpose

I built CloudGuard as hands-on cloud security to give myself expereince and to include as a portfolio project.
What I wanted to show with this project is:
AWS security auditing
Flask application development
Dockerized deployments
PostgreSQL database integration
CI/CD automation
Cloud security monitoring
Automated reporting
Production troubleshooting and debugging

FUTURE ENHANCEMENTS!!!:
User authentication and RBAC
Additional AWS service checks
Real-time notifications
Multi-account AWS scanning
Compliance reporting (CIS/NIST)

CloudGuard

This is a cloud security dashboard that I created that scans an AWS environment for common security misconfigurations and shows the findings through a flask web app.

It performs AWS security checks using boto3, stores the scan results in PostgreSQL, and runs a dockerized app deployed on EC2 with Gunicorn.  I also included Github Actions workflow for automated deployment.



Live Features
AWS S3 bucket security scanning
Public Access Block detection
Server-side encryption detection
S3 versioning checks
S3 bucket logging checks
Bucket policy public access checks
CloudTrail logging and multi-region validation
Root account MFA check
IAM access key age and usage checks
Severity-based findings: PASS, WARNING, CRITICAL, INFO
Security score calculation
Scan history stored in PostgreSQL
Color-coded dashboard findings
Severity summary counters
Dockerized deployment
Gunicorn production server
GitHub Actions CI/CD deployment to AWS EC2
Security score trend visualization
Severity trend visualization for PASS, WARNING, CRITICAL, and INFO findings


Tech Stack
Python
Flask
SQLAlchemy
PostgreSQL / Neon
Docker
Gunicorn
AWS EC2
AWS S3
AWS IAM
AWS CloudTrail
boto3
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
S3, IAM, CloudTrail


Security Checks


S3 Checks

CloudGuard scans S3 buckets for:

Public Access Block configuration
Server-side encryption status
Versioning status
Bucket logging status
Bucket policy exposure


AWS Account Checks

CloudGuard also checks:

Whether CloudTrail is enabled
Whether CloudTrail is actively logging
Whether CloudTrail is multi-region
Whether root account MFA is enabled
Whether IAM access keys are older than 90 days
Whether IAM access keys appear unused


Deployment

CloudGuard is deployed on AWS EC2 as a Docker container.

The container is run with:

docker run -d   
--restart unless-stopped   
--env-file .env   
-p 5000:5000   
--name cloudguard-prod   
cloudguard

The application uses Gunicorn as the production WSGI server:

CMD \["gunicorn", "--bind", "0.0.0.0:5000", "--timeout", "120", "app:app"]


CI/CD

CloudGuard uses GitHub Actions for automated deployment.

On every push to main, GitHub Actions:

Connects to the EC2 instance over SSH
Pulls the latest code
Stops and removes the old Docker container
Rebuilds the Docker image
Starts the updated container


Environment Variables

The app requires the following environment variables:

DATABASE\_URL=
AWS\_ACCESS\_KEY\_ID=
AWS\_SECRET\_ACCESS\_KEY=
AWS\_DEFAULT\_REGION=us-east-1

Secrets are not committed to the repository.



Purpose

It was built as a hands on cloud security and DevSecOps portfolio project.
It demonstrates practical expereince with AWS security auditiing, Dockerized app deployment, PostgreSQL, Flask, CI/CD automation and A LOT of troubleshooting.


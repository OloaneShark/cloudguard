
import boto3
from botocore.exceptions import ClientError


def list_s3_buckets():
    s3 = boto3.client("s3")
    response = s3.list_buckets()

    buckets = response.get("Buckets", [])

    if not buckets:
        print("No S3 buckets found.")
        return

    for bucket in buckets:
        bucket_name = bucket["Name"]
        score = 100
        findings = []
        
        print(f"Bucket: {bucket_name}")

        public_access_passed = check_public_access_block(s3, bucket_name, findings)
        encryption_passed = check_bucket_encryption(s3, bucket_name, findings)
        versioning_passed = check_bucket_versioning(s3, bucket_name, findings)
        logging_passed = check_bucket_logging(s3, bucket_name, findings)

        if not public_access_passed:
            score -= 50

        if not encryption_passed:
            score -= 25

        if not versioning_passed:
            score -= 10
            
        if not logging_passed:
            score -= 10

        print()
        print("Findings Summary:")

        for finding in findings:
            print(f"- {finding}")

        print(f"Security Score: {score}/100")
        print()


def check_public_access_block(s3, bucket_name, findings):
    
    try:
        response = s3.get_public_access_block(Bucket=bucket_name)
        config = response["PublicAccessBlockConfiguration"]

        all_blocked = (
            config.get("BlockPublicAcls")
            and config.get("IgnorePublicAcls")
            and config.get("BlockPublicPolicy")
            and config.get("RestrictPublicBuckets")
        )

        if all_blocked:
            findings.append("PASS: Public Access Block is fully enabled")
            print("PASS: Public Access Block is fully enabled")
            return True
        else:
            findings.append("WARNING: Public Access Block is only partially enabled")
            print("WARNING: Public Access Block is only partially enabled")
            return False

    except ClientError as error:
        error_code = error.response["Error"]["Code"]

        if error_code == "NoSuchPublicAccessBlockConfiguration":
            findings.append("CRITICAL: Public Access Block is disabled")
            print("CRITICAL: Public Access Block is disabled")
            return False
        else:
            findings.append(f"ERROR: Public Access check failed - {error_code}")
            print(f"ERROR: Public Access check failed - {error_code}")
            return False


def check_bucket_encryption(s3, bucket_name, findings):
    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)

        rules = response["ServerSideEncryptionConfiguration"]["Rules"]
        encryption_type = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]

        findings.append(f"PASS: Encryption is enabled - {encryption_type}")
        print(f"PASS: Encryption is enabled - {encryption_type}")
        return True
    
    except ClientError as error:
        error_code = error.response["Error"]["Code"]

        if error_code == "ServerSideEncryptionConfigurationNotFoundError":
            findings.append("WARNING: Encryption is disabled")
            print("WARNING: Encryption is disabled")
            return False
        else:
            findings.append(f"ERROR: Encryption check failed - {error_code}")
            print(f"ERROR: Encryption check failed - {error_code}")
            return False
        
        
def check_bucket_versioning(s3, bucket_name, findings):
    response = s3.get_bucket_versioning(Bucket=bucket_name)

    versioning_status = response.get("Status")

    if versioning_status == "Enabled":
        findings.append("PASS: Versioning is enabled")
        print("PASS: Versioning is enabled")
        return True
    else:
        findings.append("WARNING: Versioning is disabled")
        print("WARNING: Versioning is disabled")
        return False
    
    
def check_bucket_logging(s3, bucket_name, findings):
    response = s3.get_bucket_logging(Bucket=bucket_name)

    logging_config = response.get("LoggingEnabled")

    if logging_config:
        findings.append("PASS: Bucket logging is enabled")
        print("PASS: Bucket logging is enabled")
        return True
    else:
        findings.append("WARNING: Bucket logging is disabled")
        print("WARNING: Bucket logging is disabled")
        return False
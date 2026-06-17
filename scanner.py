
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

        print(f"Bucket: {bucket_name}")

        public_access_passed = check_public_access_block(s3, bucket_name)
        encryption_passed = check_bucket_encryption(s3, bucket_name)

        if not public_access_passed:
            score -= 50

        if not encryption_passed:
            score -= 25

        print(f"Security Score: {score}/100")
        print()

def check_public_access_block(s3, bucket_name):
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
            print("PASS: Public Access Block is fully enabled")
            return True
        else:
            print("WARNING: Public Access Block is only partially enabled")
            return False

    except ClientError as error:
        error_code = error.response["Error"]["Code"]

        if error_code == "NoSuchPublicAccessBlockConfiguration":
            print("CRITICAL: Public Access Block is disabled")
            return False
        else:
            print(f"ERROR: Public Access check failed - {error_code}")
            return False


def check_bucket_encryption(s3, bucket_name):
    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)

        rules = response["ServerSideEncryptionConfiguration"]["Rules"]
        encryption_type = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]

        print(f"PASS: Encryption is enabled - {encryption_type}")
        return True
    
    except ClientError as error:
        error_code = error.response["Error"]["Code"]

        if error_code == "ServerSideEncryptionConfigurationNotFoundError":
            print("WARNING: Encryption is disabled")
            return False
        else:
            print(f"ERROR: Encryption check failed - {error_code}")
            return False
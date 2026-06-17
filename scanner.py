
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
        print(f"Bucket: {bucket_name}")
        check_public_access_block(s3, bucket_name)
        check_bucket_encryption(s3, bucket_name)
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
        else:
            print("WARNING: Public Access Block is only partially enabled")

    except ClientError as error:
        error_code = error.response["Error"]["Code"]

        if error_code == "NoSuchPublicAccessBlockConfiguration":
            print("CRITICAL: Public Access Block is disabled")
        else:
            print(f"ERROR: Public Access check failed - {error_code}")


def check_bucket_encryption(s3, bucket_name):
    try:
        response = s3.get_bucket_encryption(Bucket=bucket_name)

        rules = response["ServerSideEncryptionConfiguration"]["Rules"]
        encryption_type = rules[0]["ApplyServerSideEncryptionByDefault"]["SSEAlgorithm"]

        print(f"PASS: Encryption is enabled - {encryption_type}")

    except ClientError as error:
        error_code = error.response["Error"]["Code"]

        if error_code == "ServerSideEncryptionConfigurationNotFoundError":
            print("WARNING: Encryption is disabled")
        else:
            print(f"ERROR: Encryption check failed - {error_code}")
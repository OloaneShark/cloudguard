
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
        check_public_access_block(s3, bucket_name)


def check_public_access_block(s3, bucket_name):
    print(f"Bucket: {bucket_name}")

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
            print("Public Access Block: ENABLED")
            print("Status: SECURE")
        else:
            print("Public Access Block: PARTIAL")
            print("Status: WARNING")

    except ClientError as error:
        error_code = error.response["Error"]["Code"]

        if error_code == "NoSuchPublicAccessBlockConfiguration":
            print("Public Access Block: DISABLED")
            print("Status: CRITICAL")
        else:
            print(f"Error checking bucket: {error_code}")

    print()

import boto3


def list_s3_buckets():
    s3 = boto3.client("s3")
    response = s3.list_buckets()

    buckets = response.get("Buckets", [])

    if not buckets:
        print("No S3 buckets found.")
        return

    for bucket in buckets:
        print(f"Bucket: {bucket['Name']}")
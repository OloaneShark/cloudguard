
import boto3
from scanner import list_s3_buckets


print("CloudGuard Security Scan")
print("Checking S3 buckets...")
print()


list_s3_buckets()
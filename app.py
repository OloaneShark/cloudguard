"""AWS Bucket implemented on June 17, 2026 at 9:47 am est"""


import boto3
from scanner import list_s3_buckets


print("CloudGuard Security Scan")
print("Checking S3 buckets...")
print()


list_s3_buckets()

import boto3

def test_boto3():
    print('boto3 successfully imported!')
    
    try:
        session = boto3.Session()
        region = session.region_name
        print(f"AWS configuration found. Default region {region}")
    
    except Exception as e:
        print("boto3 is imported, but no default AWS region was detected")
        
if __name__ == "__main__":
    test_boto3()
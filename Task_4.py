import boto3
from os import getenv
from dotenv import load_dotenv
import logging
from botocore.exceptions import ClientError
import magic
import os
import argparse


load_dotenv()


def init_client():
    try:
        client = boto3.client("s3",
                              aws_access_key_id=getenv("aws_access_key_id"),
                              aws_secret_access_key=getenv(
                                  "aws_secret_access_key"),
                              aws_session_token=getenv("aws_session_token"),
                              region_name=getenv("aws_region_name")

                              )

        client.list_buckets()

        return client
    except ClientError as e:
        logging.error(e)
    except:
        logging.error("Unexpected error")


def list_buckets(aws_s3_client):
    try:

        return aws_s3_client.list_buckets()
    except ClientError as e:
        logging.error(e)
        return False


def create_bucket(aws_s3_client, bucket_name, region=getenv("aws_region_name")):
    try:
        location = {'LocationConstraint': region}

        response = aws_s3_client.create_bucket(
            Bucket=bucket_name,
            CreateBucketConfiguration=location
        )
    except ClientError as e:
        logging.error(e)
        return False
    status_code = response["ResponseMetadata"]["HTTPStatusCode"]
    if status_code == 200:
        return True
    return False


def delete_bucket(aws_s3_client, bucket_name):
    try:

        response = aws_s3_client.delete_bucket(Bucket=bucket_name)
    except ClientError as e:
        logging.error(e)
        return False
    status_code = response["ResponseMetadata"]["HTTPStatusCode"]
    if status_code == 200:
        return True
    return False


def bucket_exists(aws_s3_client, bucket_name):
    try:
        response = aws_s3_client.head_bucket(Bucket=bucket_name)
    except ClientError as e:
        logging.error(e)
        return False
    status_code = response["ResponseMetadata"]["HTTPStatusCode"]
    if status_code == 200:
        return True
    return False


def download_file_and_upload_to_s3(aws_s3_client, bucket_name, url, file_name, keep_local=False):
    valid_formats = ['image/jpeg', 'image/png', 'image/webp', 'image/bmp', 'video/mp4']
    with magic.Magic() as mime:

        content_type = mime.from_file(url)

        if content_type not in valid_formats:
            logging.error("Invalid file format!")
            return

    with open(url, 'rb') as f:
        content = f.read()

    try:

        import io
        aws_s3_client.upload_fileobj(
            Fileobj=io.BytesIO(content),
            Bucket=bucket_name,
            ExtraArgs={'ContentType': content_type},
            Key=file_name
        )
    except Exception as e:
        logging.error(e)

    if keep_local:
        os.rename(url, file_name)

    return "https://s3-{0}.amazonaws.com/{1}/{2}".format(
        'us-east-1',
        bucket_name,
        file_name
    )


def set_object_access_policy(aws_s3_client, bucket_name, file_name):
    try:
        response = aws_s3_client.put_object_acl(
            ACL="public-read",
            Bucket=bucket_name,
            Key=file_name
        )
    except ClientError as e:
        logging.error(e)
        return False
    status_code = response["ResponseMetadata"]["HTTPStatusCode"]
    if status_code == 200:
        return True
    return False


def generate_public_read_policy(bucket_name):
    import json
    policy = {
        "Version": "2012-10-17",
        "Statement": [
            {
                "Sid": "PublicReadGetObject",
                "Effect": "Allow",
                "Principal": "*",
                "Action": "s3:GetObject",
                "Resource": f"arn:aws:s3:::{bucket_name}/*",
            }
        ],
    }

    return json.dumps(policy)


def create_bucket_policy(aws_s3_client, bucket_name):
    aws_s3_client.put_bucket_policy(
        Bucket=bucket_name, Policy=generate_public_read_policy(bucket_name)
    )
    print("Bucket policy created successfully")


def read_bucket_policy(aws_s3_client, bucket_name):
    try:
        policy = aws_s3_client.get_bucket_policy(Bucket=bucket_name)
        policy_str = policy["Policy"]
        print(policy_str)
    except ClientError as e:
        logging.error(e)
        return False


def main():
    parser = argparse.ArgumentParser(description="Create or check existence of an S3 bucket")
    parser.add_argument("bucket_name", type=str, help="Name of the S3 bucket")
    parser.add_argument("-r", "--region", type=str, default="us-east-1", help="Region of the S3 bucket")
    parser.add_argument("-a", "--access_key_id", type=str, help="AWS access key ID")
    parser.add_argument("-s", "--secret_access_key", type=str, help="AWS secret access key")
    parser.add_argument("-t", "--session_token", type=str, help="AWS session token")
    args = parser.parse_args()

    parser = argparse.ArgumentParser(description='Download a file and upload it to an S3 bucket')
    parser.add_argument('bucket_name', type=str, help='The name of the S3 bucket to upload the file to')
    parser.add_argument('url', type=str, help='The URL of the file to download')
    parser.add_argument('file_name', type=str, help='The name to give the file in the S3 bucket')
    parser.add_argument('--keep-local', action='store_true',
                        help='Whether or not to keep the downloaded file locally after uploading to S3')
    args = parser.parse_args()

    parser = argparse.ArgumentParser(description='Delete an S3 bucket')
    parser.add_argument('bucket_name', type=str, help='The name of the S3 bucket to delete')
    args = parser.parse_args()

    parser = argparse.ArgumentParser(description='Set the access policy of an S3 object')
    parser.add_argument('bucket_name', type=str, help='The name of the S3 bucket containing the object')
    parser.add_argument('file_name', type=str, help='The name of the object whose access policy is being set')
    args = parser.parse_args()

    parser = argparse.ArgumentParser(description='Generate a public read access policy for an S3 bucket')
    parser.add_argument('bucket_name', type=str, help='The name of the S3 bucket')
    args = parser.parse_args()

    parser = argparse.ArgumentParser(description='Create a public read access policy for an S3 bucket')
    parser.add_argument('bucket_name', type=str, help='The name of the S3 bucket')
    args = parser.parse_args()

    parser = argparse.ArgumentParser(description='Read the policy of an S3 bucket')
    parser.add_argument('bucket_name', type=str, help='The name of the S3 bucket')
    args = parser.parse_args()


    s3_client = init_client(args.access_key_id, args.secret_access_key, args.session_token, args.region)
    create_bucket(s3_client, args.bucket_name, args.region)
    buckets = list_buckets(s3_client)

    if buckets:
        for bucket in buckets['Buckets']:
            if bucket["Name"] == args.bucket_name:
                print(f"Bucket '{args.bucket_name}' exists.")




if __name__ == "__main__":
    main()

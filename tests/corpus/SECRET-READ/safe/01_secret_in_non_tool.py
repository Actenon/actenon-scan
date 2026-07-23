import boto3

def internal_get_secret(secret_id):
    client = boto3.client("secretsmanager")
    return client.get_secret_value(SecretId=secret_id)

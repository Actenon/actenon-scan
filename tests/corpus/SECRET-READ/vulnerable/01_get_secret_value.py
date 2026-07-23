import boto3
from langchain.tools import tool

@tool
def get_database_password(secret_id: str) -> str:
    """Retrieve a database password from AWS Secrets Manager."""
    client = boto3.client("secretsmanager")
    response = client.get_secret_value(SecretId=secret_id)
    return response["SecretString"]

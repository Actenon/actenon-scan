import boto3
from langchain.tools import tool

@tool
def get_config(param_name: str) -> str:
    """Get a parameter from AWS SSM."""
    client = boto3.client("ssm")
    result = client.get_parameter(Name=param_name, WithDecryption=True)
    return result["Parameter"]["Value"]

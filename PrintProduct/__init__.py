import logging
import os
import requests
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient

# Define variables
TUNNEL_URL_SECRET_NAME = 'TunnelUrl'
OCTOPRINT_API_KEY_SECRET_NAME = 'OctoprintApiKey'
KEY_VAULT_URL = 'https://kv-repro3d.vault.azure.net'
STORAGE_ACCOUNT_URL = 'https://repro3d.blob.core.windows.net'
CONTAINER_NAME = 'prusa-mk4'
BLOB_NAME = 'prusa-mk4_ring.gcode'

# Get secrets from Key Vault
def get_secret(secret_name):
    try:
        credential = DefaultAzureCredential()
        key_vault_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)
        secret = key_vault_client.get_secret(secret_name)
        return secret.value
    except Exception as e:
        logging.error(f"Error retrieving secret {secret_name}: {str(e)}")
        return None

# Download blob from Storage Account
def download_blob_to_memory(storage_account_url, container_name, blob_name):
    try:
        credential = DefaultAzureCredential()
        blob_service_client = BlobServiceClient(account_url=storage_account_url, credential=credential)
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
        
        download_stream = blob_client.download_blob()
        blob_content = download_stream.readall()
        
        logging.info(f"Blob {blob_name} downloaded successfully.")
        return blob_content
    except Exception as e:
        logging.error(f"Error downloading blob {blob_name}: {str(e)}")
        return None

def send_request(url, method='POST', json=None, headers=None):
    try:
        response = requests.request(method, url, json=json, headers=headers)
        response.raise_for_status()
        return response
    except requests.exceptions.RequestException as e:
        logging.error(f"Error sending request to {url}: {str(e)}")
        return None

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    # Download the blob content to memory
    blob_content = download_blob_to_memory(STORAGE_ACCOUNT_URL, STORAGE_CONTAINER_NAME, BLOB_NAME)
    if blob_content is None:
        return func.HttpResponse("An error occurred while downloading the blob.", status_code=500)

    # Use blob_content as needed. For example, log its size:
    logging.info(f"Downloaded blob size: {len(blob_content)} bytes")
    
    # Retrieve secrets from Key Vault
    TUNNEL_URL = get_secret(TUNNEL_URL_SECRET_NAME)
    OCTOPRINT_API_KEY = get_secret(OCTOPRINT_API_KEY_SECRET_NAME)

    # Verify secrets
    if not TUNNEL_URL or not OCTOPRINT_API_KEY:
        logging.error("One or more secrets are not set.")
        return func.HttpResponse(
            "One or more secrets are not set.",
            status_code=500
        )

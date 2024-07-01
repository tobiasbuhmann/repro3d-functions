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

# Function to get secrets from Key Vault
def get_secret(secret_name):
    try:
        credential = DefaultAzureCredential()
        key_vault_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)
        secret = key_vault_client.get_secret(secret_name)
        return secret.value
    except Exception as e:
        logging.error(f"Error retrieving secret {secret_name}: {str(e)}")
        return None

def download_blob(storage_account_url, container_name, blob_name):
    try:
        credential = DefaultAzureCredential()
        blob_service_client = BlobServiceClient(account_url=storage_account_url, credential=credential)
        blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
        
        with open(blob_name, "wb") as file:
            download_stream = blob_client.download_blob()
            file.write(download_stream.readall())
        
        logging.info(f"Blob {blob_name} downloaded successfully.")
        return blob_name
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

    # Download a specific blob from Azure Storage
    blob_file = download_blob(STORAGE_ACCOUNT_URL, CONTAINER_NAME, BLOB_NAME)
    if not blob_file:
        return func.HttpResponse("An error occurred while downloading the blob.", status_code=500)
    
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

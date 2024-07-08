import logging
import hmac
import hashlib
import base64
import requests
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient

import azure.functions as func

# Configurations & constants
CONFIG = {
    "KEY_VAULT_URL": 'https://kv-repro3d.vault.azure.net',
    "STORAGE_ACCOUNT_URL": 'https://repro3d.blob.core.windows.net',
    "CONTAINER_NAME": 'prusa-mk4',
    "BLOB_NAME": 'keychain.gcode',
    "TUNNEL_URL_SECRET_NAME": 'TunnelUrl',
    "OCTOPRINT_API_KEY_SECRET_NAME": 'OctoprintApiKey',
    "SHOPIFY_SECRET_NAME": "ShopifySecret"
}

credential = DefaultAzureCredential()
http_session = requests.Session()

# Retrieve secret from Azure Key Vault
def get_secret(secret_name):
    key_vault_client = SecretClient(vault_url=CONFIG["KEY_VAULT_URL"], credential=credential)
    secret = key_vault_client.get_secret(secret_name)
    return secret.value

def download_blob_to_memory(storage_account_url, container_name, blob_name):
    # Download blob from Azure Storage to memory
    blob_service_client = BlobServiceClient(account_url=storage_account_url, credential=credential)
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
    with blob_client.download_blob() as download_stream:
        return download_stream.readall()

# Upload file to OctoPrint
def upload_file_to_octoprint(tunnel_url, api_key, file_name, file_content):
    headers = {'X-Api-Key': api_key}
    files = {'file': (file_name, file_content)}
    response = http_session.post(f"{tunnel_url}/api/files/local", headers=headers, files=files)
    response.raise_for_status()
    return response.json()

# Start print job in OctoPrint
def start_print_job(tunnel_url, api_key, file_name):
    headers = {'X-Api-Key': api_key}
    data = {'command': 'select', 'print': True}
    response = http_session.post(f"{tunnel_url}/api/files/local/{file_name}", headers=headers, json=data)
    response.raise_for_status()
    return response.json()

# Verify Shopify webhook authenticity
def verify_shopify_webhook(req, shopify_secret):
    hmac_header = req.headers.get('X-Shopify-Hmac-Sha256')
    if not hmac_header:
        return False
    body = req.get_body()
    hash = hmac.new(shopify_secret.encode(), body, hashlib.sha256).digest()
    calculated_hmac = base64.b64encode(hash).decode()
    return hmac_header == calculated_hmac

# Main function
def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    try:
        TUNNEL_URL = get_secret(CONFIG.get("TUNNEL_URL_SECRET_NAME", ""))
        OCTOPRINT_API_KEY = get_secret(CONFIG.get("OCTOPRINT_API_KEY_SECRET_NAME", ""))
        SHOPIFY_SECRET = get_secret(CONFIG.get("SHOPIFY_SECRET_NAME", ""))
    except Exception as e:
        logging.error(f"Error retrieving secrets: {str(e)}")
        return func.HttpResponse(f"Error retrieving secrets: {str(e)}", status_code=500)

    if not verify_shopify_webhook(req, SHOPIFY_SECRET):
        return func.HttpResponse("Unauthorized", status_code=401)

    try:
        storage_account_url = CONFIG.get("STORAGE_ACCOUNT_URL", "")
        container_name = CONFIG.get("CONTAINER_NAME", "")
        blob_name = CONFIG.get("BLOB_NAME", "")
        blob_content = download_blob_to_memory(storage_account_url, container_name, blob_name)
        upload_response = upload_file_to_octoprint(TUNNEL_URL, OCTOPRINT_API_KEY, blob_name, blob_content)
        print_response = start_print_job(TUNNEL_URL, OCTOPRINT_API_KEY, blob_name)
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return func.HttpResponse(f"Error: {str(e)}", status_code=500)

    return func.HttpResponse(f"File uploaded and print started successfully: {print_response}", status_code=200)

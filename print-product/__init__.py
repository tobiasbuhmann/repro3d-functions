import logging
import hmac
import hashlib
import base64
import requests
import time
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient
from azure.storage.blob import BlobServiceClient

# Define variables
KEY_VAULT_URL = 'https://kv-repro3d.vault.azure.net'
STORAGE_ACCOUNT_URL = 'https://repro3d.blob.core.windows.net'
CONTAINER_NAME = 'prusa-mk4'
BLOB_NAME = 'prusa-mk4_ring.gcode'
TUNNEL_URL_SECRET_NAME = 'TunnelUrl'
OCTOPRINT_API_KEY_SECRET_NAME = 'OctoprintApiKey'
SHOPIFY_SECRET_NAME = "ShopifySecret"

# Initialize Azure credentials
credential = DefaultAzureCredential()

# Get secrets from Key Vault
def get_secret(secret_name):
    try:
        key_vault_client = SecretClient(vault_url=KEY_VAULT_URL, credential=credential)
        secret = key_vault_client.get_secret(secret_name)
        return secret.value
    except Exception as e:
        logging.error(f"Error retrieving secret {secret_name}: {str(e)}")
        raise

# Blob Downloader Class
class BlobDownloader:
    def __init__(self, account_url, credential):
        self.blob_service_client = BlobServiceClient(account_url=account_url, credential=credential)

    def download_blob(self, container_name, blob_name):
        blob_client = self.blob_service_client.get_blob_client(container_name, blob_name)
        download_stream = blob_client.download_blob()
        blob_content = download_stream.readall() 
        return blob_content

# Download blob content
async def download_blob_to_memory(storage_account_url, container_name, blob_name):
    downloader = BlobDownloader(storage_account_url, credential)
    blob_content = await downloader.download_blob(container_name, blob_name)
    logging.info(f"Blob {blob_name} downloaded successfully.")
    return blob_content

# Upload file to OctoPrint
async def upload_file_to_octoprint(tunnel_url, api_key, file_name, file_content):
    headers = {'X-Api-Key': api_key}
    files = {'file': (file_name, file_content)}
    response = requests.post(f"{tunnel_url}/api/files/local", headers=headers, files=files)
    response.raise_for_status()
    logging.info(f"File {file_name} uploaded to OctoPrint successfully.")
    return response.json()

# Start print job on OctoPrint
async def start_print_job(tunnel_url, api_key, file_name):
    headers = {'X-Api-Key': api_key}
    data = {'command': 'select', 'print': True}
    response = requests.post(f"{tunnel_url}/api/files/local/{file_name}", headers=headers, json=data)
    response.raise_for_status()
    logging.info(f"Print job for {file_name} started successfully.")
    return response.json()

# Delete file on OctoPrint
async def delete_file_on_octoprint(tunnel_url, api_key, file_name):
    headers = {'X-Api-Key': api_key}
    response = requests.delete(f"{tunnel_url}/api/files/local/{file_name}", headers=headers)
    response.raise_for_status()
    logging.info(f"File {file_name} deleted from OctoPrint successfully.")
    return response.json()

# Monitor print job on OctoPrint
async def monitor_print_job(tunnel_url, api_key):
    headers = {'X-Api-Key': api_key}
    while True:
        response = requests.get(f"{tunnel_url}/api/job", headers=headers)
        response.raise_for_status()
        job_status = response.json()
        state = job_status.get('state')
        logging.info(f"Current print job state: {state}")
        if state in ['Operational', 'Paused']:
            return job_status
        elif state == 'Error':
            logging.error("Print job encountered an error.")
            raise Exception("Print job encountered an error.")
        time.sleep(30)  # Wait for 30 seconds before checking again

# Verify Shopify webhook
def verify_shopify_webhook(req, shopify_secret):
    hmac_header = req.headers.get('X-Shopify-Hmac-Sha256')
    if not hmac_header:
        return False

    body = req.get_body()
    hash = hmac.new(shopify_secret.encode(), body, hashlib.sha256).digest()
    calculated_hmac = base64.b64encode(hash).decode()

    return hmac_header == calculated_hmac


# Main
async def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    # Retrieve secrets from Key Vault
    try:
        TUNNEL_URL = get_secret(TUNNEL_URL_SECRET_NAME)
        OCTOPRINT_API_KEY = get_secret(OCTOPRINT_API_KEY_SECRET_NAME)
        SHOPIFY_SECRET = get_secret(SHOPIFY_SECRET_NAME)
    except Exception as e:
        return func.HttpResponse(
            f"Error retrieving secrets: {str(e)}",
            status_code=500
        )

    # Verify the webhook signature
    if not verify_shopify_webhook(req, SHOPIFY_SECRET):
        return func.HttpResponse("Unauthorized", status_code=401)

    # Download the blob content to memory asynchronously
    blob_content = download_blob_to_memory(STORAGE_ACCOUNT_URL, CONTAINER_NAME, BLOB_NAME)
    if blob_content is None:
        return func.HttpResponse("An error occurred while downloading the blob.", status_code=500)

    # Upload the file to OctoPrint asynchronously
    try:
        upload_response = await upload_file_to_octoprint(TUNNEL_URL, OCTOPRINT_API_KEY, BLOB_NAME, blob_content)
    except Exception as e:
        logging.error(f"Error uploading file to OctoPrint: {str(e)}")
        return func.HttpResponse(
            f"An error occurred: {str(e)}",
            status_code=500
        )

    # Start the print job on OctoPrint asynchronously
    try:
        print_response = await start_print_job(TUNNEL_URL, OCTOPRINT_API_KEY, BLOB_NAME)
    except Exception as e:
        logging.error(f"Error starting print job: {str(e)}")
        return func.HttpResponse(
            f"An error occurred while starting the print job: {str(e)}",
            status_code=500
        )

    # Monitor the print job and delete the file after a successful print
    try:
        job_status = await monitor_print_job(TUNNEL_URL, OCTOPRINT_API_KEY)
        if job_status.get('state') == 'Operational':
            delete_response = await delete_file_on_octoprint(TUNNEL_URL, OCTOPRINT_API_KEY, BLOB_NAME)
        else:
            logging.error(f"Unexpected print job state: {job_status.get('state')}")
            return func.HttpResponse(
                f"Unexpected print job state: {job_status.get('state')}",
                status_code=500
            )
    except Exception as e:
        logging.error(f"Error during print job monitoring or file deletion: {str(e)}")
        return func.HttpResponse(
            f"An error occurred: {str(e)}",
            status_code=500
        )

    return func.HttpResponse(
        f"File uploaded, print started, and file deleted successfully: {print_response}",
        status_code=200
    )

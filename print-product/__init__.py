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

# Configurations & Constants
CONFIG = {
    "KEY_VAULT_URL": 'https://kv-repro3d.vault.azure.net',
    "STORAGE_ACCOUNT_URL": 'https://repro3d.blob.core.windows.net',
    "CONTAINER_NAME": 'prusa-mk4',
    "BLOB_NAME": 'keychain.gcode',
    "TUNNEL_URL_SECRET_NAME": 'TunnelUrl',
    "OCTOPRINT_API_KEY_SECRET_NAME": 'OctoprintApiKey',
    "SHOPIFY_SECRET_NAME": "ShopifySecret",
    "POLL_INTERVAL": 30
}

credential = DefaultAzureCredential()
http_session = requests.Session()

def get_secret(secret_name):
    key_vault_client = SecretClient(vault_url=CONFIG["KEY_VAULT_URL"], credential=credential)
    secret = key_vault_client.get_secret(secret_name)
    return secret.value

def download_blob_to_memory(storage_account_url, container_name, blob_name):
    blob_service_client = BlobServiceClient(account_url=storage_account_url, credential=credential)
    blob_client = blob_service_client.get_blob_client(container=container_name, blob=blob_name)
    download_stream = blob_client.download_blob()
    return download_stream.readall()

def upload_file_to_octoprint(tunnel_url, api_key, file_name, file_content):
    headers = {'X-Api-Key': api_key}
    files = {'file': (file_name, file_content)}
    response = http_session.post(f"{tunnel_url}/api/files/local", headers=headers, files=files)
    response.raise_for_status()
    return response.json()

def start_print_job(tunnel_url, api_key, file_name):
    headers = {'X-Api-Key': api_key}
    data = {'command': 'select', 'print': True}
    response = http_session.post(f"{tunnel_url}/api/files/local/{file_name}", headers=headers, json=data)
    response.raise_for_status()
    return response.json()

def delete_file_on_octoprint(tunnel_url, api_key, file_name):
    headers = {'X-Api-Key': api_key}
    response = http_session.delete(f"{tunnel_url}/api/files/local/{file_name}", headers=headers)
    response.raise_for_status()
    return response.json()

def monitor_print_job(tunnel_url, api_key, file_name):
    headers = {'X-Api-Key': api_key}
    initial_poll_interval = CONFIG["POLL_INTERVAL"]
    max_poll_interval = 300
    poll_interval = initial_poll_interval
    while True:
        response = http_session.get(f"{tunnel_url}/api/job", headers=headers)
        response.raise_for_status()
        job_status = response.json()
        state = job_status.get('state')
        logging.info(f"Current print job state: {state}")
        if state in ['Operational', 'Paused']:
            return job_status
        elif state == 'Error':
            raise Exception("Print job encountered an error.")
        elif state == 'Finished':
            delete_file_on_octoprint(tunnel_url, api_key, file_name)
            logging.info(f"File {file_name} deleted after job completion.")
            return job_status
        time.sleep(poll_interval)
        poll_interval = min(poll_interval + 30, max_poll_interval)

def verify_shopify_webhook(req, shopify_secret):
    hmac_header = req.headers.get('X-Shopify-Hmac-Sha256')
    if not hmac_header:
        return False
    body = req.get_body()
    hash = hmac.new(shopify_secret.encode(), body, hashlib.sha256).digest()
    calculated_hmac = base64.b64encode(hash).decode()
    return hmac_header == calculated_hmac

def main(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')
    try:
        TUNNEL_URL = get_secret(CONFIG["TUNNEL_URL_SECRET_NAME"])
        OCTOPRINT_API_KEY = get_secret(CONFIG["OCTOPRINT_API_KEY_SECRET_NAME"])
        SHOPIFY_SECRET = get_secret(CONFIG["SHOPIFY_SECRET_NAME"])
    except Exception as e:
        logging.error(f"Error retrieving secrets: {str(e)}")
        return func.HttpResponse(f"Error retrieving secrets: {str(e)}", status_code=500)

    if not verify_shopify_webhook(req, SHOPIFY_SECRET):
        return func.HttpResponse("Unauthorized", status_code=401)

    try:
        blob_content = download_blob_to_memory(CONFIG["STORAGE_ACCOUNT_URL"], CONFIG["CONTAINER_NAME"], CONFIG["BLOB_NAME"])
        upload_response = upload_file_to_octoprint(TUNNEL_URL, OCTOPRINT_API_KEY, CONFIG["BLOB_NAME"], blob_content)
        print_response = start_print_job(TUNNEL_URL, OCTOPRINT_API_KEY, CONFIG["BLOB_NAME"])
        job_status = monitor_print_job(TUNNEL_URL, OCTOPRINT_API_KEY, CONFIG["BLOB_NAME"])
    except Exception as e:
        logging.error(f"Error: {str(e)}")
        return func.HttpResponse(f"Error: {str(e)}", status_code=500)

    return func.HttpResponse(f"File uploaded, print started, and file deleted successfully: {print_response}", status_code=200)
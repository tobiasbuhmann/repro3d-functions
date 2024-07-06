import logging
import requests
import azure.functions as func
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

# Define Key Vault secrets names
KEY_VAULT_URL = 'https://kv-repro3d.vault.azure.net'
TUNNEL_URL_SECRET_NAME = 'TunnelUrl'
OCTOPRINT_API_KEY_SECRET_NAME = 'OctoprintApiKey'

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

    # Retrieve secrets from Key Vault
    try:
        TUNNEL_URL = get_secret(TUNNEL_URL_SECRET_NAME)
        OCTOPRINT_API_KEY = get_secret(OCTOPRINT_API_KEY_SECRET_NAME)
    except Exception as e:
        return func.HttpResponse(
            f"Error retrieving secrets: {str(e)}",
            status_code=500
        )

    # Define the move command
    move_command = {
        "command": "jog",
        "x": 10,
        "y": 10,
        "z": 0
    }

    headers = {'X-Api-Key': OCTOPRINT_API_KEY, 'Content-Type': 'application/json'}

    # Send move command to OctoPrint using the tunnel URL
    response = send_request(f"{TUNNEL_URL}/api/printer/printhead", json=move_command, headers=headers)

    if response is None:
        return func.HttpResponse("An error occurred while moving the printer.", status_code=500)

    if response.status_code == 204:
        return func.HttpResponse("Printer moved successfully. No content returned.", status_code=200)

    try:
        response_data = response.json()
        return func.HttpResponse(f"Printer moved successfully: {response_data}", status_code=200)
    except ValueError:
        logging.error("Failed to parse response as JSON")
        return func.HttpResponse(f"Error: Failed to parse response as JSON\nResponse content: {response.text}", status_code=500)

"""
Sample Code is provided for the purpose of illustration only and is not intended to be used in a production environment. 
THIS SAMPLE CODE AND ANY RELATED INFORMATION ARE PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, 
EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A PARTICULAR PURPOSE. 
We grant You a nonexclusive, royalty-free right to use and modify the Sample Code and to reproduce and distribute the object code form of the Sample Code, 
provided that you agree: 
(i) to not use Our name, logo, or trademarks to market Your software product in which the Sample Code is embedded; 
(ii) to include a valid copyright notice on Your software product in which the Sample Code is embedded; and 
(iii) to indemnify, hold harmless, and defend Us and Our suppliers from and against any claims or lawsuits, 
including attorneys’ fees, that arise or result from the use or distribution of the Sample Code    
"""


import azure.functions as func
import logging
import paramiko
import os
import tempfile
from azure.identity import DefaultAzureCredential
from azure.keyvault.secrets import SecretClient

app = func.FunctionApp(http_auth_level=func.AuthLevel.FUNCTION)

@app.route(route="get_ID")
def get_ID(req: func.HttpRequest) -> func.HttpResponse:
    """
    Function entry point that returns the query string value of id-token.
    
    Args:
        req: HTTP request object
        
    Returns:
        HTTP response containing the id-token value or an error message
    """
    logging.info('get_ID function processed a request.')

    try:
        # Get id_token from query parameters
        id_token = req.params.get('id_token')
        
        if not id_token:
            # Try to get from JSON request body
            try:
                req_body = req.get_json()
                if req_body:
                    id_token = req_body.get('id_token')
                    logging.info('ID token found in JSON body')
            except ValueError:
                logging.warning('Failed to parse request body as JSON')
                pass
        
        if not id_token:
            # Try to get from form data (application/x-www-form-urlencoded)
            try:
                form_data = req.get_body().decode('utf-8')
                if form_data:
                    # Parse form data manually
                    from urllib.parse import parse_qs
                    parsed_form = parse_qs(form_data)
                    if 'id_token' in parsed_form:
                        id_token = parsed_form['id_token'][0]  # get_qs returns lists
                        logging.info('ID token found in form data')
            except Exception as e:
                logging.warning(f'Failed to parse form data: {str(e)}')
                pass

        # Log all available parameters for debugging
        logging.info(f"Available query parameters: {dict(req.params)}")
        logging.info(f"Request method: {req.method}")
        logging.info(f"Content-Type: {req.headers.get('Content-Type', 'Not specified')}")

        if id_token:
            logging.info('ID token retrieved successfully')
            # Truncate token for security in logs (show only first and last few characters)
            token_preview = f"{id_token[:10]}...{id_token[-10:]}" if len(id_token) > 20 else id_token
            logging.info(f"Token preview: {token_preview}")
            
            return func.HttpResponse(
                f"ID Token: {id_token}",
                status_code=200,
                headers={"Content-Type": "text/plain"}
            )
        else:
            logging.warning('ID token not found in request')
            return func.HttpResponse(
                f"Parameter 'id_token' is required. Available methods:\n"
                f"1. Query parameter: ?id_token=<token_value>\n"
                f"2. JSON body: {{\"id_token\": \"<token_value>\"}}\n"
                f"3. Form data: id_token=<token_value>\n"
                f"Available params: {dict(req.params)}",
                status_code=400,
                headers={"Content-Type": "text/plain"}
            )
            
    except Exception as e:
        logging.error(f"Error processing get_ID request: {str(e)}")
        return func.HttpResponse(
            f"Internal server error: {str(e)}",
            status_code=500,
            headers={"Content-Type": "text/plain"}
        )

@app.route(route="hellow_world_trigger")
def hellow_world_trigger(req: func.HttpRequest) -> func.HttpResponse:
    logging.info('Python HTTP trigger function processed a request.')

    sshcommand = req.params.get('sshcommand')
    if not sshcommand:
        try:
            req_body = req.get_json()
        except ValueError:
            pass
        else:
            sshcommand = req_body.get('sshcommand')

    if sshcommand:
        status_code, ssh_ret = ssh_connect(sshcommand)
        if status_code == 0:
            return func.HttpResponse(f"input: {sshcommand}, SSH command executed fail: {ssh_ret}", status_code=500)
        elif status_code == 1:
            return func.HttpResponse(f"input: {sshcommand}. SSH command executed successfully: {ssh_ret}", status_code=200)
    else:
        return func.HttpResponse("parameter sshcommand is expected, use parameter: ?sshcommand=<sshcommand>", status_code=404 )
        
def ssh_connect(sshcommand: str) -> tuple[int, str]:
# SSH connection details
    hostname = "172.21.193.77"
    port = 22
    username = "linkaiyu"
      # Key Vault details - getting from environment variables
    key_vault_url = "https://private-key-kv.vault.azure.net/"
    secret_name = "ssh-key"
    
    # Optional: passphrase if your key is protected
    passphrase = None  # Set to a string if needed

# Command to run
    #remote_command = "bash ./helloworld.sh"

    try:
        # Get private key from Key Vault
        #private_key_path = get_private_key_from_keyvault(key_vault_url, secret_name)
        private_key_path = get_private_key_from_keyvault(key_vault_url, secret_name)
        
        # Create SSH client
        ssh = paramiko.SSHClient()
        ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        
        # Load private key
        if passphrase:
            private_key = paramiko.RSAKey.from_private_key_file(private_key_path, password=passphrase)
        else:
            private_key = paramiko.RSAKey.from_private_key_file(private_key_path)
            
        logging.info(f"Private key loaded: {private_key}")
        
        # Connect using private key
        ssh.connect(hostname, port, username, pkey=private_key)        # Execute command
        stdin, stdout, stderr = ssh.exec_command(sshcommand)
        output = stdout.read().decode()
        error = stderr.read().decode()
        ssh.close()
        
        # Clean up the temporary private key file
        if os.path.exists(private_key_path):
            os.unlink(private_key_path)
            logging.info(f"Temporary private key file removed: {private_key_path}")
        
        if error:
            return error, output
        else:
            return 1, output

    except Exception as e:
        logging.error(f"SSH execution failed: {str(e)}")
        # Make sure to clean up the temporary file even if an error occurs
        if 'private_key_path' in locals() and os.path.exists(private_key_path):
            os.unlink(private_key_path)
            logging.info(f"Temporary private key file removed after error: {private_key_path}")
        return 0, f"SSH execution failed: {str(e)}"

def get_private_key_from_keyvault(key_vault_url, secret_name)->str:
    """
    Retrieves a private key from Azure Key Vault and saves it to a temporary file.
    
    Args:
        key_vault_url (str): URL of the Azure Key Vault (e.g., "https://myvault.vault.azure.net/")
        secret_name (str): Name of the secret containing the private key
        
    Returns:
        str: Path to the temporary file containing the private key
    """
    try:
        # Check if we can use the local private key file instead of Key Vault
        
        local_key_path = "id_rsa.pem"
        if os.path.exists(local_key_path):
            logging.info(f"Using local private key file: {local_key_path}")
            return local_key_path
        # Use DefaultAzureCredential which supports multiple authentication methods
        # When running locally, it will try to use Azure CLI, Visual Studio, etc.
        # When deployed to Azure, it will use managed identity
        logging.info("Authenticating with Azure using DefaultAzureCredential")
        
        # Create the credential with detailed logging
        credential = DefaultAzureCredential(logging_enable=True)
        secret_client = SecretClient(vault_url=key_vault_url, credential=credential)
        
        # Retrieve the secret containing the private key
        logging.info(f"Retrieving private key '{secret_name}' from Key Vault")
        secret = secret_client.get_secret(secret_name)
        logging.info(f"Private key retried from key vault: {secret}")

        # Create a temporary file to store the private key
        # Using delete=False to keep the file after closing it
        fd, temp_path = tempfile.mkstemp(suffix='.pem')
        
        try:
            # Write the private key to the temporary file
            with os.fdopen(fd, 'w') as temp_file:
                temp_file.write(secret.value)
            
            # Set appropriate permissions for the private key file (only owner can read)
            os.chmod(temp_path, 0o600)
            
            logging.info(f"Private key saved to temporary file: {temp_path}")
            return temp_path
        
        except Exception as e:
            # Handle errors while writing to file
            logging.error(f"Failed to write private key to temporary file: {str(e)}")
            # Clean up the temp file if an error occurs
            if os.path.exists(temp_path):
                os.unlink(temp_path)
            raise
    except Exception as e:
        # Handle errors from Key Vault operations
        logging.error(f"Failed to retrieve private key from Key Vault: {str(e)}")
        raise

import click
import os
import json
import getpass

from ..bitwarden.Bitwarden import Bitwarden

class AuthenticationFailedException(Exception):
    def __init__(self, email, url):
        super().__init__(self, "Authentication failed for %s on %s" % (email, url))

def getAuthenticator(acct_config, server_url, root_ca_path):
    """
    Handles process of inspecting account configuration to generate
    the appropriate authenticator for handling the unlock operations.
    """

    if('client_id' in acct_config and 'client_secret' in acct_config):
        return BitwardenApiKeyAuthenticator(acct_config, server_url, root_ca_path)
    else:
        return BitwardenPasswordAuthenticator(acct_config, server_url, root_ca_path)

class BitwardenPasswordAuthenticator(object):
    """
    Handles the process of unlocking the vault using password
    based login. The password based login is able to perform
    the authentication and unlock in a single step.
    """

    def __init__(self, acct_config, server_url = r'https://vault.bitwarden.com', root_ca_path = None):
        self.account = acct_config
        self.url = server_url
        self._bw = Bitwarden(serverUrl=server_url, ca_cert_path=root_ca_path)

    @property
    def bw(self):
        return self._bw

    def unlockVault(self, password):
        """
        Performs the process of unlocking the account's vault
        """
        return self._bw.loginWithPassword(self.account['email'], password)

class BitwardenApiKeyAuthenticator(BitwardenPasswordAuthenticator):
    """
    Handles the process of unlocking the vault using API Key
    based login. The API Key based login separates the authentication to the
    account from the unlocking process of the vault. The authenticator
    handles the process of abstracting those details for purpose of
    performing account backups.
    """

    def __init__(self, acct_config, server_url = r'https://vault.bitwarden.com', root_ca_path = None):
        super().__init__(acct_config, server_url, root_ca_path)

    def unlockVault(self, password):
        """
        Performs the process of unlocking the account's vault
        """
        client_id = self.account['client_id']
        client_secret = self.account['client_secret']
        status = self._bw.loginWithApiKey(client_id, client_secret)
        if not status:
            raise AuthenticationFailedException(self.account['email'], self.url)

        return self._bw.unlock(password)
        
@click.command(name='backup')
@click.argument('filename')
@click.option('--dir', default='.', help='Location where exports should be stored.')
@click.option('--format', default='json', help='Specification of default backup format (csv, json, encrypted_json). The format can be overriden for an account within the configuration file.')
def backup(filename, dir, format):
    """
    Performs a backup of Bitwarden vaults.

    The Bitwarden server provides a mechanism for handling export of items from
    vaults for purposes of backups. These exports can then be imported to Vaultwarden
    at a later time to recover the entries if necessary. The exports ARE NOT ENCRYPTED
    when they are created in the output directory. As such, it's important to understand
    the risks with having these exports available.

    The export process supports multiple formats for the export. The json format is best
    for handling the recovery scenario of an account. The csv format is better for being
    able to interpret the passwords in an external application such as Excel. The csv format
    will result in loss of history as the format is too basic to support that level of meta-data.

    The backup process utilizes a json based configuration to understand locations of server
    and accounts that should be backed up. The path to the configuration is required so that
    application knows how to process.

    The following is an example of the json configuration that is required for this tool:

    {

        "ca_root_certificate" : "Path to Root CA Certificate here",

        "server_url" : "URL to Vaultwarden here",

        "accounts" : {

            "v1 - Password Example" : {

                "email" : "test+alice@gmail.com",

                "format" : "csv"

            },

            "v2 - API Key Example" : {

                "email" : "test+bob@gmail.com",

                "client_id" : "",

                "client_secret" : ""

            }

        }

    }

    The information in the above configuration will need to populated based upon environment
    specifics.

    - ca_root_certificate - Path to the root certificate for instances where a self-signed CA is being leveraged.

    - server_url - URL for the Bitwarden/Vaultwarden instance that is housing the accounts.

    - accounts - List of the accounts that need to be included in the backup.
    """
    if(not os.path.exists(filename)):
        print("ERROR: Specified configuration file doesn't exist!")
        exit()

    with open(filename, 'r') as f:
        configuration = json.load(f)

    server_url = r'https://vault.bitwarden.com'
    if 'server_url' in configuration:
        server_url = configuration['server_url']

    root_ca_path = None
    if 'ca_root_certificate' in configuration:
        root_ca_path = configuration['ca_root_certificate']

    for acct in configuration['accounts']:

        account_config = configuration['accounts'][acct]
        auth = getAuthenticator(account_config, server_url, root_ca_path)
        print("\nBitwarden Account Backup:\n\tAccount: {}\n\tURL: {}\n".format(account_config['email'], server_url))

        try:
            prompt = "Enter Account Password for %s on %s:" % (account_config['email'], server_url)
            passwordForLogin = getpass.getpass(prompt = prompt)
        except Exception as error:
            print("ERROR: Failed to retrieve password for " + account_config['email'])
            print('There is an error : ', error)
            continue

        try:
            auth.bw.logout()
            status = auth.unlockVault(passwordForLogin)
        except AuthenticationFailedException:
            print("ERROR: Failed to login to " + account_config['email'])
            continue

        exp_format = format
        encrypt_password = None
        if('format' in account_config):
            exp_format = account_config['format']

        if(exp_format == 'encrypted_json'):
            try:
                prompt = "Enter Backup Password for %s on %s:" % (account_config['email'], server_url)
                encrypt_password = getpass.getpass(prompt = prompt)
            except Exception as error:
                print("ERROR: Failed to retrieve encryption password for " + account_config['email'])
                print('There is an error : ', error)
                continue

        status = auth.bw.exportAll(dir, exp_format, encrypt_password)
        if(status == False):
            print("ERROR: Failed to export " + account_config['email'])
            continue

        # Log Out Account
        auth.bw.logout()

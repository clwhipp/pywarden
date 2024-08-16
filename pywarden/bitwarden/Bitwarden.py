import os
import json
from datetime import datetime
from time import sleep

from .Types import get_bitwarden_item, BitwardenCollection, BitwardenOrganization, OrganizationUserTypes
from .Exceptions import NoEncryptionPasswordException, VaultNotUnlockedException
from ..common.Utils import performCommandLineOperation
from ..common.Exceptions import InvalidStateException, InvalidArgumentsException

class Bitwarden:
    """
    Bitwarden is an open source password manager that is available across several platforms.
    At it's basest level, Bitwarden saved passwords, credit cards, identity information within
    an encrypted vault. This vault is then synchronized across all supported clients to provide
    convenient access.

    One of the supported clients is the Bitwarden command line interface (CLI). More information
    can be found https://bitwarden.com/help/article/cli/ on this particular client. This class
    acts as a wrapper around the CLI interface to provide support for interacting with Bitwarden
    from python.
    """

    def __init__(self, bwCliLocation = r'bw', serverUrl = r'https://vault.bitwarden.com', ca_cert_path = None ):
        """
        Handles the process of initializing the Bitwarden CLI wrapper. It handles the process
        of ensuring that we are interacting with appropriate server as well as ensuring the
        operating environment is properly configured for proper operation of the API's.
        
        @param serverUrl URL for the Bitwarden server that is being accessed
        @param ca_cert_path Location for certificate authority (CA) certificate if necessary
        """
        self._serverUrl = None
        self._bw_session_id = None
        self._bw_app_location = bwCliLocation

        # An additional environment variable needs to be configured in order to allow
        # the use of self-signed certificates. By checking the length of the path it allows
        # for support for self-signed as well as not self-signed certs
        if(ca_cert_path != None):
            os.environ['NODE_EXTRA_CA_CERTS'] = ca_cert_path

        # Need to ensure that the client is connected to the appropriate remote server.
        status = self.status
        if(status['serverUrl'] != serverUrl):
            self.serverUrl = serverUrl


    @property
    def serverUrl(self):
        return self._serverUrl


    @serverUrl.setter
    def serverUrl(self, url):
        """
        Handles the process of changing the server that the Bitwarden cli is interacting with.
        This function will logout any accounts that may currently be logged in.

        @param url Location for the new Bitwarden server
        """
        status = self.status
        if(status['status'] != r'unauthenticated'):
            raise InvalidStateException()

        # Initiate the command line arguments to trigger the server change within the client
        cmd = [self._bw_app_location, 'config', 'server', url]
        performCommandLineOperation(cmd)


    def __extractSessionFromStdOut__(self, stdout):
        """
        Retrieves the Session ID from stdout after unlocking/logging into a Bitwarden
        vault.

        @param stdout String containing content from stdout after unlock/login process
        """

        # After an unlock/login process, the session id is spit to stdout. The output is not json
        # so custom processing needs to take place.
        #
        #
        # Example Output:
        # Your vault is now unlocked!
        # 
        # To unlock your vault, set your session key to the `BW_SESSION` environment variable. ex:
        # $ export BW_SESSION=""
        # > $env:BW_SESSION=""
        # 
        # You can also pass the session key to any command with the `--session` option. ex:
        # $ bw list items --session <id>

        content = stdout.decode('utf-8')
        lines = content.split('\n')
        for line in lines:

            if(r'export' in line):

                idx = line.index('=')
                session_raw = line[idx:]
                self._bw_session_id = session_raw[2:len(session_raw)-1]


    @property
    def status(self):
        """
        Retrieves the status of the vault.

        The status of the vault contains information regarding which account is configured and
        whether the vault has been unlocked, locked, and/or not configured.

        Example Output (As of 2021-03-24)
        {
          "serverUrl": "https://bitwarden.example.com",
          "lastSync": "2020-06-16T06:33:51.419Z",
          "userEmail": "user@example.com",
          "userId": "00000000-0000-0000-0000-000000000000",
          "status": "locked"
        }

        # States (As of 2021-03-24)
        # "unauthenticated" when you’re not logged in
        # "locked" when the vault is locked
        # "unlocked" when the vault is unlocked

        @return Dictionary containing the vaults status
        """

        cmd = [self._bw_app_location, 'status']
        if(self._bw_session_id != None):
            cmd.append('--session')
            cmd.append(self._bw_session_id)

        code, stdout, stderr = performCommandLineOperation(cmd)
        if(code == 0):
            return json.loads(stdout)
        
        return None


    def isClientLatest(self):
        """
        Checks to see if updated version of the client is available for download

        @return Boolean to indicate if newer version is available for download
        """

        cmd = [self._bw_app_location, 'update']
        code, stdout, stderr = performCommandLineOperation(cmd)
        if(code == 0):
            output = stdout.decode('utf-8')
            if(r'No update available' in output):
                return True
        return False


    def loginWithPassword( self, username, password, retry_count=5 ):
        """
        Handles logging into the Bitwarden vault using username and password

        @param username Email address that is registered with account
        @param password Password for accessing the account
        @param retry_count Number of login attempts to perform prior to considering a failure.
        @raises InvalidStateException Encountered a bitwarden state that is inconsistent with login such as already being logged in.
        @return Boolean to indicate success or failure
        """

        ret_value = False
        status = self.status
        if(status['status'] != r'unauthenticated'):
            raise InvalidStateException()
        
        number_retries = 1
        while(number_retries <= retry_count):

            cmd = [self._bw_app_location, 'login', username, password]
            code, stdout, stderr = performCommandLineOperation(cmd)
            if(code == 0):
                self.__extractSessionFromStdOut__(stdout)
                ret_value = True
                self.sync()
                break
            else:
                sleep(0.5 * number_retries)
                number_retries += 1

        return ret_value


    def loginWithApiKey(self, client_id, client_secret, retry_count=5):
        """
        Handles process of loggin into Bitwarden vault using API Key

        The API Key metholody for accessing Bitwarden is designed for
        automated workflows. One of the big differences is that the
        API Key bypasses any sort of 2FA that may be configured on the
        account.

        The API Key based login is unable to handle the unlocking of the
        vault. As such, it will be necessary to unlock the vault after
        completing this step.

        @param client_id Client identifier pulled from Bitwarden account
        @param client_secret Client secret taht is pulled from the Bitwarden account
        @param retry_count Number of login attempts to perform prior to considering a failure.
        @raises InvalidStateException Encountered a bitwarden state that is inconsistent with login such as already being logged in.
        @return Boolean to indicate success or failure
        """

        ret_value = False
        status = self.status
        if(status['status'] != r'unauthenticated'):
            raise InvalidStateException()

        os.environ['BW_CLIENTID'] = client_id
        os.environ['BW_CLIENTSECRET'] = client_secret

        number_retries = 1
        while(number_retries <= retry_count):

            cmd = [self._bw_app_location, 'login', '--apikey']
            code, stdout, stderr = performCommandLineOperation(cmd)
            if(code == 0):
                ret_value = True
                break
            else:
                sleep(0.5 * number_retries)
                number_retries += 1

        del os.environ['BW_CLIENTID']
        del os.environ['BW_CLIENTSECRET']

        return ret_value


    def logout( self ):
        """
        Logs out current bitwarden sessions making use of the CLI

        Bitwarden will persist a locked version of the database for the longevity
        of the time that an account is logged in. Locking and unlocking the database
        operates on a local copy. Logging out will remove these cached versions of the
        databases
        """
        cmd = [self._bw_app_location, 'logout']
        performCommandLineOperation(cmd)

        self._bw_session_id = None


    def unlock( self, password ):
        """
        Handles process of unlocking the Bitwarden vault

        Handles the process of using the password to unlock the Bitwarden
        vault so that it can be utilized and interacted with.

        @param password Password for unlocking the vault
        @return Boolean indicating whether unlocking operation was successful
        """

        status = self.status
        if(status['status'] == r'unlocked'):
            return True

        if(status['status'] == r'unauthenticated'):
            raise InvalidStateException()

        os.environ['BW_PASSWORD'] = password
        cmd = [self._bw_app_location, 'unlock', '--passwordenv', 'BW_PASSWORD']
        code, stdout, stderr = performCommandLineOperation(cmd)
        del os.environ['BW_PASSWORD']

        if(code == 0):
            self.__extractSessionFromStdOut__(stdout)
            ret_value = True
        else:
            ret_value = False

        return ret_value


    def lock( self ):
        """
        Locks the active database within the CLI

        Locking the database means that contents are no longer accessible without
        providing the unlock password again to the CLI.
        """

        cmd = [self._bw_app_location, 'lock']
        performCommandLineOperation(cmd)


    def sync(self):
        """
        Synchronizes local database with remote version

        Bitwarden CLI is able to provide read-only access to the database
        when a connection to the host environment is not possible. This
        means that updates could have been made to remote database and are
        not available within local database until synchronization operation
        takes place
        """

        # Ensure that we have an active session available
        if(self._bw_session_id == None):
            raise VaultNotUnlockedException()

        cmd = [self._bw_app_location, 'sync', '--session', self._bw_session_id]
        code, stdout, stderr = performCommandLineOperation(cmd)
        if(code == 0):
            return True

        return False


    @property
    def items(self):

        # Ensure that we have an active session available
        if(self._bw_session_id == None):
            return None

        cmd = [self._bw_app_location, 'list', 'items', '--session', self._bw_session_id]
        code, stdout, stderr = performCommandLineOperation(cmd)
        if(code == 0):
            content = json.loads(stdout)

        return []


    def __getitem__(self, name):
        """
        Retrieve specific items by name from the vault
        """
        # Ensure that we have an active session available
        if(self._bw_session_id == None):
            return []

        if(not isinstance(name, str)):
            return []

        cmd = [self._bw_app_location, 'list', 'items', '--search', name, '--session', self._bw_session_id]
        code, stdout, stderr = performCommandLineOperation(cmd)
        if(code == 0):

            item_list = []
            item_dict_list = json.loads(stdout)
            for item_dict in item_dict_list:
                item = get_bitwarden_item(item_dict)
                item_list.append(item)

            return item_list

        return []


    @property
    def orgs(self):
        """
        Retrieves list of organizations to which access has been granted

        Organizations in Bitwarden are a method by which keys and passwords
        can be shared across multiple accounts. Accounts can be provided with
        access to organizations and subsequently provide restriction based upon
        collection access.
        """
        # Ensure that we have an active session available
        if(self._bw_session_id == None):
            return None

        cmd = [self._bw_app_location, 'list', 'organizations', '--session', self._bw_session_id]
        code, stdout, stderr = performCommandLineOperation(cmd)
        if(code == 0):

            orgs = []
            for org_dict in json.loads(stdout):
                org = BitwardenOrganization(org_dict)
                orgs.append(org)
            return orgs

        return []

    @property
    def collections(self):
        """
        Retrieves a list of collections to which logged-in account has access.

        Collections are utilized to bucket keys/passwords into groups so that access can
        be managed accordingly. This will return list of collections that could span multiple
        organizations as well.
        """
        # Ensure that we have an active session available
        if(self._bw_session_id == None):
            return None

        cmd = [self._bw_app_location, 'list', 'collections', '--session', self._bw_session_id]
        code, stdout, stderr = performCommandLineOperation(cmd)
        if(code == 0):

            collections = []
            for col_dict in json.loads(stdout):
                col = BitwardenCollection(col_dict)
                collections.append(col)
            return collections

        return []


    def exportAll(self, dir_path, format = 'json', encrypt_password=None):
        """
        Performs an export of personal vault and all owned organizations

        This function performs the export of a personal vault as well as all
        owned organizations. If the account is an owner of an organization, the
        contents of the organization will also be exported as part of this operation.

        @param password Accounts master password for deriving the master decryption key.
        @param dir_path Directory to which all the exports should be placed.
        @param format Format of the exported vaults (csv, json)
        """

        # Ensure that we have an active session available
        if(self._bw_session_id == None):
            print("ERROR: BW Session Error")
            return False

        # if path doesn't exist then it should be created
        if(not os.path.exists(dir_path)):
            os.makedirs(dir_path)

        # make sure provided path is for a directory
        if(not os.path.isdir(dir_path)):
            print("ERROR: Not directory")
            return False

        status = self.status

        now = datetime.now()
        timeStr = now.strftime("%Y%m%d-%H%M")
        filename = "%s-%s.%s" % (status['userEmail'], timeStr, format)
        file_path = os.path.join(dir_path, filename)

        if(not self.exportPersonalVault(file_path, format, encrypt_password)):
            return False

        # Export contents of all organizations owned by the user
        for org in self.orgs:

            if(org.type not in [OrganizationUserTypes.OWNER.value, OrganizationUserTypes.ADMIN.value]):
                continue

            filename = "%s-%s-%s.%s" % (status['userEmail'], org.name, timeStr, format)
            file_path = os.path.join(dir_path, filename)
            if(not self.exportCollections(file_path, org.id, format, encrypt_password)):
                return False

        return True

    def exportPersonalVault(self, path, format = 'csv', encrypt_password=None):
        """
        Handles process of exporting the personal vault

        A Bitwarden account maintains a personal vault as well as organizational vaults. The
        personal vault contains items that are not shared between multiple accounts. This
        function handles the export from the personal vault rather than organizational.

        WARNING: The exported vault contents will be UNENCRYPTED and thus should only be
        exported to safe a location.

        @param password Accounts master password for deriving the master decryption key.
        @param path Location for the exported vault contents.
        @param format Format of the exported vault contents (csv, json, encrypted_json)

        @throws InvalidArgumentsException Incorrect format is provided.
        @throws NoEncryptionPasswordException Encrypted_json format was specific but password provided.
        """

        # Ensure that we have an active session available
        if(self._bw_session_id == None):
            return False
        
        if(format not in ['json', 'encrypted_json', 'csv']):
            raise InvalidArgumentsException()
        
        if(format == 'encrypted_json' and encrypt_password==None):
            raise NoEncryptionPasswordException()

        # Generate the export command and ensure that appropriate session is provided
        cmd = [self._bw_app_location, 'export', '--format', format, '--output', path, '--session', self._bw_session_id]
        if encrypt_password:
            cmd += ['--password', encrypt_password]

        code, stdout, stderr = performCommandLineOperation(cmd)
        if(code == 0):
            return True

        return False

    def exportCollections(self, path, organization_id, format = 'csv', encrypt_password=None):
        """
        Exports the collections of the specified Organization

        An organization contains a series of collections. These collections are able to maintain
        1 or more keys/passwords. At an organizational level, an owner can provide permissions
        to keys at a collection level. This function provide a facility to export all the contents
        of the collections within an organization. The calling account must be an owner of the
        organization for this to be successful.

        @param password Accounts master password for deriving the master decryption key.
        @param path Location for the exported vault contents.
        @param organization_id ID of the organization that needs to be exported.
        @param format Format of the exported vault contents (csv, json, encrypted_json)

        @throws InvalidArgumentsException Incorrect format is provided.
        @throws NoEncryptionPasswordException Encrypted_json format was specific but password provided.
        """

        # Ensure that we have an active session available
        if(self._bw_session_id == None):
            return False
        
        if(format not in ['json', 'encrypted_json', 'csv']):
            raise InvalidArgumentsException()
        
        if(format == 'encrypted_json' and encrypt_password==None):
            raise NoEncryptionPasswordException()

        # Generate the export command and ensure that appropriate session is provided
        cmd = [self._bw_app_location, 'export', '--format', format, '--output', path, '--session', self._bw_session_id, '--organizationid', organization_id]
        if encrypt_password:
            cmd += ['--password', encrypt_password]
        
        code, stdout, stderr = performCommandLineOperation(cmd)
        if(code == 0):
            return True

        return False

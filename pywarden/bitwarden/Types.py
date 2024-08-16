from enum import Enum

class ItemTypes(Enum):
    LOGIN = 1
    NOTE = 2
    CARD = 3
    IDENTITY = 4

class FieldTypes(Enum):
    TEXT = 0
    HIDDEN = 1
    BOOLEAN = 2

class OrganizationStatus(Enum):
    INVITED = 0
    ACCEPTED = 1
    CONFIRMED = 2
    REVOKED = -1

class OrganizationUserTypes(Enum):
    OWNER = 0
    ADMIN = 1
    USER = 2
    MANAGER = 3
    CUSTOM = 4

class BitwardenCollection(object):
    """
    Represents a Bitwarden Collection within an Organization

    Processes a Bitwarden Collection that is returned from Bitwarden CLI. A series
    of read-only properties are made available for easy access within python.
    """

    def __init__(self, conf):

        self._id = conf['id']
        self._oid = conf['organizationId']
        self._name = conf['name']
        self._eid = conf['externalId']

    @property
    def id(self):
        return self._id

    @property
    def orgId(self):
        return self._oid

    @property
    def name(self):
        return self._name

    @property
    def extId(self):
        return self._eid

class BitwardenOrganization(object):
    """
    Represents a Bitwarden Organization

    Processes a Bitwarden Organization that is returned from Bitwarden CLI. A series of
    read-only properties are made available for easy access within python.
    """

    def __init__(self, conf):

        self._id = conf['id']
        self._name = conf['name']
        self._status = conf['status']
        self._type = conf['type']
        self._enabled = conf['enabled']

    @property
    def id(self):
        return self._id

    @property
    def name(self):
        return self._name

    @property
    def status(self):
        return self._status

    @property
    def type(self):
        return self._type

    @property
    def enabled(self):
        return self._enabled

class BitwardenItem(object):
    """
    Parent class for all Bitwarden item types

    There are a series of attributes/properties that are consistent across
    all item types within Bitwarden. This class serves to process those common
    elements and provide read-only properties for their consumption.
    """

    def __init__(self, conf):

        self._id = conf['id']
        self._fid = conf['folderId']
        self._name = conf['name']
        self._note = conf['notes']

    @property
    def id(self):
        return self._id

    @property
    def folderId(self):
        return self._fid

    @property
    def name(self):
        return self._name

    @property
    def notes(self):
        return self._note

    def __eq__(self, other):

        if(other == None):
            return False

        if(self.name != other.name):
            return False
        if(self.notes != other.notes):
            return False

        return True

class BitwardenCard(BitwardenItem):
    """
    Represents a Credit Card within Bitwarden Vault

    Handles the process of processing credit card entries identified within
    a Bitwarden Vault.
    """

    def __init__(self, conf):
        super().__init__(conf)

        self._card_holder_name = conf["card"]['cardholderName']
        self._brand = conf["card"]['brand']
        self._number = conf["card"]['number']
        self._exp_month = conf["card"]['expMonth']
        self._exp_year = conf["card"]['expYear']
        self._code = conf["card"]['code']

    @property
    def holder_name(self):
        return self._card_holder_name

    @property
    def brand(self):
        return self._brand

    @property
    def number(self):
        return self._number

    @property
    def month(self):
        return self._exp_month

    @property
    def year(self):
        return self._exp_year

    @property
    def code(self):
        return self._code

    def __eq__(self, other):
        base_match = super().__eq__(other)
        if(not base_match):
            return False

        if(self.holder_name != other.holder_name):
            return False

        if(self.brand != other.brand):
            return False

        if(self.number != other.number):
            return False

        if(self.month != other.month):
            return False

        if(self.year != other.year):
            return False

        if(self.code != other.code):
            return False

        return True        

class BitwardenNote(BitwardenItem):
    """
    Represents a Secure Note within Bitwarden Vault
    """

    def __init__(self, conf):
        super().__init__(conf)

class BitwardenLogin(BitwardenItem):
    """
    Represents a Login item from Bitwarden vault.


    """

    def __init__(self, conf):
        super().__init__(conf)

        self._username = conf['login']['username']
        self._password = conf['login']['password']
        self._totp = conf['login']['totp']

    @property
    def username(self):
        return self._username

    @property
    def password(self):
        return self._password

    @property
    def totp(self):
        return self._totp

    def __eq__(self, other):
        base_match = super().__eq__(other)
        if(not base_match):
            return False

        if(self.username != other.username):
            return False

        if(self.password != other.password):
            return False

        if(self.totp != other.totp):
            return False

        return True

def get_bitwarden_item(conf):

    type = conf['type']
    if(type == ItemTypes.CARD.value):
        return BitwardenCard(conf)
    elif(type == ItemTypes.LOGIN.value):
        return BitwardenLogin(conf)
    elif(type == ItemTypes.NOTE.value):
        return BitwardenNote(conf)
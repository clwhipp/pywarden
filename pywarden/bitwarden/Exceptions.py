
class NoEncryptionPasswordException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

class VaultNotUnlockedException(Exception):
    def __init__(self, *args: object) -> None:
        super().__init__(*args)

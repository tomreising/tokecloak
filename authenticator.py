"""
tokecloak is a library to handle authentication
and authorization for KeyCloak OIDC clients 
"""
import requests

class KCAuth:
    """
    OIDC Authentication Class For Use on Keycloak endpoints
    init
    :params: Kc_domain : str Key Cloak Domain i.e. "http://auth.KC.local"
    :params: kc_realm : str Key Cloak Realm for client auth
    :params: client_id : str Key Cloak Client ID
    :params: client_secret: str Key Cloak Client Secret
    :returns: KCAuth Object
    """
    def __init__(self, kc_domain, kc_realm, client_id: str, client_secret: str):
        self.kc_domain = kc_domain
        self.kc_realm = kc_realm
        self.client_id = client_id
        self.client_secret = client_secret

    def get_token_basic(self, username:str, password: str) -> str | None:
        """
        Retrieves a keycloak token for basic username and password configurations
        :params: username : str
        :params: password : str
        :return: token : str  
        """
        url = f"{self.kc_domain}/realms/{self.kc_realm}/protocol/openid-connect/token"
        headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'grant_type': 'password',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'username': username,
            'password': password
        }
        try:
            response = requests.post(url,headers=headers, data=data, timeout=300)
            token = response.json()['access_token']
            return token
        except KeyError as e:
            print(e.__doc__)
            return None

    def get_token_2fa(self, username:str, password: str, totp: int) -> str | None:
        """
        Retrieves a keycloak token for basic username and password configurations
        :params: username : str
        :params: password : str
        :params: totp : str 
        :return: token : str  
        """
        url = f"{self.kc_domain}/realms/{self.kc_realm}/protocol/openid-connect/token"
        headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
        }
        data = {
            'grant_type': 'password',
            'client_id': self.client_id,
            'client_secret': self.client_secret,
            'username': username,
            'password': password,
            'totp': str(totp)
        }
        try:
            response = requests.post(url,headers=headers, data=data, timeout=300)
            token = response.json()['access_token']
            return token
        except KeyError:
            return None

    def token_introspect(self, token: str) -> dict | None:
        """
        Validate provided token
        :params: token : str
        :return: dict | None provides dictionary of user data and active state or None
        """
        url = f"{self.kc_domain}/realms/{self.kc_realm}/protocol/openid-connect/token/introspect"
        payload = f"""token={token}&client_id={self.client_id}&client_secret={self.client_secret}"""
        headers = {
        'Content-Type': 'application/x-www-form-urlencoded'
        }
        response = requests.request("POST", url, headers=headers, data=payload, timeout=300)
        if response.status_code == 200:
            return response.json()
        return None

    def get_well_known(self):
        """
        Get Clien End Poins
        """
        url = f"{self.kc_domain}/realms/{self.kc_realm}/.well-known/openid-configuration"
        response = requests.get(url,timeout=300)
        if response.status_code == 200:
            return response.json()
        return None

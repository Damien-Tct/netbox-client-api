#! /usr/bin/env python3

import requests, json, sys, re
from credentials import *

'''
credentials.py need some variables inside :

    api_token : your netbox's api token
    api_url : the url where you can get the api requests. like : https://127.0.0.1/api/ipam/ip-addresses
    proxy_user : the user you have to login to pass through the proxy
    proxy_password : the password that allow you to login with your user
    proxy_address : the proxy's address, included the port number, like : 127.0.0.1:3128
'''

# Disable SSL  warnings
requests.packages.urllib3.disable_warnings()

### CONNEXION PROXY
token_auth = "Token " + api_token
https_proxy = "http://" + proxy_user + ":" + proxy_password + "@" + proxy_address
proxies = { "https" : https_proxy }

# Récupération $1
def requete(arg, url):
    try:
        api_call = requests.get(f"{api_url}?q={arg}", headers={'Authorization': token_auth }, proxies = proxies, verify=False ).json()
    except:
        print("Erreur lors de la requête API, vérifiez les credentials")
        sys.exit(1)
    
    result = [ {"ip" : ip["display"], "DNS" : ip["dns_name"], "description" : ip["description"]}  for ip in api_call.get("results")]
    return result


if __name__ == "__main__" :
    try :
        for arguments in sys.argv[1:]:
            result = requete(arguments, api_url)
            print(f"Recherche : {arguments}")
            if len(result) != 0 :
                for results in result :
                    print(f'IP : {results["ip"]:<20s} DNS : {results["DNS"]:<25s} Description : {results["description"]:<40s}')
            else :
                print(f"Aucune entrée trouvée")
            print()
    except IndexError as e:
        print(f"Verifiez les arguments : {e}")
        sys.exit(1)

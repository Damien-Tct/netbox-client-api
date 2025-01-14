#! /usr/bin/env python3


try:
    import requests, json, sys, argparse
    from credentials import *
except ModuleNotFoundError as e :
    print(e)
    sys.exit(1)
'''
credentials.py need some variables inside :

    api_token : your netbox's api token
    api_url_ip : the url where you can get the api requests about the ip addresses like : https://127.0.0.1/api/ipam/ip-addresses
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

def debugger(func):
    def wrapper(*args, **kwargs):
        if kwargs["debug"] :
            print(f'##### Fonction lancée : {func.__name__}')
            print(f'Arguments passés : {kwargs}')
            print(f'Résultat donné par la fonction : {func(*args, **kwargs)}\n')
            return func(*args, **kwargs)
        else :
            return func(*args, **kwargs)
            
    return wrapper

@debugger
def requete(arg, url, limit, debug):
    '''
    the first argument : arg : all the args passed to the command
    the second argument : url : the url requested for api requests
    the third : limit : by default 1, can be overwriten when the method is called
    '''
    try:
        api_call = requests.get(f"{url}?q={arg}&limit={limit}", headers={'Authorization': token_auth }, proxies = proxies, verify=False ).json()
    except:
        print("Erreur lors de la requête API, vérifiez les credentials")
        sys.exit(1)
    
    result = [ {"ip" : ip["display"], "DNS" : ip["dns_name"], "description" : ip["description"]}  for ip in api_call.get("results")]
    return result



if __name__ == "__main__" :
    try :
        parser = argparse.ArgumentParser()
        parser.add_argument("-l","--limit", type=int, default=5, help="Permet de modifier le nombre de resultats maximum - Par défaut : 5")
        parser.add_argument("-d","--debug", action="store_true", default=False, help="Activation du debug")
        parser.add_argument("ip",nargs='+', type=str, help="IP ou FQDN à rechercher dans l'IPAM")
        args=parser.parse_args()
        for ips in args.ip :
            result = requete(arg = ips, url = api_url_ip, limit = args.limit, debug = args.debug)
            print(f"Searching for : {ips}\n")
            if len(result) != 0 :
                for results in result :
                    print(f'----------')
                    print(f'IP : {results["ip"]:<20s}\nDNS : {results["DNS"]:<25s}\nDescription : {results["description"]:<40s}')
            else :
                print(f"No entries found")
            print(f'----------')
            print()
    except IndexError as e:
        print(f"get rif of the arguments : {e}")
        sys.exit(1)

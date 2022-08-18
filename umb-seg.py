#!/usr/bin/env python
#
import requests
import json
import urllib3
import base64
import re
from ipaddress import IPv4Network

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

VMANAGE = 'vmanage.onesase.com'
USER = 'rshoemak'
PASS = 'C1sco12345!'
ROUTER = '1.3.9.1'
UMBORGID = '6358063'
UMBMGMTKEY = 'f2aeb2a241714916a798d0f1a296400c'
UMBMGMTSEC = 'df721d3593454f3294aab626dc7ef759'
VPNID = '10'
UMBDEVKEY = '3b8a0835ae4e44428f41b654efde198b'
UMBDEVSEC = '4e8094dca7f446f598db169f8fa33b0f'
VPN = 'Corporate'
WEBPOLICY = 'Corporate-Segment-Web-Policy'

VPNLIST = [{'name':'Corporate','vpn':'10','webpolicy':'Corporate-Segment-Web-Policy'},
           {'name':'Guest','vpn':'20','webpolicy':'Guest-Segment-Web-Policy'},
           {'name':'IoT','vpn':'30','webpolicy':'IOT-Segment-Web-Policy'}]

umbCredStr = UMBMGMTKEY + ":" + UMBMGMTSEC
umbCredBytes = umbCredStr.encode("ascii")
umbCredEnc = base64.b64encode(umbCredBytes)
umbCredDec = umbCredEnc.decode("ascii")

umbDevStr = UMBDEVKEY + ":" + UMBDEVSEC
umbDevBytes = umbDevStr.encode("ascii")
umbDevEnc = base64.b64encode(umbDevBytes)
umbDevDec = umbDevEnc.decode("ascii")

vmanage_url_base = 'https://{vmanage}/dataservice'.format(vmanage=VMANAGE)
umb_url_base = 'https://management.api.umbrella.com/v1/organizations/{org_id}'.format(org_id=UMBORGID)

class IntInfo():
    def __init__(self, name, ip, mask):
        self.name = name
        self.ip = ip
        self.mask = mask


def get_session_id():

    url = 'https://{vmanage}/j_security_check'.format(vmanage=VMANAGE)

    payload = {'j_username': USER, 'j_password': PASS}
    
    resp = requests.post(url,
                         data=payload,
                         verify=False)
    
    try:
        cookies = resp.headers["Set-Cookie"]
        jsessionid = cookies.split(";")
        return(jsessionid[0])
    except:
        print("No Valid JSESSION ID returned\n")
        exit()

def get_vmanage_token(jsessionid):

    url = vmanage_url_base + '/client/token?json=true'

    headers = {'Cookie': jsessionid}

    resp = requests.get(url,
                        headers=headers,
                        verify=False)

    token = resp.json()['token']
    return(token)

def get_umb_sig_name(jsessionid, token):

    sig_tunnel_list = []

    url = vmanage_url_base + '/device/sig/umbrella/tunnels?deviceId={router}'.format(router=ROUTER)

    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'Cookie': jsessionid,
               'X-XSRF-TOKEN': token}

    resp = requests.get(url,
                        headers = headers,
                        verify=False)

    json_data = resp.content
    data_dict = json.loads(json_data)
    tunnel_list = data_dict['data']
    for tunnel in tunnel_list:
        
        try:
            sig_tunnel_name = tunnel["tunnel-name"]
            print("Found SIG Tunnel {tunnel} for router {router}\n".format(tunnel=sig_tunnel_name, router=ROUTER))
            sig_tunnel_list.append(sig_tunnel_name)
        except:
            continue
    return(sig_tunnel_list)

def get_umb_sig_id(umb_sig_tunnel_name):

    sig_tunnel_id = []

    url = umb_url_base + '/tunnels'

    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'Authorization': 'Basic %s' %umbCredDec}

    resp = requests.get(url,
                        headers=headers,
                        verify=False,)

    json_data = resp.content
    data_dict = json.loads(json_data)

    for tunnel_name in umb_sig_tunnel_name:
        
        for tunnel_info in data_dict:
            
            try:
                if tunnel_name == tunnel_info['name']:
                    sig_tunnel_id.append(tunnel_info['id'])
                    print("Found SIG Tunnel ID {id} for Tunnel {tunnel}\n".format(id=tunnel_info['id'], tunnel=tunnel_info['name']))
            except:
                print("Error with matching Tunnels")
                continue

    return(sig_tunnel_id)


def get_int_info(jsessionid, token):

    url = vmanage_url_base + '/device/interface?deviceId={router}&vpn-id={vpn}'.format(router=ROUTER, vpn=VPNID)

    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'Cookie': jsessionid,
               'X-XSRF-TOKEN': token}

    resp = requests.get(url,
                        headers = headers,
                        verify=False)

    json_data = resp.content
    data_dict = json.loads(json_data)
    int_list = data_dict['data']

    for ints in int_list:
        name = ints['ifname']
        ip = ints['ip-address']
        mask = ints['ipv4-subnet-mask']

    return IntInfo(name, ip, mask)
        

def post_priv_nets(umb_sig_id_list, ip, mask):

    origin_id_list = []
    
    url = umb_url_base + '/internalnetworks'

    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'Authorization': 'Basic %s' %umbCredDec}

    for counter, sig_tunnel_int in enumerate(umb_sig_id_list):

        index = str(counter)
        priv_name = 'Site9-Macrosegment-{vpn}-Tu{num}'.format(vpn=VPN, num=index)
        sig_tunnel=str(sig_tunnel_int)

        payload = {'name': priv_name,
                   'ipAddress': ip,
                   'prefixLength': mask,
                   'tunnelId': sig_tunnel}

        try:
            resp = requests.request("POST", 
                                url,
                                headers=headers,
                                json=payload)

            json_data = resp.content
            data_dict = json.loads(json_data)
            orig_id = data_dict['originId']
        except:
            print('Error creating internal nets')
            continue

        origin_id_list.append(orig_id)

    return(origin_id_list)


def get_web_policy():

    url = umb_url_base + '/policies?type=web&page=1&limit=100'

    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'Authorization': 'Basic %s' %umbDevDec}

    resp = requests.get(url,
                        headers = headers,
                        verify=False)

    json_data = resp.content
    policy_list = json.loads(json_data)

    for policy in policy_list:
        if policy['name'] == WEBPOLICY:
            web_policy_id = policy['policyId']
    
    return(web_policy_id)


def put_policy(origin_id_list, web_policy_id):
    
    url = umb_url_base + '/policies/{policy}'.format(policy=web_policy_id)

    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'Authorization': 'Basic %s' %umbDevDec}

    for origin_id in origin_id_list:

        fullUrl = url + '/identities/{origin}'.format(origin=origin_id)

        try:
            requests.request("PUT", 
                            fullUrl,
                            headers=headers)

        except:
            print('Error adding web policy')
            continue


if __name__ == '__main__':
    
    jsessionid = get_session_id()
    token = get_vmanage_token(jsessionid)

    print("\n *** Looking for SIG Tunnels for router {router} ***\n".format(router=ROUTER))
    umb_sig_tunnel_name = get_umb_sig_name(jsessionid, token)
    #print('Looking for info on these tunnels')
    #print(umb_sig_tunnel_name)

    print("\n *** Looking for Tunnel IDs for SIG Tunnels ***\n")
    umb_sig_id = get_umb_sig_id(umb_sig_tunnel_name)
    print('\n *** Found Tunnel Ids *** \n')
    print(umb_sig_id)

    print("\n *** Finding IP address for internal IP for VPN {vpn} ***\n".format(vpn=VPNID))
    int_info = get_int_info(jsessionid, token)
    print("\n *** Found internal IP information ***\n")
    print("\n *** The IP is {ip}\{mask} ***\n".format(ip=int_info.ip, mask=int_info.mask))

    sep_ip = re.split(r'(\.|/)', int_info.ip)
    new_ip = sep_ip[0] + '.' + sep_ip[2] + '.' + sep_ip[4] + '.0'
    #print(new_ip)

    mask = sum(bin(int(x)).count('1') for x in int_info.mask.split('.'))
    #print(mask)

    origin_id_list = post_priv_nets(umb_sig_id, new_ip, mask)
    print(origin_id_list)

    web_policy_id = get_web_policy()
    print(web_policy_id)

    print("\n *** Mapping New internal IPs to: {policy} ***\n".format(policy=WEBPOLICY))
    put_policy(origin_id_list, web_policy_id)
    print("\n *** FINISHED ***")

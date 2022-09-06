#!/usr/bin/env python
#
import requests
import json
import urllib3
import base64
import re
from ipaddress import IPv4Network

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

import helper

umbCredStr = helper.UMBMGMTKEY + ":" + helper.UMBMGMTSEC
umbCredBytes = umbCredStr.encode("ascii")
umbCredEnc = base64.b64encode(umbCredBytes)
umbCredDec = umbCredEnc.decode("ascii")

umbDevStr = helper.UMBDEVKEY + ":" + helper.UMBDEVSEC
umbDevBytes = umbDevStr.encode("ascii")
umbDevEnc = base64.b64encode(umbDevBytes)
umbDevDec = umbDevEnc.decode("ascii")

vmanage_url_base = 'https://{vmanage}/dataservice'.format(vmanage=helper.VMANAGE)
umb_url_base = 'https://management.api.umbrella.com/v1/organizations/{org_id}'.format(org_id=helper.UMBORGID)

class IntInfo():
    def __init__(self, vpn, ip, mask):
        self.vpn = vpn
        self.ip = ip
        self.mask = mask


def get_session_id():

    url = 'https://{vmanage}/j_security_check'.format(vmanage=helper.VMANAGE)

    payload = {'j_username': helper.USER, 'j_password': helper.PASS}
    
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

    url = vmanage_url_base + '/device/sig/umbrella/tunnels?deviceId={router}'.format(router=helper.ROUTER)

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
            print("Found SIG Tunnel {tunnel} for router {router}\n".format(tunnel=sig_tunnel_name, router=helper.ROUTER))
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

    url = vmanage_url_base + '/device/interface?deviceId={router}'.format(router=helper.ROUTER)

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
    vpnlist = []

    #Set a loop to find all interfaces that are GigabiEthernet and NOT VPN 0
    #Then collect the description, vpn number, ip address and subnet mask
    for ints in int_list:
        name = ints['ifname']
        vpn = ints['vpn-id']
        if('GigabitEthernet' in name):
            if(vpn != '0'):
                
                description = ints['description']
                ip = ints['ip-address']
                mask = ints['ipv4-subnet-mask']

                curInt = {'description':description, 'vpn':vpn, 'ip':ip, 'mask':mask}
                vpnlist.append(curInt)

    print('Found Service Side VPNs - Total VPNs found is/are %i \n'.format(len(vpnlist)))
    vpnlist_json = json.dumps(vpnlist, indent=2)
    print(vpnlist_json)

    return(vpnlist)
        
def get_web_policy_name(description):

    #Grab the first word of the VPN descirption.  This will be used to match against web policy name
    split_word = description.split()
    match_word = split_word[0]

    url = umb_url_base + '/policies?type=web&page=1&limit=100'

    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'Authorization': 'Basic %s' %umbDevDec}

    resp = requests.get(url,
                        headers=headers,
                        verify=False,)

    json_data = resp.content
    data_dict = json.loads(json_data)

    # Iterate through all the web policies and find one that contains the match name from the VPN description
    for each in data_dict:
        if match_word in each['name']:
            webpolicy = each['name']
            break
        else:
            webpolicy = 'default'
        
    return(webpolicy)


def post_priv_nets(umb_sig_id_list, ip, mask, vpnid):

    origin_id_list = []
    
    url = umb_url_base + '/internalnetworks'

    headers = {'Content-Type': 'application/json',
               'Accept': 'application/json',
               'Authorization': 'Basic %s' %umbCredDec}

    for counter, sig_tunnel_int in enumerate(umb_sig_id_list):

        #create a string off the index number to be used in naming the Internal Networks
        index = str(counter)
        priv_name = 'Site9-Macrosegment-{vpn}-Tu{num}'.format(vpn=vpnid, num=index)
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

            print('\n Created Internal Network {intnet} \n'.format(intnet=priv_name))
            json_data = resp.content
            data_dict = json.loads(json_data)
            #Collect the Origin ID field from the newly created Internal Network
            orig_id = data_dict['originId']
        except:
            print('Error creating internal nets')
            continue

        origin_id_list.append(orig_id)

    return(origin_id_list)


def get_web_policy_id(webpolicy):

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
        if policy['name'] == webpolicy:
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

    #Step 1: Find the tunnels from the router to Umbrella SIG
    print("\n *** Step 1: Looking for SIG Tunnels for router {router} ***\n".format(router=helper.ROUTER))
    umb_sig_tunnel_name = get_umb_sig_name(jsessionid, token)

    #Step 2: Find the Tunnel IDs for the SIG tunnels from previous step
    print("\n *** Step 2: Looking for Tunnel IDs for SIG Tunnels ***\n")
    umb_sig_id = get_umb_sig_id(umb_sig_tunnel_name)

    #Step 3: Find information about the service side VPNs
    print("\n *** Step 3: Finding Service Side VPN Info ***\n")
    vpnlist = get_int_info(jsessionid, token)

    #Iterate through list of service side VPNs
    for each in vpnlist:
        description = each['description']
        vpnid = each['vpn']
        ip = each['ip']
        mask = each['mask']

        #Step 4: Find Web Policy by using VPN description to match against web policy name
        #!! First name of VPN description must be in web policy name !!
        print("\n *** Step 4: Find the Web Policy name for each VPN ***\n")
        webpolicy = get_web_policy_name(description)

        print("\n The web policy for vpn {vpn} is {policy} \n".format(vpn=vpnid, policy=webpolicy))

        #Step 5: Collect IP information for each service side VPN 
        print("\n *** Step 5: Collecting Info for VPN {vpn} ***\n".format(vpn=vpnid))

        print("\n The IP for vpn {vpn} is {ip}\{mask} \n".format(vpn=vpnid, ip=ip, mask=mask))

        #After collecting IP info, this program assumes /24 subnets per VPN and sets the Internal Nework to align to that
        sep_ip = re.split(r'(\.|/)', ip)
        new_ip = sep_ip[0] + '.' + sep_ip[2] + '.' + sep_ip[4] + '.0'

        sep_mask = sum(bin(int(x)).count('1') for x in mask.split('.'))

        #Step 6: Create the Internal Networks in Umbrella 
        print("\n *** Step 6: Create the Internal Netwokrs in Umbrella ***\n")
        origin_id_list = post_priv_nets(umb_sig_id, new_ip, sep_mask, vpnid)
        #print(origin_id_list)

        #Step 7: Collect the web policy Id
        print('\n *** Step 7: Collect the Web Policy Id ***\n')
        web_policy_id = get_web_policy_id(webpolicy)
        print('\n Found web policy Id for {policy}\n'.format(policy=webpolicy))

        #Step 8: Map Net Internal Networks to Web Policies
        print('\n *** Step 8: Map new Internal Network to Web Policy ***\n')
        print("\n *** Mapping New internal IPs to: {policy} ***\n".format(policy=webpolicy))
        put_policy(origin_id_list, web_policy_id)
    
    print("\n *** FINISHED ***")

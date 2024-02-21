"""
Author: Roman Eggerts
Date: February 21, 2024
Description: Script to sync Netbox API with Zscaler Sub-locations
"""


import requests
import json
import pandas as pd
import ipaddress
import warnings
import time
from datetime import datetime
import os


#######################################################################################################################
#######################################################################################################################
##          *Secrets*
##
netbox_api_token = os.environ.get('NETBOX_TOKEN', '')
passwd = os.environ.get('ZS_PASSWORD', '')
user = os.environ.get('ZS_USER', '') 
api_key = os.environ.get('ZS_API', '') 
##
##          *Secrets*
#######################################################################################################################
#######################################################################################################################

# API Helperes to authenticate to Zscaler API

def obfuscate_api_key(api_key, timestamp):
    high = timestamp[-6:]
    low = str(int(high) >> 1)
    obfuscated_api_key = ''

    while len(low) < 6:
        low = '0' + low

    for i in high:
        obfuscated_api_key += api_key[int(i)]

    for j in low:
        obfuscated_api_key += api_key[int(j) + 2]

    return obfuscated_api_key

def set_zscaler_api_variables():
    timestamp = str(int(time.time() * 1000))
    obfuscated_api_key = obfuscate_api_key(api_key, timestamp)

    payload = {
        'username': f'{user}',
        'password': f'{passwd}',
        'apiKey': obfuscated_api_key,
        'timestamp': timestamp
    }
    
    payload_json = json.dumps(payload)
    return(payload_json)

#######################################################################################################################
#######################################################################################################################
#Variables
timestamp = datetime.now().strftime("%S-%M-%H_%d-%m-%Y")
verify_cert = False

#Zscaler stuff
zscaler_base_url = 'https://zsapi.zscloud.net/api/v1/'
zscaler_auth_url = zscaler_base_url+'authenticatedSession'

headers = {
  'Content-Type': 'application/json',
  'Server': 'Zscaler',
}

payload = set_zscaler_api_variables()
auth_response = requests.request("POST", zscaler_auth_url, headers=headers, data=payload)
auth_response_headers = (auth_response.headers)
set_cookie_header = auth_response_headers.get('Set-Cookie', '')
jsessionid_value = None
if 'JSESSIONID=' in set_cookie_header:
    start = set_cookie_header.find('JSESSIONID=') + len('JSESSIONID=')
    end = set_cookie_header.find(';', start)
    jsessionid_value = set_cookie_header[start:end]


zscaler_locations_endpoint = zscaler_base_url + 'locations/{parentID}/sublocations'
zscaler_headers = {
    'Content-Type': 'application/json',
    'Cookie': f'JSESSIONID={jsessionid_value}'
}
#Netbox stuff

netbox_base_url = 'https://192.168.178.25/api/'
endpoint = 'ipam/prefixes/'
netbox_headers = {
    'Authorization': f'Token {netbox_api_token}',
    'Content-Type': 'application/json',
}
#######################################################################################################################
#######################################################################################################################
# start here:
with warnings.catch_warnings():
    warnings.simplefilter("ignore")
    #fetching data from netbox
    netbox_response = requests.get(netbox_base_url + endpoint, headers=netbox_headers, verify=verify_cert)

if netbox_response.status_code == 200:
    netbox_data = netbox_response.content
else:
    print('Failed to retrieve data from NetBox. Status code:', netbox_response.status_code)

#Parse Netbox data
netbox_data = json.loads(netbox_data)
parent_ids = set()

for result in netbox_data["results"]:
    custom_fields = result["custom_fields"]
    parent_id = custom_fields.get("parentId")
    if parent_id:
        parent_ids.update(parent_id.split(";"))

df = pd.DataFrame([{
    "id": result["id"],
    "description": result["description"],
    "prefix": result["prefix"],
    "parentId": result["custom_fields"]["parentId"]
} for result in netbox_data["results"]])

# Create netbox Dataframe
netbox_df = df.groupby(['description', 'parentId'])['prefix'].apply(','.join).reset_index()

# helper function to convert list of CIDR blocks into a continuous IP range to comply with zscaler api
def cidrs_to_continuous_range(cidr_list):
    continuous_ranges = []
    
    for cidr in cidr_list.split(','):
        net = ipaddress.ip_network(cidr, strict=False)
        ip_range = []
        for subnet in net.subnets(prefixlen_diff=0):
            ip_range.append(f"{subnet.network_address}-{subnet.broadcast_address}")
        continuous_ranges.extend(ip_range)
    
    # Sort the list of IP ranges in descending order based on the first IP address stupid api is reversed
    continuous_ranges.sort(key=lambda ip: int(ipaddress.IPv4Address(ip.split('-')[0])), reverse=True)

    return continuous_ranges

# convert the CIDR in the netbox api to zscaler IP range
netbox_df['continuous_ip_range'] = netbox_df.apply(
    lambda row: cidrs_to_continuous_range(row['prefix']), axis=1)
#update dataframe
netbox_df[['description', 'parentId', 'continuous_ip_range']]
#this are the date we are working off
netbox_df.to_csv(f"output_netbox_{timestamp}.csv", index=False)


# placehoder for Zscaler Sublocation data
zscaler_data = []

# Function to fetch sublocations for each location
for parent_id in parent_ids:   
    request_url = zscaler_locations_endpoint.replace("{parentID}", parent_id)
    response = requests.get(request_url, headers=zscaler_headers)
    if response.status_code == 200:
        zscaler_data.extend(json.loads(response.content))

# create Zscaler Dataframe out of the data        
zscaler_df = pd.DataFrame(zscaler_data)
zscaler_df.to_csv(f"output_zscaler_{timestamp}.csv", index=False)

#helper function to check if all sublocation in netbox are also present in zscaler
def check_missing_entries(netbox_df, zscaler_df):
    # Prepare a list to hold missing entries
    missing_entries = []

    # Iterate over each row in netbox_df
    for _, netbox_row in netbox_df.iterrows():
        description = netbox_row['description']
        parentIds = netbox_row['parentId'].split(';')  # Split the parentId field into a list
        for parentId in parentIds:
            matching_entries = zscaler_df[
                (zscaler_df['name'] == description) & 
                (zscaler_df['parentId'].astype(str) == parentId)
            ]
            if matching_entries.empty:
                missing_entries.append({
                    'missing_description': description,
                    'missing_parentId': parentId
                })

    return missing_entries

missing_entries = check_missing_entries(netbox_df, zscaler_df)
#List missing sublocations - they need to be created manualy
########################################################################################################################
########################################################################################################################
####
####         todo: add function to push a basic config and create the location
####
########################################################################################################################
########################################################################################################################

if missing_entries != []:
    print("Missing entries:")
    for entry in missing_entries:
        print(entry)

# Helper function to check if all entries present in zscaler_df are also present in netbox_df
# They yould be deleated.
        
def check_entries_to_deleat(zscaler_df, netbox_df):
    # Prepare a list to hold entries missing in netbox
    missing_in_netbox = []

    # Iterate over each row in zscaler_df
    for _, zscaler_row in zscaler_df.iterrows():
        name = zscaler_row['name']
        parentId = str(zscaler_row['parentId'])  # Ensure parentId is a string for comparison

        # Skip entries that contain 'other' in the name
        if 'other' in name.lower():
            continue

        # Look for matching entries in netbox_df
        matching_entries = netbox_df[
            (netbox_df['description'] == name) &
            (netbox_df['parentId'].str.contains(parentId))
        ]

        # If no matching entries are found, this entry is missing in netbox_df
        if matching_entries.empty:
            missing_in_netbox.append({
                'missing_name': name,
                'missing_parentId': parentId
            })

    return missing_in_netbox

entries_to_deleat = check_entries_to_deleat(zscaler_df, netbox_df)

entries_to_deleat_df = pd.DataFrame(entries_to_deleat)
if entries_to_deleat_df.empty:
    print("DataFrame with elements to deleat is empty ... nothing to do")
else:
    print("DataFrame with elements to deleat is empty ... let's go to work!")
    entries_to_deleat_df.to_csv(f"entries_to_deleat_{timestamp}.csv", index=False)

# List missing entries - they need to be created manually in netbox
if entries_to_deleat != []:
    print("Entries to deleat:")
    for entry in entries_to_deleat:
        print(entry)

########################################################################################################################
########################################################################################################################
####
####         todo: add function to deleat unused locations 
####
########################################################################################################################
########################################################################################################################


# Zscaler expectes the IP ranges to be the biggest possible range for example if you have two /25 networks
# The Zscaler backend will convert them to one x.x.x.0 - x.x.x.255
        
def merge_ip_ranges(ip_ranges):
    # Merge contiguous or overlapping IP ranges
    # Normalize single IPs to range format and escape them
    normalized_ranges = []
    for r in ip_ranges:
        if '-' not in r:  # It's a single IP
            r = f"{r}-{r}"
        normalized_ranges.append(r)
    
    sorted_ranges = sorted(normalized_ranges, key=lambda r: ipaddress.IPv4Address(r.split('-')[0]))
    merged_ranges = []

    current_start, current_end = sorted_ranges[0].split('-')
    current_start = ipaddress.IPv4Address(current_start)
    current_end = ipaddress.IPv4Address(current_end)

    for r in sorted_ranges[1:]:
        start, end = r.split('-')
        start = ipaddress.IPv4Address(start)
        end = ipaddress.IPv4Address(end)

        if start <= current_end + 1:
            current_end = max(current_end, end)
        else:
            merged_ranges.append(f"{current_start}-{current_end}")
            current_start, current_end = start, end

    merged_ranges.append(f"{current_start}-{current_end}")
    return merged_ranges

# helper function to identify the difference betwen the Zscaler Dataframe and the Netbox Dataframe

def diff_dataframes(df_zscaler, df_netbox):
    updates = []
    processed_zscaler_ids = set()  # Track processed IDs to avoid duplicates

    for indexZ, rowZ in df_zscaler.iterrows():
        if rowZ['id'] in processed_zscaler_ids:
            continue  # Skip this entry if it has already been processed

        for indexN, rowN in df_netbox.iterrows():
            if rowZ['name'] == rowN['description'] and any(pid == str(rowZ['parentId']) for pid in rowN['parentId'].split(';')):
                zscaler_ips = eval(rowZ['ipAddresses']) if isinstance(rowZ['ipAddresses'], str) else rowZ['ipAddresses']
                netbox_ips = eval(rowN['continuous_ip_range']) if isinstance(rowN['continuous_ip_range'], str) else rowN['continuous_ip_range']
                normalized_zscaler_ips = merge_ip_ranges(zscaler_ips)
                normalized_netbox_ips = merge_ip_ranges(netbox_ips)

                if set(normalized_zscaler_ips) != set(normalized_netbox_ips):
                    updates.append({
                        'id': rowZ['id'],
                        'parentId': rowZ['parentId'],
                        'name': rowZ['name'],
                        'old_ipAddresses': zscaler_ips, 
                        'ipAddresses': normalized_netbox_ips,
                        'upBandwidth': rowZ['upBandwidth'],
                        'dnBandwidth': rowZ['dnBandwidth'],
                        'country': rowZ['country'],
                        'language': rowZ['language'],
                        'tz': rowZ['tz'],
                        'latitude': rowZ['latitude'],
                        'longitude': rowZ['longitude'],
                        'authRequired': rowZ['authRequired'],
                        'xffForwardEnabled': rowZ['xffForwardEnabled'],
                        'surrogateIP': rowZ['surrogateIP'],
                        'idleTimeInMinutes': rowZ['idleTimeInMinutes'],
                        'surrogateIPEnforcedForKnownBrowsers': rowZ['surrogateIPEnforcedForKnownBrowsers'],
                        'surrogateRefreshTimeInMinutes': rowZ['surrogateRefreshTimeInMinutes'],
                        'kerberosAuth': rowZ['kerberosAuth'],
                        'digestAuthEnabled': rowZ['digestAuthEnabled'],
                        'ofwEnabled': rowZ['ofwEnabled'],
                        'ipsControl': rowZ['ipsControl'],
                        'aupEnabled': rowZ['aupEnabled'],
                        'cautionEnabled': rowZ['cautionEnabled'],
                        'aupBlockInternetUntilAccepted': rowZ['aupBlockInternetUntilAccepted'],
                        'aupForceSslInspection': rowZ['aupForceSslInspection'],
                        'iotDiscoveryEnabled': rowZ['iotDiscoveryEnabled'],
                        'aupTimeoutInDays': rowZ['aupTimeoutInDays'],
                        'staticLocationGroups': rowZ['staticLocationGroups'],
                        'dynamiclocationGroups': rowZ['dynamiclocationGroups'],
                        'excludeFromDynamicGroups': rowZ['excludeFromDynamicGroups'],
                        'excludeFromManualGroups': rowZ['excludeFromManualGroups'],
                        'profile': rowZ['profile'],
                        'description': rowZ['description'],
                        'ipv6Enabled': rowZ['ipv6Enabled'],
                        'ipv6Dns64Prefix': rowZ['ipv6Dns64Prefix']

                    })
                    processed_zscaler_ids.add(rowZ['id'])  # Mark this ID as processed
                    break  # Break out of the loop to avoid processing the same entry again

    return updates

#identify the diff in the dataframes
updates_needed = diff_dataframes(zscaler_df, netbox_df)
#create new dataframe with the diff
updates_needed_df = pd.DataFrame(updates_needed)
if updates_needed_df.empty:
    print("DataFrame is empty ... nothing to do")
else:
    print("DataFrame is not empty ... let's go to work!")
    updates_needed_df.to_csv(f"diff_{timestamp}.csv", index=False)


#Updates the Subloations where a change is needed
for item in updates_needed:
    url = f"{zscaler_base_url}locations/{item['id']}"
    payload = {
        "parentId":                             item['parentId'],
        "name":                                 item['name'],
        "ipAddresses":                          item['ipAddresses'],
        'upBandwidth':                          item['upBandwidth'],
        'dnBandwidth':                          item['dnBandwidth'],
        'country':                              item['country'],
        'language':                             item['language'],
        'tz':                                   item['tz'],
        'latitude':                             item['latitude'],
        'longitude':                            item['longitude'],
        'authRequired':                         item['authRequired'],
        'xffForwardEnabled':                    item['xffForwardEnabled'],
        'surrogateIP':                          item['surrogateIP'],
        'idleTimeInMinutes':                    item['idleTimeInMinutes'],
        'surrogateIPEnforcedForKnownBrowsers':  item['surrogateIPEnforcedForKnownBrowsers'],
        'surrogateRefreshTimeInMinutes':        item['surrogateRefreshTimeInMinutes'],
        'kerberosAuth':                         item['kerberosAuth'],
        'digestAuthEnabled':                    item['digestAuthEnabled'],
        'ofwEnabled':                           item['ofwEnabled'],
        'ipsControl':                           item['ipsControl'],
        'aupEnabled':                           item['aupEnabled'],
        'cautionEnabled':                       item['cautionEnabled'],
        'aupBlockInternetUntilAccepted':        item['aupBlockInternetUntilAccepted'],
        'aupForceSslInspection':                item['aupForceSslInspection'],
        'iotDiscoveryEnabled':                  item['iotDiscoveryEnabled'],
        'aupTimeoutInDays':                     item['aupTimeoutInDays'],
        'staticLocationGroups':                 item['staticLocationGroups'],
        'dynamiclocationGroups':                item['dynamiclocationGroups'],
        'excludeFromDynamicGroups':             item['excludeFromDynamicGroups'],
        'excludeFromManualGroups':              item['excludeFromManualGroups'],
        'profile':                              item['profile'],
        'description':                          item['description'],
        'ipv6Enabled':                          item['ipv6Enabled'],
        'ipv6Dns64Prefix':                      item['ipv6Dns64Prefix']
    }

    #to dry-run uncomment this and comment the next line starting with response
    #print(payload)
    response = requests.put(url, json=payload, headers=zscaler_headers)
    #print(payload)
    if response.status_code == 200:
        print(f"Successfully updated {item['name']} - {item['parentId']}")
    else:
        print(f"Failed to update {item['id']} - {item['name']}. Status code: {response.status_code}.\nError: {response.content}")

########################################################################################################################
########################################################################################################################
####
####         todo: still a logic issue in case the range exists in another sublocation that was not altered before
####               temp workaround is running the script twice
####               this will be possible in case the range was successfuly removed from the item and is no longer
####               blocking the second run. 
####
########################################################################################################################
########################################################################################################################


#Activates the saved configuration changes
response = requests.request("POST", f"{zscaler_base_url}status/activate", headers=zscaler_headers, data="")
if response.status_code == 200:
    print(f"Successfully Activated --> {response.text}")
else:
    print(f"Failed to update. Status code: {response.status_code}.\nError: {response.content}")

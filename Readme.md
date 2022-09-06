    ##Extending SD-WAN Macrosegmentation to Umbrella
    
    This repository is a script that automates extending SD-WAN VPNs/VRFs into Umbrella.  It assumes the following:
    1. SIG tunnels are already in place between the router and Umbrella
    2. Web policies have already been created in Umbrella to be used for each VPN.
    3. The naming convention of the VPNs description begins with a unique name to identify each VPN (i.e. "Corporate" or "Iot").
    4. The web policies also contain this unique name so they can be identified.
    5. Each subnet for the service side VPNs are /24 subnets.
    
    The script collects information from vManage (sd-wan controller) about the service side VPNs.  With the collected info, it then creates a set of Internal Networks in Umbrella based on the IP information gathered from the VPN and the SIG tunnel information.  After creating these networks, it then makes these new networks source Identities for the web policy.

    This page contains the umb-seg.py script, which has all the logic for running the script.
    In addition, there is a helper.py file that must be modified to include all the values for a user's particular situation.

    To use this script, add/modify the values for the following variables:
    VMANAGE - The FQDN or IP address of your vManage
    USER - The username for vManage with access to the APIs
    PASS - The password for vManage with access to the APIs
    ROUTER - The routerId as seen by vManage of the device where you are extending segmentation
    UMBORGID - Your Umbrella Organization Id
    UMBMGMTKEY - The API Key for Umbrella Management (this is now in the Legacy Keys section)
    UMBMGMTSEC - The API Secret for Umbrella Management
    UMBDEVKEY - The API Key for Umbrella Network Devices
    UMBDEVSEC - The API Secret for Umbrella Network Devices

    Note:  This script was written using Umbrella v1 APIs.  

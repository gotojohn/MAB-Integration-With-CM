# MAB-Integration-With-CM
Updates an AD used for MAC Authentication Bypass (MAB) by querying a SCCM/MEMCM for known MAC addresses.

# Installation
SCCM/MEMCM
1. Create a Query in SCCM/MEMCM for all the approved MAC-adresses (Will require som filtering). Include properties from the computer that will be used to make a description.
2. Create/Define a restricted "Service" User (1) to run the Query.

AD
1. Create a seperate "OU" in an restricted Active Directory (AD) used for MAB. 
2. Create/Define an AD-group used for fine grained passwordpolicy. (Username = Password)
3. Create/Define an AD-group used for vlan assignment.
4. Create/Define a restricted "Service" user (2) to update (Create/Remove) user accounts to the OU and assign membership to the AD-groups.

Running as a scheduled task
1. Place the script in a separate folder (Will be populated with logs and encrypted credentials).
2. Define a "Service" users (3) to run the script on the server.
3. Run the script manually as the selected "Service" users (3) on the server. This will create the encrypted credentials only accessible for that user (3).
3. Setup a scheduled task as the example "Scheduled_Task_Example.xml".

Running manually
1. Place the script in a separate folder (Will be populated with logs and encrypted credentials).
2. Run the script.

# Verified on 
Microsoft Endpoint Configuration Manager 5.2006.1024.1005.
Active Directory for Windows Server 2019 (Schema Version 88)
Powershell 5.1 with ActiveDirectory module 1.0.1.0


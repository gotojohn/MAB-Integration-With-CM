@{
#These settings will be loaded by the main script.
    
    #Version of the configurationfile
    #Update freely.
    Version = "1.0"
    
    #Your identifier for this MAB integration. Eg. "VLAN 007". 
    #Useful if multiple integrations is in use.
    Identifier = ""

    #Information about the Active Directory (AD) Domain
    ADSettings = @{
        #Your domain
        Domain = "my.test"
        #Restricted OU that will be used for populating accounts (representing approved MAC-adresses).
        ChangeBase = "OU=CM,OU=Staging-Demo,DC=my,DC=test"
        #AD-group for fine grained passwordpolicy
        GroupPasswordPolicy = "the-password-policy"
        #AD-group for vlan assignement
        GroupVLAN = "the-vlan"
    }

    #Information about Microsoft Endpoint Manager Configuration Manager (MEMCM) / System Center Configuration Manager (SCCM)
    CMSettings = @{ 
        SiteCode = "SC1"
        SMSProvider = "your.cm.com"
        #Query with approved MAC-adresses
        QueryID = "thequeryid"
        #Collection to limit the query
        QueryCollection = "thecollectionid"
        #Minimum and Maximum resultant of objects from CM. (Safety-fix for the CM Query integration during changes in CM)
        ExpectedMin = 1
        ExpectedMax = 10000

        #Validation for the query to CM
        QueryValidation = @{
            #Expected properties from the Query
            ExpectedProps = @("PSComputerName","PSShowComputerName","SmsProviderObjectPath","SMS_G_System_COMPUTER_SYSTEM","SMS_G_System_NETWORK_ADAPTER","SMS_G_System_NETWORK_ADAPTER_CONFIGURATION","SMS_G_System_PC_BIOS","SMS_G_System_SERVICE","SMS_R_System")
        }
        
        #Translation of the queried properties to strings.
        QueryTranslation = @{
            #Use <> to define placeholders for the property.

            #Define the property with the MAC-address. Eg. "<SMS_G_System_NETWORK_ADAPTER.MACAddress>"
            MAC = "<SMS_G_System_NETWORK_ADAPTER.MACAddress>"
            #Define the description, using the properties. Eg "<PROPERTIES.B>, some text <PROPERTIES.C> more text"
            Description = "<SMS_G_System_COMPUTER_SYSTEM.Manufacturer>, <SMS_G_System_COMPUTER_SYSTEM.Model>, SerialNr: <SMS_G_System_PC_BIOS.SerialNumber>, Hostname: <SMS_R_System.Name>"
        }
    }
    OtherSettings = @{
        #Settings used for statusreport over SMTP.
        Mail = @{
            Recipient = "recipient_example@youremail.com"
            Sender = "sender_example@youremail.com"
            SMTPServer = "your.smtpserver.com"
        }
    }
}

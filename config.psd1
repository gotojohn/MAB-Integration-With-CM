@{
#These settings will be loaded by the main script.
    
    #Version of the configuration
    Version = "1.0"

    #Information about the Active Directory (AD) Domain
    ADSettings = @{
        Domain = "my.test"
        ChangeBase = "OU=CM,OU=Staging-Demo,DC=my,DC=test"
        GroupPasswordPolicy = "the-password-policy"
        GroupVLAN = "the-vlan"
    }

    #Information about Microsoft Endpoint Manager Configuration Manager (MEMCM) / System Center Configuration Manager (SCCM)
    CMSettings = @{ 
        SiteCode = "SC1"
        SMSProvider = "your.cm.com"
        #Query with approved MAC-adresses
        QueryID = "thequeryid"
        #Collection to limit the query
        QueryCollection = "thecollecitonid"
         #Minimum and Maximum resultant of objects from CM. (Safety-fix for the CM Query integration)
        ExpectedMin = 1
        ExpectedMax = 10000

        QueryValidation = @{
            #Expected properties from the Query
            ExpectedProps = @("PSComputerName","PSShowComputerName","SmsProviderObjectPath","SMS_G_System_COMPUTER_SYSTEM","SMS_G_System_NETWORK_ADAPTER","SMS_G_System_NETWORK_ADAPTER_CONFIGURATION","SMS_G_System_PC_BIOS","SMS_G_System_SERVICE","SMS_R_System")
        }

        QueryTranslation = @{
            #Use <> to define placeholders for the property.

            #Define the property with the MAC-address. Eg. "<SMS_G_System_NETWORK_ADAPTER.MACAddress>"
            MAC = "<SMS_G_System_NETWORK_ADAPTER.MACAddress>"
            #Define the description, using the properties. Eg "<PROPERTIES.B>, some text <PROPERTIES.C> more text"
            Description = "<SMS_G_System_COMPUTER_SYSTEM.Manufacturer>, <SMS_G_System_COMPUTER_SYSTEM.Model>, SerialNr: <SMS_G_System_PC_BIOS.SerialNumber>, Hostname: <SMS_R_System.Name>"
        }
    }
    OtherSettings = @{
        Mail = @{
            Recipient = "recipient_example@youremail.com"
            Sender = "sender_example@youremail.com"
            SMTPServer = "your.smtpserver.com"
        }
    }
}

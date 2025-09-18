Import-Module WebAdministration

$ruleName = "block useragent webscrapers"

# Add a request filtering rule to deny specific User-Agent strings server-wide
Add-WebConfigurationProperty -PSPath "IIS:\" `
    -Filter "system.webServer/security/requestFiltering/filteringRules" `
    -Name "." `
    -Value @{
        name = $ruleName
    }

# Configure the rule to apply to the User-Agent header
Add-WebConfigurationProperty -PSPath "IIS:\" `
    -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/scanHeaders" `
    -Name "." `
    -Value "User-Agent"

# Add denyStrings to the  filtering rule


# wget
# useragent: Wget/1.11.4
Add-WebConfigurationProperty -PSPath "IIS:\" `
    -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="Wget"} `
    -Force

# curl
# useragent: curl/8.16.0
Add-WebConfigurationProperty -PSPath "IIS:\" `
    -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="curl"} `
    -Force
	
# powershell iwr
# useragent: Mozilla/5.0+(Windows+NT;+Windows+NT+10.0;+en-NL)+WindowsPowerShell/5.1.26100.6584
Add-WebConfigurationProperty -PSPath "IIS:\" `
    -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="WindowsPowerShell"} `
    -Force
	
# bitsadmin
# useragent: Microsoft+BITS/7.8
Add-WebConfigurationProperty -PSPath "IIS:\" `
    -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="Microsoft+BITS"} `
    -Force
	

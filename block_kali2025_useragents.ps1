Import-Module WebAdministration

$ruleName = "kali tools 2025"

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


# dirbuster 1.0 rc1 
# useragent: DirBuster-1.0-RC1+(http://www.owasp.org/index.php/Category:OWASP_DirBuster_Project)
Add-WebConfigurationProperty -PSPath "IIS:\" `
    -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="DirBuster"} `
    -Force

# fuff 2.1.0 dev
# useragent: Fuzz+Faster+U+Fool+v2.1.0-dev 
Add-WebConfigurationProperty -PSPath "IIS:\" `
    -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="Fuzz"} `
    -Force
	
# gobuster
# useragent: gobuster/3.6
Add-WebConfigurationProperty -PSPath "IIS:\" `
    -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="gobuster"} `
    -Force

# davtest
# useragent: DAV.pm/v0.50
Add-WebConfigurationProperty -PSPath "IIS:\" `
    -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="DAV.pm"} `
    -Force	
	
# WhatWeb
# useragent: Whatweb 0.5.5
Add-WebConfigurationProperty -PSPath "IIS:\" `
    -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="WhatWeb"} `
    -Force	
	
# Wpscan 3.2.28
# useragent: WPScan+v3.8.28+(https://wpscan.com/wordpress-security-scanner)
Add-WebConfigurationProperty -PSPath "IIS:\" `
    -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="WPScan"} `
    -Force	
	

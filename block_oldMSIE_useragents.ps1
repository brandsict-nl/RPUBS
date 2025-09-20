Import-Module WebAdministration

$ruleName = "block useragent old MSIE"

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

# MS internet explorer
# useragents: 
# Internet Explorer - Windows Server 2022 21H2 - about box MSIE doesn't show specific ie version
# 	Mozilla/5.0+(Windows+NT+10.0;+WOW64;+Trident/7.0;+rv:11.0)+like+Gecko
#
# Internet Explorer	- Windows Server 2019 - about box MSIE doesn't show specific ie version	 
#	Mozilla/5.0+(Windows+NT+10.0;+WOW64;+Trident/7.0;+rv:11.0)+like+Gecko
#
# Internet Explorer 11.0.9600.21615 update versions: 11.0.315 - Windows Server 2012 r2	
#	Mozilla/5.0+(Windows+NT+6.3;+WOW64;+Trident/7.0;+rv:11.0)+like+Gecko
#
# Internet Explorer 11.0.9600.19596 update versions: 11.0.170 - Windows Server 2008 r2	
#	Mozilla/5.0+(Windows+NT+6.1;+WOW64;+Trident/7.0;+rv:11.0)+like+Gecko
#
Add-WebConfigurationProperty -PSPath "IIS:\" `
    -Filter "system.webServer/security/requestFiltering/filteringRules/filteringRule[@name='$ruleName']/denyStrings" `
    -Name "." `
    -Value @{string="Trident"} `
    -Force

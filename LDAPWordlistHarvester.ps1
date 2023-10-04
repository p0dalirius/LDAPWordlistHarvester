# File name          : LDAPWordlistHarvester.ps1
# Author             : Podalirius (@podalirius_)
# Date created       : 21 September 2023

Param (
    [parameter(Mandatory=$true)][string]$dcip = $null,
    [parameter(Mandatory=$false,ParameterSetName="Credentials")][System.Management.Automation.PSCredential]$Credentials,
    [parameter(Mandatory=$false,ParameterSetName="Credentials")][Switch]$UseCredentials,
    [parameter(Mandatory=$false)][switch]$LDAPS,
    [parameter(Mandatory=$false)][switch]$Help
)

If ($Help) {
    Write-Host "[+]========================================================"
    Write-Host "[+] Powershell LDAPWordlistHarvester v1.3    @podalirius_  "
    Write-Host "[+]========================================================"
    Write-Host ""

    Write-Host "Required arguments:"
    Write-Host "  -dcip             : LDAP host to target, most likely the domain controller."
    Write-Host ""
    Write-Host "Optional arguments:"
    Write-Host "  -Help             : Displays this help message"
    Write-Host "  -Quiet            : Do not print keys, only export them."
    Write-Host "  -UseCredentials   : Flag for asking for credentials to authentication"
    Write-Host "  -Credentials      : Providing PSCredentialObject for authentication"
    Write-Host "  -LDAPS            : Use LDAPS instead of LDAP."
    exit 0
}

if ($UseCredentials -and ([string]::IsNullOrEmpty($Credentials))) {
    $Credentials = Get-Credential
}

#===============================================================================

Write-Host  "[+]========================================================"
Write-Host  "[+] Powershell LDAPWordlistHarvester v1.3    @podalirius_  "
Write-Host  "[+]========================================================"
Write-Host  ""

# Handle LDAPS connection
$connectionString = "LDAP://{0}:{1}";
If ($LDAPS) {
    $connectionString = ($connectionString -f $dcip, "636");
} else {
    $connectionString = ($connectionString -f $dcip, "389");
}
Write-Verbose "Using connectionString: $connectionString"

# Connect to LDAP
try {

    $wordList = @()

    # Setup LDAP session
    $rootDSE = New-Object System.DirectoryServices.DirectoryEntry("{0}/RootDSE" -f $connectionString);
    $defaultNamingContext = $rootDSE.Properties["defaultNamingContext"].ToString();
    $configurationNamingContext = $rootDSE.Properties["configurationNamingContext"].ToString();
    Write-Host "[+] Authentication successful!";


    # Extracting AD sites
    $ldapSearcher = New-Object System.DirectoryServices.DirectorySearcher
    if ($Credentials.UserName) {
        $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $configurationNamingContext), $Credentials.UserName, $($Credentials.Password | ConvertFrom-Securestring -AsPlaintext))
    } else {
        $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $configurationNamingContext))
    }
    $ldapSearcher.SearchScope = "Subtree"
    $ldapSearcher.PageSize = 5000
    Write-Host "[>] Extracting AD Sites from LDAP ... "
    $ldapSearcher.Filter = "(objectClass=site)"
    $ldapSearcher.PropertiesToLoad.Clear();
    $ldapSearcher.PropertiesToLoad.Add("name") | Out-Null ;
    $ldapSearcher.PropertiesToLoad.Add("description") | Out-Null ;
    $added = 0
    Foreach ($entry in $ldapSearcher.FindAll()) {
        Foreach ($word in ($entry.Properties["description"] -split '\s+')) {
            If ($word -notin $wordList) { $wordList += $word; $added += 1 }
        }
        $wordList += $entry.Properties["description"]
        Foreach ($word in ($entry.Properties["name"] -split '\s+')) {
            If ($word -notin $wordList) { $wordList += $word; $added += 1 }
        }
        $wordList += $entry.Properties["name"]
    }
    Write-Host (" └──[+] Added {0} unique words to wordlist." -f $added)


    # Extracting user and computer
    $ldapSearcher = New-Object System.DirectoryServices.DirectorySearcher
    if ($Credentials.UserName) {
        $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $defaultNamingContext), $Credentials.UserName, $($Credentials.Password | ConvertFrom-Securestring -AsPlaintext))
    } else {
        $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $defaultNamingContext))
    }
    $ldapSearcher.SearchScope = "Subtree"
    $ldapSearcher.PageSize = 5000
    Write-Host "[>] Extracting user and computer names from LDAP ... "
    $ldapSearcher.Filter = "(|(objectClass=person)(objectClass=user)(objectClass=computer))"
    $ldapSearcher.PropertiesToLoad.Clear();
    $ldapSearcher.PropertiesToLoad.Add("name") | Out-Null ;
    $ldapSearcher.PropertiesToLoad.Add("sAMAccountName") | Out-Null ;
    $added = 0
    Foreach ($entry in $ldapSearcher.FindAll()) {
        Foreach ($word in ($entry.Properties["name"] -split '\s+')) {
            If ($word -notin $wordList) { $wordList += $word; $added += 1 }
        }
        $wordList += $entry.Properties["name"]
        Foreach ($word in ($entry.Properties["sAMAccountName"] -split '\s+')) {
            If ($word -notin $wordList) { $wordList += $word; $added += 1 }
        }
        $wordList += $entry.Properties["sAMAccountName"]
    }
    Write-Host (" └──[+] Added {0} unique words to wordlist." -f $added)


    # Extracting descriptions
    $ldapSearcher = New-Object System.DirectoryServices.DirectorySearcher
    if ($Credentials.UserName) {
        $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $defaultNamingContext), $Credentials.UserName, $($Credentials.Password | ConvertFrom-Securestring -AsPlaintext))
    } else {
        $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $defaultNamingContext))
    }
    $ldapSearcher.SearchScope = "Subtree"
    $ldapSearcher.PageSize = 5000
    Write-Host "[>] Extracting descriptions of all LDAP objects ... "
    $ldapSearcher.Filter = "(description=*)"
    $ldapSearcher.PropertiesToLoad.Clear();
    $ldapSearcher.PropertiesToLoad.Add("description") | Out-Null ;
    $added = 0
    Foreach ($entry in $ldapSearcher.FindAll()) {
        Foreach ($word in ($entry.Properties["description"] -split '\s+')) {
            If ($word -notin $wordList) { $wordList += $word; $added += 1 }
        }
    }
    Write-Host (" └──[+] Added {0} unique words to wordlist." -f $added)


    # Extracting group names of all LDAP objects
    $ldapSearcher = New-Object System.DirectoryServices.DirectorySearcher
    if ($Credentials.UserName) {
        $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $defaultNamingContext), $Credentials.UserName, $($Credentials.Password | ConvertFrom-Securestring -AsPlaintext))
    } else {
        $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $defaultNamingContext))
    }
    $ldapSearcher.SearchScope = "Subtree"
    $ldapSearcher.PageSize = 5000
    Write-Host "[>] Extracting group names of all LDAP objects ... "
    $ldapSearcher.Filter = "(objectCategory=group)"
    $ldapSearcher.PropertiesToLoad.Clear();
    $ldapSearcher.PropertiesToLoad.Add("name") | Out-Null ;
    $added = 0
    Foreach ($entry in $ldapSearcher.FindAll()) {
        Foreach ($word in ($entry.Properties["name"] -split '\s+')) {
            If ($word -notin $wordList) { $wordList += $word; $added += 1 }
        }
        $wordList += $entry.Properties["name"]
    }
    Write-Host (" └──[+] Added {0} unique words to wordlist." -f $added)


    # Extracting organizationalUnit names of all LDAP objects
    $ldapSearcher = New-Object System.DirectoryServices.DirectorySearcher
    if ($Credentials.UserName) {
        $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $defaultNamingContext), $Credentials.UserName, $($Credentials.Password | ConvertFrom-Securestring -AsPlaintext))
    } else {
        $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $defaultNamingContext))
    }
    $ldapSearcher.SearchScope = "Subtree"
    $ldapSearcher.PageSize = 5000
    Write-Host "[>] Extracting organizationalUnit names ... "
    $ldapSearcher.Filter = "(objectCategory=organizationalUnit)"
    $ldapSearcher.PropertiesToLoad.Clear();
    $ldapSearcher.PropertiesToLoad.Add("name") | Out-Null ;
    $added = 0
    Foreach ($entry in $ldapSearcher.FindAll()) {
        Foreach ($word in ($entry.Properties["name"] -split '\s+')) {
            If ($word -notin $wordList) { $wordList += $word; $added += 1 }
        }
        $wordList += $entry.Properties["name"]
    }
    Write-Host (" └──[+] Added {0} unique words to wordlist." -f $added)


    # Extracting servicePrincipalName
    $ldapSearcher = New-Object System.DirectoryServices.DirectorySearcher
    if ($Credentials.UserName) {
        $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $defaultNamingContext), $Credentials.UserName, $($Credentials.Password | ConvertFrom-Securestring -AsPlaintext))
    } else {
        $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $defaultNamingContext))
    }
    $ldapSearcher.SearchScope = "Subtree"
    $ldapSearcher.PageSize = 5000
    Write-Host "[>] Extracting servicePrincipalName of all LDAP objects ... "
    $ldapSearcher.Filter = "(servicePrincipalName=*)"
    $ldapSearcher.PropertiesToLoad.Clear();
    $ldapSearcher.PropertiesToLoad.Add("servicePrincipalName") | Out-Null ;
    $added = 0
    Foreach ($entry in $ldapSearcher.FindAll()) {
        Foreach ($word in ($entry.Properties["servicePrincipalName"] -split '\s+')) {
            If ($word -notin $wordList) { $wordList += $word; $added += 1 }
        }
    }
    Write-Host (" └──[+] Added {0} unique words to wordlist." -f $added)


    # Extracting trustedDomains
    $ldapSearcher = New-Object System.DirectoryServices.DirectorySearcher
    if ($Credentials.UserName) {
        $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $defaultNamingContext), $Credentials.UserName, $($Credentials.Password | ConvertFrom-Securestring -AsPlaintext))
    } else {
        $ldapSearcher.SearchRoot = New-Object System.DirectoryServices.DirectoryEntry(("{0}/{1}" -f $connectionString, $defaultNamingContext))
    }
    $ldapSearcher.SearchScope = "Subtree"
    $ldapSearcher.PageSize = 5000
    Write-Host "[>] Extracting trustedDomains of all LDAP objects ... "
    $ldapSearcher.Filter = "(objectClass=trustedDomain)"
    $ldapSearcher.PropertiesToLoad.Clear();
    $ldapSearcher.PropertiesToLoad.Add("name") | Out-Null ;
    $added = 0
    Foreach ($entry in $ldapSearcher.FindAll()) {
        Foreach ($word in ($entry.Properties["name"] -split '\s+')) {
            If ($word -notin $wordList) { $wordList += $word; $added += 1 }
        }
    }
    Write-Host (" └──[+] Added {0} unique words to wordlist." -f $added)


    # Exporting output
    $outputFile = "wordlist.txt"
    Write-Host ("[+] Writing {0} words to {1} ... " -f $wordList.Lenght, $outputFile)
    $wordList | Out-File -FilePath $outputFile -Encoding UTF8

} catch {
    Write-Verbose $_.Exception
    Write-Host ("[!] (0x{0:X8}) {1}" -f $_.Exception.HResult, $_.Exception.InnerException.Message)
    exit -1
}
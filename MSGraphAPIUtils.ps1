Add-Type -AssemblyName System.Web

#note "Group.ReadWrite.All User.ReadWrite.All openid profile offline_access"
#offline access required for refresh_token

#msgraph
$msgraph = @{ resource = "https://graph.microsoft.com/";
              appId = "14d82eec-204b-4c2f-b7e8-296a70dab67e" }

$tenant = "ldej.onmicrosoft.com"

$tokenBaseEndpoint = "https://login.microsoftonline.com/" + $tenant + "/oauth2/v2.0/"


Function Convert-FromUnixDate ($UnixDate) {
   [timezone]::CurrentTimeZone.ToLocalTime(([datetime]'1/1/1970').AddSeconds($UnixDate))
}


function Get-OAuthTokenByClientSecret([string] $tenant, [string]$resource, [string] $appID , [string] $clientSecret, [string] $scope = ".default")
{
    $tokenEndpoint = ($tokenBaseEndpoint + "token") 
    $headers = @{}
    $headers.Add("Content-Type","application/x-www-form-urlencoded")
    $headers.Add("Accept","application/json")
    $postBody = @{resource = $resource ;
                client_id = $AppID ;
                grant_type = "client_credentials" ;
                client_secret = $clientSecret;
                scope =  ( $scope )
                };
    
    $Token= Invoke-RestMethod -Headers $headers -Uri $tokenEndpoint -Body $postBody -Method Post
    return $Token
}

function Get-OAuthTokenByUser([string] $tenant, [string]$resource, [string] $appID, [string] $userName, [string] $password, [string] $scope = ".default")
{
    $tokenEndpoint = ($tokenBaseEndpoint + "token") 
    $headers = @{}
    $headers.Add("Content-Type","application/x-www-form-urlencoded")
    $headers.Add("Accept","application/json")

    $postBody = @{
                client_id = $AppID ;
                grant_type = "password" ;
                username = $userName;
                password = $password;
                scope =  ( $scope )
                };

    $Token= Invoke-RestMethod -Headers $headers -Uri $tokenEndpoint -Body $postBody -Method Post
    return $Token
}

function Start-OAuthTokenByDeviceLogin([string] $tenant, [string]$resource, [string] $appID , [string] $scope = ".default")
{
    $devicecodeendpoint = ($tokenBaseEndpoint + "devicecode") 

    $headers = @{}
    $headers.Add("Content-Type","application/x-www-form-urlencoded")
    $headers.Add("Accept","application/json")
   
    $postBody = @{
                   client_id = $appid ;
                   scope =  (  $scope )
                 }
    $response = Invoke-RestMethod -Method POST -Uri $devicecodeendpoint -Body $postBody -Headers $headers
    Write-Host $response.message
    $code = ($response.message -split "code " | Select-Object -Last 1) -split " to authenticate."
    Set-Clipboard -Value $code
    return $response.device_code
}

function Get-OAuthTokenByDeviceLogin([string] $tenant, [string]$resource, [string] $appID , [string] $devicecode)
{
    $devicecodeendpoint = ($tokenBaseEndpoint + "devicecode") 
    $headers = @{}
    $headers.Add("Content-Type","application/x-www-form-urlencoded")
    $headers.Add("Accept","application/json")
    $postBody = @{  grant_type = "device_code"; 
                    resource = "$resource"; 
                    client_id = "$appID"; 
                    code = $devicecode }
    $token = Invoke-RestMethod -Method POST -Uri $devicecodeendpoint -Body $postBody -Headers $headers
    return $token
}

function Get-AccessTokenFromRefreshToken([string] $tenant, [string]$resource, [string] $appID , [string] $refresh_token)
{
    $tokenEndpoint = ($tokenBaseEndpoint + "token") 
    $headers = @{}
    $headers.Add("Content-Type","application/x-www-form-urlencoded")
    $headers.Add("Accept","application/json")

    $postBody = @{  grant_type = "refresh_token"; 
                    refresh_token = $refresh_token;
                    client_id = "$appID" }

    $token = Invoke-RestMethod -Method POST -Uri $tokenEndpoint -Body $postBody -Headers $headers
    return $token
}


function JWTParser ($jWTToken) 
{
    $base64Url = $jWTToken.split('.')[1]
    $base64 = $base64Url.replace('-', '+').replace('_', '/')
    if (($base64.Length % 4) -gt 0)
    {
        $base64Padding = "=" * (4 - ($base64.Length % 4))
    }
    else
    {
        $base64Padding = $null
    }
    $jsonString = [System.Text.Encoding]::UTF8.GetString([System.Convert]::FromBase64String($base64+$base64Padding))
    return $jsonString | ConvertFrom-Json         
}

Function GetGraphObjectSByType
  {
    param
        (
        [Parameter(Mandatory=$true)]
        $Token,
        [Parameter(Mandatory=$true)]
        $Type,
        $APIVersion = "beta"
       )
    #------Building Rest Api header with authorization token------#

    $authHeader = @{
        'Content-Type'='application/json'
        'Authorization'= ("Bearer " + $token.access_token)
        }

    $uri = "https://graph.microsoft.com/" + $APIVersion + "/" + $Type 
    $objects = Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Get 
    return $objects
}

Function GetGraphObjectByType
  {
    param
        (
        [Parameter(Mandatory=$true)]
        $Token,
        [Parameter(Mandatory=$true)]
        $Type,
        [Parameter(Mandatory=$true)]
        $OID,
        $APIVersion = "beta"
       )
    #------Building Rest Api header with authorization token------#

    $authHeader = @{
        'Content-Type'='application/json'
        'Authorization'= ("Bearer " + $token.access_token)
        }

    $uri = "https://graph.microsoft.com/" + $APIVersion + "/" + $Type + "/" + $OID
    $objects = Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Get 
    return $objects
}
Function DeleteGraphObjectByType
  {
    param
        (
        [Parameter(Mandatory=$true)]
        $Token,
        [Parameter(Mandatory=$true)]
        $Type,
        [Parameter(Mandatory=$true)]
        $OID,
        $APIVersion = "beta"
       )
    #------Building Rest Api header with authorization token------#

    $authHeader = @{
        'Content-Type'='application/json'
        'Authorization'= ("Bearer " + $token.access_token)
        }
    
    $uri = "https://graph.microsoft.com/" + $APIVersion + "/" + $Type + "/" + $OID 
    Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Delete    
}




Function NewGraphObjectByType
  {
    param
        (
        [Parameter(Mandatory=$true)]
        $Token,
        [Parameter(Mandatory=$true)]
        $Type,
        [Parameter(Mandatory=$true)]
        $ObjectInJson,
        $APIVersion = "beta"
       )
    #------Building Rest Api header with authorization token------#

    $authHeader = @{
        'Content-Type'='application/json'
        'Authorization'= ("Bearer " + $token.access_token)
        }
    $uri = "https://graph.microsoft.com/" + $APIVersion + "/" + $Type 
    $objects = Invoke-RestMethod -Uri $uri -Headers $authHeader -Method POST -Body $ObjectInJson
    return $objects
}

Function UpdateGraphObjectByType
  {
    param
        (
        [Parameter(Mandatory=$true)]
        $Token,
        [Parameter(Mandatory=$true)]
        $Type,
        [Parameter(Mandatory=$true)]
        $OID,
        [Parameter(Mandatory=$true)]
        $ObjectInJson,
        $APIVersion = "beta"
       )
    #------Building Rest Api header with authorization token------#

    $authHeader = @{
        'Content-Type'='application/json'
        'Authorization'= ("Bearer " + $token.access_token)
        }
    $uri = "https://graph.microsoft.com/" + $APIVersion + "/" + $Type + "/" + $OID 
    $objects = Invoke-RestMethod -Uri $uri -Headers $authHeader -Method Patch -Body $ObjectInJson
    return $objects
}

Function AddGraphUserToAdminGroup
  {
    param
        (
        [Parameter(Mandatory=$true)]
        $Token,
        [Parameter(Mandatory=$true)]
        $AdminUnitID,
        [Parameter(Mandatory=$true)]
        $UserID
       )
    #------Building Rest Api header with authorization token------#

    $authHeader = @{
        'Content-Type'='application/json'
        'Authorization'= ("Bearer " + $token.access_token)
        }

    $uri = "https://graph.microsoft.com/beta/administrativeUnits/" + $AdminUnitID + '/members/$ref'

    $body = @{'@odata.id'="https://graph.microsoft.com/beta/users/" + $UserID}
     
    Invoke-RestMethod -Uri $uri –Headers $authHeader –Method Post -Body ($body | ConvertTo-Json)
   }


Function AddGraphUserToAdminGroupRole
  {
    param
        (
        [Parameter(Mandatory=$true)]
        $Token,
        [Parameter(Mandatory=$true)]
        $AdminUnitID,
        [Parameter(Mandatory=$true)]
        $UserID,
        [Parameter(Mandatory=$true)]
        $Role
       )
    #------Building Rest Api header with authorization token------#

    $authHeader = @{
        'Content-Type'='application/json'
        'Authorization'= ("Bearer " + $token.access_token)
        }

    $uri = "https://graph.microsoft.com/beta/administrativeUnits/" + $AdminUnitID + '/scopedRoleMembers'
    $body = @{'roleId'= $role
               'roleMemberInfo'= @{'id'=$UserID}
                } 

                $body | ConvertTo-Json
    Invoke-RestMethod -Uri $uri –Headers $authHeader –Method Post -Body ($body | ConvertTo-Json)
   }
   
Function New-GraphUser
  {
    param
        (
        [Parameter(Mandatory=$true)]
        $authToken,
        [Parameter(Mandatory=$true)]
        $displayName,
        [Parameter(Mandatory=$true)]
        $mailNickName,
        [Parameter(Mandatory=$true)]
        $userPrincipalName,
        [Parameter(Mandatory=$true)]
        $password,
        $accountEnabled = $true,
        $forceChangePasswordNextSignIn = $true,
        $city,
        $companyName,
        $country,
        $department,
        $employeeId,
        $employeeHireDate,
        $employeeOrgData,
        $employeeType,
        $ageGroup,
        $businessPhones,
        $faxNumber,
        $givenName,
        $jobTitle,
        $mail,
        $mobilePhone,
        $officeLocation,
        $postalCode,
        $preferredDataLocation,
        $preferredLanguage,
        $proxyAddresses,
        $state,
        $streetAddress,
        $surname,
        $usageLocation,
        $extensionAttribute1,
        $extensionAttribute2,
        $extensionAttribute3,
        $extensionAttribute4,
        $extensionAttribute5,
        $extensionAttribute6,
        $extensionAttribute7,
        $extensionAttribute8,
        $extensionAttribute9,
        $extensionAttribute10,
        $extensionAttribute11,
        $extensionAttribute12,
        $extensionAttribute13,
        $extensionAttribute14,
        $extensionAttribute15   
       )
    
    $userConfig = @{'accountEnabled'= $accountEnabled;
            'displayName' = $displayName;
            'mailNickname' = $mailNickName;
            'userPrincipalName' = $userPrincipalName;
            'passwordProfile'  = @{'forceChangePasswordNextSignIn' = $forceChangePasswordNextSignIn;
                                  'password' = $password;
                                  }
           }
           
    if ( $city) { $userConfig.Add('city',$city) }
    if ( $companyName) { $userConfig.Add('companyName',$companyName)}
    if ( $country) { $userConfig.Add('country',$country)}
    if ( $department) { $userConfig.Add('department',$department)}
    if ( $employeeId) { $userConfig.Add('employeeId',$employeeId)}
    if ( $employeeHireDate) { $userConfig.Add('employeeHireDate',$employeeHireDate)}
    if ( $employeeOrgData) { $userConfig.Add('employeeOrgData',$employeeOrgData)}
    if ( $employeeType) { $userConfig.Add('employeeType',$employeeType)}
    if ( $ageGroup) { $userConfig.Add('ageGroup',$ageGroup)}
    if ( $businessPhones) { $userConfig.Add('businessPhones',$businessPhones)}
    if ( $faxNumber) { $userConfig.Add('faxNumber',$faxNumber)}
    if ( $givenName) { $userConfig.Add('givenName',$givenName)}
    if ( $jobTitle) { $userConfig.Add('jobTitle',$jobTitle)}
    if ( $mail) { $userConfig.Add('mail',$mail)}
    if ( $mobilePhone) { $userConfig.Add('mobilePhone',$mobilePhone)}
    if ( $officeLocation) { $userConfig.Add('officeLocation',$officeLocation)}
    if ( $postalCode) { $userConfig.Add('postalCode',$postalCode)}
    if ( $preferredDataLocation) { $userConfig.Add('preferredDataLocation',$preferredDataLocation)}
    if ( $preferredLanguage) { $userConfig.Add('preferredLanguage',$preferredLanguage)}
    if ( $proxyAddresses) { $userConfig.Add('proxyAddresses',$proxyAddresses)}
    if ( $state) { $userConfig.Add('state',$state)}
    if ( $streetAddress) { $userConfig.Add('streetAddress',$streetAddress)}
    if ( $surname) { $userConfig.Add('surname',$surname)}
    if ( $usageLocation) { $userConfig.Add('usageLocation',$usageLocation)}
  if ( $extensionAttribute1 -or $extensionAttribute2 -or $extensionAttribute3 -or $extensionAttribute4 -or
        $extensionAttribute5 -or $extensionAttribute6 -or $extensionAttribute7 -or $extensionAttribute8 -or  
        $extensionAttribute9 -or $extensionAttribute10 -or  $extensionAttribute11 -or $extensionAttribute12 -or 
        $extensionAttribute13 -or $extensionAttribute14 -or $extensionAttribute15 )
    {
        $onPremisesExtensionAttributes = @{};

        if ( $extensionAttribute1) { $onPremisesExtensionAttributes.Add('extensionAttribute1',$extensionAttribute1)}
        if ( $extensionAttribute2) { $onPremisesExtensionAttributes.Add('extensionAttribute2',$extensionAttribute2)}
        if ( $extensionAttribute3) { $onPremisesExtensionAttributes.Add('extensionAttribute3',$extensionAttribute3)}
        if ( $extensionAttribute4) { $onPremisesExtensionAttributes.Add('extensionAttribute4',$extensionAttribute4)}
        if ( $extensionAttribute5) { $onPremisesExtensionAttributes.Add('extensionAttribute5',$extensionAttribute5)}
        if ( $extensionAttribute6) { $onPremisesExtensionAttributes.Add('extensionAttribute6',$extensionAttribute6)}
        if ( $extensionAttribute7) { $onPremisesExtensionAttributes.Add('extensionAttribute7',$extensionAttribute7)}
        if ( $extensionAttribute8) { $onPremisesExtensionAttributes.Add('extensionAttribute8',$extensionAttribute8)}
        if ( $extensionAttribute9) { $onPremisesExtensionAttributes.Add('extensionAttribute9',$extensionAttribute9)}
        if ( $extensionAttribute10) { $onPremisesExtensionAttributes.Add('extensionAttribute10',$extensionAttribute10)}
        if ( $extensionAttribute11) { $onPremisesExtensionAttributes.Add('extensionAttribute11',$extensionAttribute11)}
        if ( $extensionAttribute12) { $onPremisesExtensionAttributes.Add('extensionAttribute12',$extensionAttribute12)}
        if ( $extensionAttribute13) { $onPremisesExtensionAttributes.Add('extensionAttribute13',$extensionAttribute13)}
        if ( $extensionAttribute14) { $onPremisesExtensionAttributes.Add('extensionAttribute14',$extensionAttribute14)}
        if ( $extensionAttribute15) { $onPremisesExtensionAttributes.Add('extensionAttribute15',$extensionAttribute15)}
         $userConfig.Add('onPremisesExtensionAttributes',$onPremisesExtensionAttributes)
       }   
    if ( $extensionAttribute15) { $userConfig.Add('extensionAttribute15',$extensionAttribute15)}   
    return (NewGraphObjectByType -Type 'users' -Token $token -ObjectInJson ($userConfig | ConvertTo-Json))
}

Function Update-GraphUser
  {
    param
        (
        [Parameter(Mandatory=$true)]
        $authToken,
        [Parameter(Mandatory=$true)]
        $userPrincipalName,
        $displayName,
        $mailNickName,
        $password,
        $accountEnabled = $true,
        $forceChangePasswordNextSignIn = $true,
        $city,
        $companyName,
        $country,
        $department,
        $employeeId,
        $employeeHireDate,
        $employeeOrgData,
        $employeeType,
        $ageGroup,
        $businessPhones,
        $faxNumber,
        $givenName,
        $jobTitle,
        $mail,
        $mobilePhone,
        $officeLocation,
        $postalCode,
        $preferredDataLocation,
        $preferredLanguage,
        $proxyAddresses,
        $state,
        $streetAddress,
        $surname,
        $usageLocation,
        $extensionAttribute1,
        $extensionAttribute2,
        $extensionAttribute3,
        $extensionAttribute4,
        $extensionAttribute5,
        $extensionAttribute6,
        $extensionAttribute7,
        $extensionAttribute8,
        $extensionAttribute9,
        $extensionAttribute10,
        $extensionAttribute11,
        $extensionAttribute12,
        $extensionAttribute13,
        $extensionAttribute14,
        $extensionAttribute15       
       )
    
    $userConfig = @{}
    if ( $displayName) { $userConfig.Add('displayName',$displayName) }
    if ( $mailNickName) { $userConfig.Add('mailNickName',$mailNickName) }
    if ( $accountEnabled) { $userConfig.Add('accountEnabled',$accountEnabled) }
    if ( $password -or  $forceChangePasswordNextSignIn)
    {
        $passwordProfile  = @{}
        if ( $forceChangePasswordNextSignIn) { $passwordProfile.Add('forceChangePasswordNextSignIn',$forceChangePasswordNextSignIn) }
        if ( $password) { $passwordProfile.Add('password',$password) }
        $userConfig.Add('passwordProfile',$passwordProfile)                                 
    }
    if ( $city) { $userConfig.Add('city',$city) }
    if ( $companyName) { $userConfig.Add('companyName',$companyName)}
    if ( $country) { $userConfig.Add('country',$country)}
    if ( $department) { $userConfig.Add('department',$department)}
    if ( $employeeId) { $userConfig.Add('employeeId',$employeeId)}
    if ( $employeeHireDate) { $userConfig.Add('employeeHireDate',$employeeHireDate)}
    if ( $employeeOrgData) { $userConfig.Add('employeeOrgData',$employeeOrgData)}
    if ( $employeeType) { $userConfig.Add('employeeType',$employeeType)}
    if ( $ageGroup) { $userConfig.Add('ageGroup',$ageGroup)}
    if ( $businessPhones) { $userConfig.Add('businessPhones',$businessPhones)}
    if ( $faxNumber) { $userConfig.Add('faxNumber',$faxNumber)}
    if ( $givenName) { $userConfig.Add('givenName',$givenName)}
    if ( $jobTitle) { $userConfig.Add('jobTitle',$jobTitle)}
    if ( $mail) { $userConfig.Add('mail',$mail)}
    if ( $mobilePhone) { $userConfig.Add('mobilePhone',$mobilePhone)}
    if ( $officeLocation) { $userConfig.Add('officeLocation',$officeLocation)}
    if ( $postalCode) { $userConfig.Add('postalCode',$postalCode)}
    if ( $preferredDataLocation) { $userConfig.Add('preferredDataLocation',$preferredDataLocation)}
    if ( $preferredLanguage) { $userConfig.Add('preferredLanguage',$preferredLanguage)}
    if ( $proxyAddresses) { $userConfig.Add('proxyAddresses',$proxyAddresses)}
    if ( $state) { $userConfig.Add('state',$state)}
    if ( $streetAddress) { $userConfig.Add('streetAddress',$streetAddress)}
    if ( $surname) { $userConfig.Add('surname',$surname)}
    if ( $usageLocation) { $userConfig.Add('usageLocation',$usageLocation)}
    if ( $extensionAttribute1 -or $extensionAttribute2 -or $extensionAttribute3 -or $extensionAttribute4 -or
        $extensionAttribute5 -or $extensionAttribute6 -or $extensionAttribute7 -or $extensionAttribute8 -or  
        $extensionAttribute9 -or $extensionAttribute10 -or  $extensionAttribute11 -or $extensionAttribute12 -or 
        $extensionAttribute13 -or $extensionAttribute14 -or $extensionAttribute15 )
    {
        $onPremisesExtensionAttributes = @{};

        if ( $extensionAttribute1) { $onPremisesExtensionAttributes.Add('extensionAttribute1',$extensionAttribute1)}
        if ( $extensionAttribute2) { $onPremisesExtensionAttributes.Add('extensionAttribute2',$extensionAttribute2)}
        if ( $extensionAttribute3) { $onPremisesExtensionAttributes.Add('extensionAttribute3',$extensionAttribute3)}
        if ( $extensionAttribute4) { $onPremisesExtensionAttributes.Add('extensionAttribute4',$extensionAttribute4)}
        if ( $extensionAttribute5) { $onPremisesExtensionAttributes.Add('extensionAttribute5',$extensionAttribute5)}
        if ( $extensionAttribute6) { $onPremisesExtensionAttributes.Add('extensionAttribute6',$extensionAttribute6)}
        if ( $extensionAttribute7) { $onPremisesExtensionAttributes.Add('extensionAttribute7',$extensionAttribute7)}
        if ( $extensionAttribute8) { $onPremisesExtensionAttributes.Add('extensionAttribute8',$extensionAttribute8)}
        if ( $extensionAttribute9) { $onPremisesExtensionAttributes.Add('extensionAttribute9',$extensionAttribute9)}
        if ( $extensionAttribute10) { $onPremisesExtensionAttributes.Add('extensionAttribute10',$extensionAttribute10)}
        if ( $extensionAttribute11) { $onPremisesExtensionAttributes.Add('extensionAttribute11',$extensionAttribute11)}
        if ( $extensionAttribute12) { $onPremisesExtensionAttributes.Add('extensionAttribute12',$extensionAttribute12)}
        if ( $extensionAttribute13) { $onPremisesExtensionAttributes.Add('extensionAttribute13',$extensionAttribute13)}
        if ( $extensionAttribute14) { $onPremisesExtensionAttributes.Add('extensionAttribute14',$extensionAttribute14)}
        if ( $extensionAttribute15) { $onPremisesExtensionAttributes.Add('extensionAttribute15',$extensionAttribute15)}
         $userConfig.Add('onPremisesExtensionAttributes',$onPremisesExtensionAttributes)
       }   
    return (UpdateGraphObjectByType -Type 'users' -Token $token  -OID $userPrincipalName -ObjectInJson ($userConfig | ConvertTo-Json))
}

Function Remove-GraphUser
  {
    param
        (
        [Parameter(Mandatory=$true)]
        $authToken,
        [Parameter(Mandatory=$true)]
        $userPrincipalName
       )
 return (DeleteGraphObjectByType -Type 'users' -Token $token  -OID $userPrincipalName )
 }


Function Get-GraphUser
  {
    param
        (
        [Parameter(Mandatory=$true)]
        $authToken,
        [Parameter(Mandatory=$true)]
        $userPrincipalName
       )
 return (GetGraphObjectByType -Type 'users' -Token $token  -OID $userPrincipalName )
 }

<# 

Sample calls:

$token = Get-OAuthTokenByClientSecret -tenant $tenant  -resource "https://graph.microsoft.com/" -appID $AppID -clientSecret $clientSecret
 
$token = Get-OAuthTokenByUser -tenant $tenant  -resource $msgraph.resource -appID $msgraph.appId -userName "admin@ldej.onmicrosoft.com" -password "" `
                -scope "Group.ReadWrite.All User.ReadWrite.All openid profile offline_access"

$devicecode = Start-OAuthTokenByDeviceLogin -tenant $tenant -resource $msgraph.resource -appID  $msgraph.appId  `
 -scope "Group.ReadWrite.All User.ReadWrite.All offline_access profile openid"
$token = Get-OAuthTokenByDeviceLogin -tenant $tenant -resource $msgraph.resource -appID $msgraph.appId -devicecode $devicecode


$adminunits = GetObjectSByType -Token $token  -Type "administrativeunits"
$users = GetObjectSByType -Token $token  -Type "users"
$groups = GetObjectSByType -Token $token  -Type "groups"


$RetVal = DeleteObjectByType -Token $token  -Type "administrativeunits" -ID "f7f08448-c480-4cc0-8cc3-7503c2fbe96c"

AddUserToAdminGroup -Token $token -AdminUnitID "1b5eec54-caa0-4269-ae69-c5d5b583a2e0" -UserID "8bfd4224-8956-4691-a225-bc5e2fedf952"

AddUserToAdminGroup -Token $token -AdminUnitID "1b5eec54-caa0-4269-ae69-c5d5b583a2e0" -UserID "DonaldFlowers@ldeg.onmicrosoft.com"

AddUserToAdminGroupRole -Token $token -AdminUnitID "1b5eec54-caa0-4269-ae69-c5d5b583a2e0" -UserID $users[8].id -Role "983dcdbe-ad06-483d-a212-b15cf3c15b46"


#>




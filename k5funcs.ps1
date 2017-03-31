# Import K5 json definitions function
. $PSScriptRoot/k5json.ps1

# Only TLS 1.2 allowed, Powershell needs to be forced as it won't negotiate!
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12

Function Get-K5Token
{
    [cmdletbinding(DefaultParameterSetName=’Scoped’)]
    param
    (
        # Region parameter - default to uk-1
        [Parameter()][ValidateSet('de-1','fi-1','uk-1')][string]$region = "uk-1",
        # Contract parameter - default to appropriate free tier contract for the specified region
        [string]$contract = $(
                                switch ($region)
                                {
                                    "uk-1" {$((Get-K5Vars)["k5_uk_contract"])}
                                    "fi-1" {$((Get-K5Vars)["k5_fi_contract"])}
                                    "de-1" {$((Get-K5Vars)["k5_de_contract"])}
                                }
                            ),
        # User parameter - default to required user
        [string]$user = $((Get-K5Vars)["k5user"]),
        # Password parameter - default to required user's password
        [string]$password = $((Get-K5Vars)["k5pword"]),
        # Project name parameter - default to required project
        [Parameter(ParameterSetName="Scoped")][string]$projectname = $((Get-K5Vars)["k5project"]),
        # Global token scope parameter - default to false
        [Parameter(ParameterSetName="Global")][switch]$global = $false,
        # Unscoped token parameter - default to false
        [Parameter(ParameterSetName="Unscoped")][switch]$unscoped = $false,
        # Use proxy switch parameter
        [switch]$useProxy
    )

    # URL for the secified region's identity service, future calls will use the endpoint returned when retrieving the token
    $regional_identity_url = "https://identity.$region.cloud.global.fujitsu.com/v3/auth/tokens"
    # Global identity service URL
    $global_identity_url = "https://auth-api.jp-east-1.paas.cloud.global.fujitsu.com/API/paas/auth/token"
    # Default header for REST API calls, accept JSON returns
    $headers = @{"Accept" = "application/json"}
    # Define the token object for the function return
    $token = "" | select "token","projectid","userid","domainid","expiry","endpoints","projects"

    # Check if we need to return a globally scoped token
    if ($global)
    {
        try
        {
            # Retrieve the JSON for a global token request
            $json = get-k5json token_global
            # Make the API call to request a token from the global identity endpoint
            $detail = Invoke-WebRequest2 -Uri "$global_identity_url" -Method POST -headers $headers -Body $json -ContentType "application/json" -UseProxy $useProxy
            # Extract the payload from the API return and convert from JSON to a PS object
            $return = $detail.Content | ConvertFrom-json
            # Set the token property stored in the headers of the API return
            $token.token = @{"Token" = $detail.headers["X-Access-Token"]}
            # Set the token expiry time
            $token.expiry = ([xml.xmlconvert]::ToDateTime($return.token.expires_at)).DateTime
        }
        catch
        {
            # If something went wrong, display an error and exit
            Display-Error -error "Global token retrieval failed...`n$($_.Exception.Message)"
        }
        # Exit and return the token object
        return $token
    }
    
    # Retrieve unscoped token   
    try
    {
        # Retrieve the JSON for an unscoped token request
        $json = get-k5json token_unscoped
        # Make the API call to request a token from the regional identity endpoint
        $detail = Invoke-WebRequest2 -Uri "$regional_identity_url" -Method POST -headers $headers -Body $json -ContentType "application/json" -UseProxy $useProxy
        # Extract the payload from the API return and convert from JSON to a PS object
        $return = $detail.Content | ConvertFrom-json
    }
    catch
    {
        # If something went wrong, display an error and exit
        Display-Error -error "Unscoped token retrieval failed..." -errorObj $_
    }
    # Set the token property stored in the headers of the API return
    $token.token = @{"X-Auth-Token" = $detail.headers["X-Subject-Token"]}
    # Set the domain id property
    $token.domainid = $return.token.project.domain.id
    # Set the user id property
    $token.userid = $return.token.user.id
    # Set the project id property
    $token.projectid = $return.token.project.id
    # Retrieve the endpoints from the API return and set the endpoints property accordingly
    $token.endpoints = Process-Endpoints $return.token.catalog.endpoints
    # Set the token expiry property
    $token.expiry = ([xml.xmlconvert]::ToDateTime($return.token.expires_at)).DateTime
    # Add the token to the headers object for authenticating the following API calls 
    $headers += $token.token
    # Enumerate the projects available to this user
    try
    {
        # Make the API call to retrieve the list of projects accessible to this user from the identity endpoint
        $detail = Invoke-WebRequest2 -Uri "$($token.endpoints["identityv3"])/users/$($token.userid)/projects" -Method GET -headers $headers -ContentType "application/json" -UseProxy $useProxy
        # Extract the payload from the API return and convert from JSON to a PS object
        $return = $detail.Content | ConvertFrom-Json
    }
    catch
    {
        # If something went wrong, display an error and exit
        Display-Error -error "Project enumeration failed..." -errorObj $_
    }
    # Set the projects property using the projects returned from the API call        
    $token.projects = $return.projects
    # Do we require a scoped token?
    if (-not $unscoped)
    {
        # Scoped token required, find the project id of the project we need to scope to
        $token.projectid = ($return.projects | where name -eq $projectname).id
        # If we can't find a project id for the specified project name display an error and exit
        if ( -not $token.projectid) { Display-Error -error "Project $projectname not found."}
        # Reset the headers
        $headers = @{"Accept" = "application/json"}
        try
        {
            # Set the projectid propert expected in the JSON skeleton
            $projectid = $token.projectid
            # Retrieve the JSON for an scoped token request
            $json = get-k5json token_scoped
            # Make the API call to request a token from the identity endpoint
            $detail = Invoke-WebRequest2 -Uri "$($token.endpoints["identityv3"])/auth/tokens" -Method POST -headers $headers -Body $json -ContentType "application/json" -UseProxy $useProxy
            # Extract the payload from the API return and convert from JSON to a PS object
            $return = $detail.Content | ConvertFrom-json
        }
        catch
        {
            # If something went wrong, display an error and exit
            Display-Error -error "Scoped token retrieval failed..." -errorObj $_
        }
        # Scoped token, retrieve the endpoints from the API return and set the endpoints property accordingly
        $token.endpoints = Process-Endpoints $return.token.catalog.endpoints
        # Set the token property
        $token.token = @{"X-Auth-Token" = $detail.headers["X-Subject-Token"]}
        # Set the token expiry property
        $token.expiry = ([xml.xmlconvert]::ToDateTime($return.token.expires_at)).DateTime
    }
    # Return the token object
    return $token
}

Function Process-Endpoints
{
    param
    (
        [array]$endpointlist
    )
    $endpoints = @{}
    foreach ($endpoint in $endpointlist)
    {
        $endpoints.Add($endpoint.name,$endpoint.url)
    }
    return $endpoints
}

Function Get-K5Vars
{
    $k5vars = @{} 
    $vars = Import-Csv $PSScriptRoot\k5env.csv
    foreach ($var in $vars)
    {
        $k5vars.Add($var.name,$var.value)
    }
    return $k5vars
}

Function Display-Error
{
    param
    (
        [string]$error,
        [pscustomobject]$errorObj
    )
    Write-Host "Error: $error" -ForegroundColor Red
    if ($errorObj)
    {
        Write-Host "Exception: $($errorObj.Exception.Message)" -ForegroundColor Red
        Write-Host "$($errorObj.InvocationInfo.PositionMessage)" -ForegroundColor Red
    }
    break
}

# Mirror Invoke-WebRequest function to allow use (or not) of proxy within the K5 functions without hardcoding
Function Invoke-WebRequest2
{
    param
    (
        [string]$Uri,
        [string]$Method,
        [hashtable]$Headers,
        [string]$Body,
        [string]$ContentType,
        [pscustomobject]$token,
        [bool]$UseProxy=$false
    )
    # If a token was passed in check it's expiry and inform user if it's expired
    if (($token) -and ($token.expiry -le (get-date))) {Display-Error "Token has expired, please obtain another..."}
    # Was the -UseProxy switch specified?
    if ($UseProxy)
    {
        # We're using a proxy, was there a body passed?
        if ($Body)
        {
            # Invoke web request using proxy including body
            $return = Invoke-WebRequest -Uri $Uri -Method $Method -headers $Headers -Body $Body -ContentType $ContentType -Proxy $((Get-K5Vars)["proxyURL"]) -ProxyUseDefaultCredentials
        } else {
            # Invoke web request using proxy without body
            $return = Invoke-WebRequest -Uri $Uri -Method $Method -headers $Headers -ContentType $ContentType -Proxy $((Get-K5Vars)["proxyURL"]) -ProxyUseDefaultCredentials
        }
    } else {
    # No proxy required, was there a body passed?
    if ($Body)
        {
            # Invoke web request without proxy including body
            $return = Invoke-WebRequest -Uri $Uri -Method $Method -headers $Headers -Body $Body -ContentType $ContentType
        } else {
            # Invoke web request without proxy and without body
            $return = Invoke-WebRequest -Uri $Uri -Method $Method -headers $Headers -ContentType $ContentType
        }
    }
    # Return the web request return
    return $return
}

Function Get-K5UserGroups
{
    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [switch]$useProxy
    )
    if (-not $token){break}
    try
    {
        $headers = @{"Accept" = "application/json"}
        $headers += $token.token
        $detail = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["identityv3"])/users/?domain_id=$($token.domainid)" -Method GET -headers $headers -ContentType "application/json" -UseProxy $useProxy
        $users = ($detail.Content | ConvertFrom-Json).users
        $usergroups = @()
        foreach ($user in $users)
        {
            $detail = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["identityv3"])/users/$($user.id)/groups" -Method GET -headers $headers -ContentType "application/json" -UseProxy $useProxy
            $return = $detail.Content | ConvertFrom-Json
            foreach ($group in $return.groups)
            {
                $usergroup = "" | select "Username","Group","Description","id"
                $usergroup.Username = $user.name
                $usergroup.Group = $group.name
                $usergroup.Description = $group.description
                $usergroup.id = $group.id
                $usergroups += $usergroup
            }
        }
    }
    catch
    {
        Display-Error -error "Get-K5UserGroups failed..." -errorObj $_
    }
    return $usergroups
}

Function Get-K5Resources
{
    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$type = $(Display-Error -error "Please specify a resource type using the -type parameter"),
        [string]$name,
        [switch]$detailed,
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $type)) {break}
    $type_nw    = "routers","networks","subnets","ports","security-groups","security-group-rules","floatingips","network_connectors","network_connector_endpoints"
    $type_fw    = "firewalls","firewall_rules","firewall_policies"
    $type_comp  = "servers","images","flavors","os-keypairs"
    $type_block = "volumes","types","snapshots"
    $type_obj   = "containers"
    $type_user  = "users"
    $type_stack = "stacks"
    $validtypes = ((Get-Variable -name type_*).Value | sort) -join ", " 
    switch ($type)
    {
       {$_ -in $type_nw}    {$endpoint = $token.endpoints["networking"] + "/v2.0/" + $type}
       {$_ -in $type_fw}    {$endpoint = $token.endpoints["networking"] + "/v2.0/fw/" + $type}
       {$_ -in $type_comp}  {$endpoint = $token.endpoints["compute"] +"/" + $type}
       {$_ -in $type_block} {$endpoint = $token.endpoints["blockstoragev2"] +"/" + $type}
       {$_ -in $type_obj}   {$endpoint = $token.endpoints["objectstorage"] + "/?format=json"}
       {$_ -in $type_user}  {$endpoint = $token.endpoints["identityv3"] + "/users/?domain_id=" + $token.domainid}
       {$_ -in $type_stack} {$endpoint = $token.endpoints["orchestration"] +"/stacks"}
       default              {Display-Error -error "Unknown type 'type' - acceptable values are $validtypes"}
    }
    if (-not $endpoint){break}
    try
    {
        $detail = (Invoke-WebRequest2 -token $token -Uri "$endpoint" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy).content | ConvertFrom-Json
        if ($detail)
        {
            if ($type -in $obj)
            {
                if ($name) {$detail = $detail  | where name -eq $name}
                if (-not $detail) { Display-Error -error "Resource named: $name of type: $type not found"}
                if ($detailed)
                {
                    $return = @()
                    foreach ($container in $detail)
                    {
                        $detail2 = Invoke-WebRequest2 -token $token -Uri "$($endpoint.replace('/?format=json',''))/$($container.name)?format=json" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy | ConvertFrom-Json
                        foreach ($object in $detail2)
                        {
                            $object | Add-Member -MemberType NoteProperty -Name "Container" -Value $container.name
                            $return += $object
                        }
                        
                    }
                    
                } else {
                    $return = $detail
                }
                return $return
            } else {
                while (($detail | gm -MemberType NoteProperty).count -in 1..2)
                {
                    $detail = $detail.$(($detail | gm)[-1].Name)
                }
                if ($detail.stack_name -ne $null){$detail | Add-Member -MemberType AliasProperty -Name name -Value stack_name}
                if ($name) {$detail = $detail  | where name -eq $name}
                if (-not $detail) { Display-Error -error "Resource named '$name' of type '$type' not found"}
                if ($detailed)
                {
                    if ((($detail.links -ne $null) -or ($detail.id -eq $null)) -and ( $type -ne $user))
                    {
                        $return = @()
                        if ($detail.links -ne $null){$ids = $detail.id} else {$ids = $detail.name}
                        foreach ($id in $ids)
                        {
                            $return += (Invoke-WebRequest2 -token $token -Uri "$endpoint/$id" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy).content | ConvertFrom-Json
                        }
                        $return = $return.$(($return | gm)[-1].Name)
                    } else {
                        $return = $detail
                    }
                } else {
                    $return = $detail | select name,id
                }
            }
        }
    }
    catch
    {
        Display-Error -error "Get-K5Resources failed..." -errorObj $_
    }
    return $return
}


Function Get-K5VNCConsole
{
    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$servername = $(Display-Error -error "Please specify a server name using the -servername parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $servername)) {break}
    try
    {
        $return = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["compute"])/servers" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy
        $serverid = (($return.Content | ConvertFrom-Json).servers | where name -eq $servername).id
        if (-not $serverid)
        {
            Display-Error -error "Get-K5VNCConsole - Server $servername not found."
        }
        $json = Get-K5JSON vnc_console
        $return = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["compute"])/servers/$serverid/action" -Method POST -headers $token.token -Body $json -ContentType "application/json" -UseProxy $useProxy
        $url = ($return.content | ConvertFrom-Json).console.url
    }
    catch
    {
        Display-Error -error "Get-K5VNCConsole failed..." -errorObj $_
    }
    return $url
}

Function Get-K5WindowsPassword
{
    param
    (
        [pscustomobject]$token = $(Display-Error -error "Please supply a token using the -token parameter"),
        [string]$servername = $(Display-Error -error "Please specify a server name using the -servername parameter"),
        [string]$key = $(Display-Error -error "Please specify the path to a private key file using the -key parameter"),
        [switch]$UseProxy
    )
    if ((-not $token) -or (-not $servername) -or (-not $key)) {break}
    try
    {
        $return = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["compute"])/servers" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy
        $serverid = (($return.Content | ConvertFrom-Json).servers | where name -eq $servername).id
        if (-not $serverid)
        {
            Display-Error -error "Server $servername not found."
        }
        $return = Invoke-WebRequest2 -token $token -Uri "$($token.endpoints["compute"])/servers/$serverid/os-server-password" -Method GET -headers $token.token -ContentType "application/json" -UseProxy $useProxy
        $password = ($return.Content | ConvertFrom-Json).password
        $password | & cmd /c "$OpenSSLPath base64 -d -A | $((Get-K5Vars)["OpenSSLPath"]) rsautl -decrypt -inkey $key"
    }
    catch
    {
        Display-Error -error "Get-K5WindowsPassword failed..." -errorObj $_
    }
}


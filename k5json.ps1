function Get-K5JSON
{
    param ([string]$k5json)

$token_global = @"
{
  "auth": {
    "identity": {
      "password": {
        "user": {
          "contract_number": '$contract',
          "name": '$user',
          "password": '$password'
        }
      }
    }
  }
}
"@

$token_unscoped = @"
{
  "auth": {
    "identity": {
      "methods": [
        "password"
      ],
      "password": {
        "user": {
          "domain": {
            "name": '$contract'
          },
          "name": '$user',
          "password": '$password'
        }
      }
    }
  }
}
"@

$token_scoped = @"
{
  "auth": {
    "identity": {
      "methods": [
        "password"
      ],
      "password": {
        "user": {
          "domain": {
            "name": '$contract'
          },
          "name": '$user',
          "password": '$password'
        }
      }
    },
    "scope": {
      "project": {
        "id": '$projectid'
      }
    }
  }
}
"@

$network = @"
{
  "network": {
    "name": '$name',
    "admin_state_up": '$admin_state_up',
    "availability_zone": '$availability_zone'
  }
}
"@

$subnet = @"
{
  "subnet": {
    "name": '$name',
    "network_id": '$network_id',
    "ip_version": 4,
    "cidr": '$cidr',
    "availability_zone": '$availability_zone'
  }
}
"@

$network_connector = @()
 $network_connector += @"
{
  "network_connector": {
    "name": '$name'
  }
}
"@
 $network_connector += @"
{
  "network_connector": {
    "blah": '$name'
  }
}
"@

$vnc_console = @"
{
  "os-getVNCConsole": {
    "type": "novnc"
  }
}
"@

$vpnservice = @"
{
  "vpnservice": {
    "subnet_id": '$subnet_id',
    "router_id": '$router_id',
    "name": '$name',
    "admin_state_up": '$admin_state_up',
    "description": '$description',
    "availability_zone": '$availability_zone'
  }
}
"@

Set-Variable -name json -Value ((Get-Variable -name $k5json).Value -replace "'",'"')
return $json
}
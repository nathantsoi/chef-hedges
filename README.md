# Hedges

Easily white list ports and port ranges from specific hosts

## Defaults

Invalid packets are dropped. Disable with `default['hedges']['drop_invalid'] = false`

Port 22 is opened from anywhere. Disable with `default['hedges']['ssh'] = false`.

Loopback traffic is allowed by the rules `-A INPUT -i lo -j ACCEPT` and `-A output -o lo -j ACCEPT`, set `default['hedges']['allow_loopback'] = false` to remove these rules

All other inbound traffic is denied by the rule `-A INPUT -j DROP`, set `default['hedges']['default_deny'] = false` to allow all traffic

### stateful traffic

Defaults:

```
default['hedges']['allow_stateful'] = {
  incoming: true,
  outgoing: true
}
```

incoming rule: `-A INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT`

outgoing rule: `-A OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT`

# Defining Rules

Set:

```
node['hedges']['rules'] = [
  {
    # defaults to input
    direction: '[INPUT|OUTPUT]',
    # hostname to which we will apply the rule
    hostnames: ['(e.g. someserver-01.mydomain.com)'],
    # specify:
    #  a port range in the format '443:445' to open ports 443 to 445 inclusive
    #  or a list of descrete ports in the format '80,443' to open ports 80 and 443
    #  or a single port in the format '443'
    #  or all ports by leaving the 'ports' value blank or nil
    ports: '(e.g. 443)',
    # defaults to tcp
    proto: '[udp, tcp]'
  },
  ...
]
```

## Examples

Allow `http` traffic from one host (`myserver01.awesomedomain.com`)

```
node['hedges']['rules'] = [
  {
    hosts: ['myserver01.awesomedomain.com'],
    ports: '80'
  }
]
```

All firewall rules can be disabled by setting:

node['hedges']['enabled'] = false

by default, this value is set to true when the recipe is included.



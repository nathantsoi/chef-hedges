include_recipe 'iptables'

ruby_block 'build_firewall_config' do
  block do
    # generated rules
    rules = []

    if node['hedges']['drop_invalid']
      rules << '-I INPUT -m conntrack --ctstate INVALID -j DROP'
    end

    if node['hedges']['ssh']
      rules << '-I INPUT -p tcp --dport 22 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT'
      rules << '-I OUTPUT -p tcp --sport 22 -m conntrack --ctstate ESTABLISHED -j ACCEPT'
    end

    if node['hedges']['allow_loopback']
      rules << '-I INPUT -i lo -j ACCEPT'
      rules << '-I OUTPUT -o lo -j ACCEPT'
    end

    if (stateful = node['hedges']['allow_stateful']||{})
      rules << '-I INPUT -m conntrack --ctstate ESTABLISHED,RELATED -j ACCEPT' if stateful['incoming']
      rules << '-I OUTPUT -m conntrack --ctstate ESTABLISHED -j ACCEPT' if stateful['outgoing']
    end

    (node['hedges']['rules']||[]).each do |rule, i|
      direction = (rule['direction']||'INPUT').strip.upcase
      raise "unknown direction '#{direction}'" unless %w/INPUT OUTPUT/.include?(direction)
      Chef::Resource::RubyBlock.send(:include, Chef::Mixin::ShellOut)

      # aggregate all host string types
      host_strings = []
      (rule['hostnames']||[]).each do |hostname|
        cmd = "host #{hostname} |cut -f4 -d' '|head -n1"
        print "host cmd: '#{cmd}'\n"
        host_ip = shell_out(cmd).stdout.strip
        print "host_ip: '#{host_ip}'\n\n"
        # TODO: notify instead of fail?
        raise "unknown host '#{hostname}'" unless host_ip.strip.length > 0
        host_strings << "-s #{host_ip}"
      end
      (rule['ips']||[]).each do |ip|
        host_strings << "-s #{ip}"
      end
      (rule['ranges']||[]).each do |range|
        host_strings << "-m iprange --src-range #{range}"
      end

      ports =
        if rule['ports'].strip == '' || rule['ports'] == nil
          ''
        # non-continuous port list
        elsif rule['ports'] =~ /,/
          "-m multiport --dports #{rule['ports']}"
        # single port or continuous port range
        else
          "--dport #{rule['ports']}"
        end
      proto = (rule['proto']||'tcp').strip.downcase
      raise "unknown protocol '#{proto}'" unless %w/udp tcp/.include?(proto)

      # buid our list of rules
      host_strings.each do |host_string|
        rules << "-I INPUT -p #{proto} #{host_string} #{ports} -j ACCEPT"
      end
    end

    if node['hedges']['default_deny']
      rules << '-A INPUT -j DROP'
    end

    lines = [ rules ].flatten.join("\n")
    print "iptables generated:\n#{lines}"
    node.override['hedges']['lines'] = lines

  end
  action :run
end

# keep all the rules in one action, so we can easily enable/disable per
#  https://supermarket.chef.io/cookbooks/iptables
iptables_rule 'hedges' do
  lines lazy { node['hedges']['lines'] }
  action node['hedges']['enabled'] ? :enable : :disable
end

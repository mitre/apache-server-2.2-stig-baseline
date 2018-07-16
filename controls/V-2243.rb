DMZ_SUBNET= attribute(
  'dmz_subnet',
  description: 'Subnet of the DMZ',
  default: '62.0.0.0/24'
)

APACHE_CONF_FILE = attribute(
  'apache_conf_file',
  description: 'Path for the apache configuration file',
  default: "/etc/httpd/conf/httpd.conf"
)

control "V-2243" do
  title "A private web server must be located on a separate controlled access
subnet."
  desc  "Private web servers, which host sites that serve controlled access
data, must be protected from outside threats in addition to insider threats.
Insider threat may be accidental or intentional but, in either case, can cause
a disruption in service of the web server. To protect the private web server
from these threats, it must be located on a separate controlled access subnet
and must not be a part of the public DMZ that houses the public web servers. It
also cannot be located inside the enclave as part of the local general
population LAN."
  impact 0.5
  tag "gtitle": "WA070"
  tag "gid": "V-2243"
  tag "rid": "SV-32935r1_rule"
  tag "stig_id": "WA070 A22"
  tag "fix_id": "F-29263r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "System Administrator"
  tag "check": "Verify the site’s network diagram and visually check the web
server, to ensure that the private web server is located on a separate
controlled access subnet and is not a part of the public DMZ that houses the
public web servers. In addition, the private web server needs to be isolated
via a controlled access mechanism from the local general population LAN."
  tag "fix": "Isolate the private web server from the public DMZ and separate
it from the internal general population LAN. "

begin
  describe apache_conf(APACHE_CONF_FILE) do
    its('Listen') { should cmp /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}):(\d{1,5})/ }
  end

  apache_httpd = apache_conf(APACHE_CONF_FILE)
  server_ip = apache_httpd.Listen.join.split(':').first
  server_ip = server_ip.eql?('localhost') ? '127.0.0.1' : server_ip

  describe IPAddr.new(DMZ_SUBNET) === IPAddr.new(server_ip) do
    it { should be false }
  end unless (IPAddr.new(server_ip) rescue nil).nil?


  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil }
    end
  end
end

APACHE_CONF_FILE = attribute(
  'apache_conf_file',
  description: 'define path for the apache configuration file',
  default: "/etc/httpd/conf/httpd.conf"
)

control "V-26326" do
  title "The web server must be configured to listen on a specific IP address
and port."
  desc  "The Apache Listen directive specifies the IP addresses and port
numbers the Apache web server will listen for requests. Rather than be
unrestricted to listen on all IP addresses available to the system, the
specific IP address or addresses intended must be explicitly specified.
Specifically a Listen directive with no IP address specified, or with an IP
address of zero’s should not be used. Having multiple interfaces on web servers
is fairly common, and without explicit Listen directives, the web server is
likely to be listening on an inappropriate IP address / interface that were not
intended for the web server. Single homed system with a single IP addressed are
also required to have an explicit IP address in the Listen directive, in case
additional interfaces are added to the system at a later date."
  impact 0.5
  tag "gtitle": "WA00555"
  tag "gid": "V-26326"
  tag "rid": "SV-33228r1_rule"
  tag "stig_id": "WA00555 A22"
  tag "fix_id": "F-29425r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "Enter the following command:

grep \"Listen\" /usr/local/apache2/conf/httpd.conf

Review the results for the following  directive:   Listen

For any enabled Listen directives ensure they specify both an IP address and
port number.

If the Listen directive is found with only an IP address, or only a port number
specified, this is finding.
If the IP address is all zeros (i.e. 0.0.0.0:80 or [::ffff:0.0.0.0]:80, this is
a finding.
If the Listen directive does not exist, this is a finding."
  tag "fix": "Edit the httpd.conf file and set the \"Listen directive\" to
listen on a specific IP address and port. "

  describe apache_conf(APACHE_CONF_FILE).Listen do
    it { should_not cmp '0.0.0.0' }
    it { should_not cmp '[::ffff:0.0.0.0]' }
    it { should match %r([0-9]+(?:\.[0-9]+){3}|[a-zA-Z]:[0-9]+) }
  end
end

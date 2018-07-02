APACHE_CONF_FILE = attribute(
  'apache_conf_file',
  description: 'define path for the apache configuration file',
  default: "/etc/httpd/conf/httpd.conf"
)

control "V-13725" do
  title "The KeepAlive directive must be enabled."
  desc  "The KeepAlive extension to HTTP/1.0 and the persistent connection
feature of HTTP/1.1 provide long lived HTTP sessions which allow multiple
requests to be sent over the same connection. These requirements are set to
mitigate the effects of several types of denial of service attacks. Although
there is some latitude concerning the settings themselves, the requirements
attempt to provide reasonable limits for the protection of the web server. If
necessary, these limits can be adjusted to accommodate the operational
requirement of a given system."
  impact 0.5
  tag "gtitle": "WA000-WWA022"
  tag "gid": "V-13725"
  tag "rid": "SV-32844r2_rule"
  tag "stig_id": "WA000-WWA022 A22"
  tag "fix_id": "F-13173r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "To view the KeepAlive value enter the following command:

grep \"KeepAlive\" /usr/local/apache2/conf/httpd.conf.

Verify the Value of KeepAlive is set to “On” If not, this is a finding.

NOTE: This vulnerability can be documented locally with the ISSM/ISSO if the
site has operational reasons for not using persistent connections. If the site
has this documentation, this should be marked as Not a Finding.
"
  tag "fix": "Edit the httpd.conf file and set the value of \"KeepAlive\" to
\"On\""

  describe apache_conf(APACHE_CONF_FILE) do
    its('KeepAlive') { should cmp 'On' }
  end
end

APACHE_CONF_FILE = attribute(
  'apache_conf_file',
  description: 'define path for the apache configuration file',
  default: "/etc/httpd/conf/httpd.conf"
)

control "V-13727" do
  title "The httpd.conf StartServers directive must be set properly."
  desc  "These requirements are set to mitigate the effects of several types of
denial of service attacks. Although there is some latitude concerning the
settings themselves, the requirements attempt to provide reasonable limits for
the protection of the web server. If necessary, these limits can be adjusted to
accommodate the operational requirement of a given system.

    From Apache.org: The StartServers directive sets the number of child server
processes created on startup. As the number of processes is dynamically
controlled depending on the load, there is usually little reason to adjust this
parameter.

    The default value differs from MPM to MPM. For worker the default is
StartServers 3. For prefork defaults to 5 and for mpmt_os2 to 2.
  "
  impact 0.5
  tag "gtitle": "WA000-WWA026"
  tag "gid": "V-13727"
  tag "rid": "SV-36645r2_rule"
  tag "stig_id": "WA000-WWA026 A22"
  tag "fix_id": "F-13175r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "Locate the Apache httpd.conf file.  If you cannot locate the
file, you can do a search of the drive to find the location of the file.

Open the httpd.conf file with an editor and search for the following directive:

StartServers

The value needs to be between 5 and 10

If the directive is set improperly, this is a finding.

If the directive does not exist, this is NOT a finding because it will default
to 5.  It is recommended that the directive be explicitly set to prevent
unexpected results if the defaults change with updated software.

NOTE: This vulnerability can be documented locally with the ISSM/ISSO if the
site has operational reasons for the use of increased or decreased value. If
the site has this documentation, this should be marked as Not a Finding.
"
  tag "fix": "Open the httpd.conf file with an editor and search for the
following directive:

StartServer

Set the directive to a value between 5 and 10, add the directive if it does not
exist.

It is recommended that the directive be explicitly set to prevent unexpected
results if the defaults change with updated software.
"

entries = apache_conf(APACHE_CONF_FILE).StartServers
entries.each { |entry|
  describe entry do
    it { should cmp <= 10 }
    it { should cmp >= 5 }
  end
} unless entries.nil?
end

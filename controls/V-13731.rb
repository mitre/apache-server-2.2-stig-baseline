APACHE_CONF_FILE = attribute(
  'apache_conf_file',
  description: 'define path for the apache configuration file',
  default: "/etc/httpd/conf/httpd.conf"
)

control "V-13731" do
  title "All interactive programs must be placed in a designated directory with
appropriate permissions."
  desc  "Directory options directives are directives that can be applied to
further restrict access to file and directories.  The Options directive
controls which server features are available in a particular directory. The
ExecCGI option controls the execution of CGI scripts using mod_cgi.  This needs
to be restricted to only the directory intended for script execution."
  impact 0.5
  tag "gtitle": "WA000-WWA050"
  tag "gid": "V-13731"
  tag "rid": "SV-32763r1_rule"
  tag "stig_id": "WA000-WWA050 A22"
  tag "fix_id": "F-29240r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "Search for the unnecessary CGI programs which may be found in
the directories configured with ScriptAlias, Script or other Script*
directives. Often, CGI directories are named cgi-bin. Also, CGI AddHandler or
SetHandler directives may also be in use for specific handlers such as perl,
python and PHP.

To search the http.conf file for Options enter the following command:

grep \"Options\" /usr/local/apache2/conf/httpd.conf.

If the value for Options is returned with a ExecCGI (no +) this is a finding."
  tag "fix": "Locate any cgi-bin files and directories enabled in the Apache
configuration via Script, ScriptAlias or other Script* directives.

Remove the printenv default CGI in cgi-bin directory if it is installed.

rm $APACHE_PREFIX/cgi-bin/printenv.

Remove the test-cgi file from the cgi-bin directory if it is installed.

rm $APACHE_PREFIX/cgi-bin/test-cgi.

Review and remove any other cgi-bin files which are not needed for business
purposes."

  describe apache_conf(APACHE_CONF_FILE) do
    its('Options') { should_not match /ExecCGI/i }
  end
end

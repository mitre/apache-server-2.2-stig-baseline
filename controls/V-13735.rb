APACHE_CONF_FILE = attribute(
  'apache_conf_file',
  description: 'define path for the apache configuration file',
  default: "/etc/httpd/conf/httpd.conf"
)

APPROVED_OPTIONS = attribute(
  'approved_options',
  description: 'List of approved options settings',
  default: ['-Indexes', 'None']
)

UNAPPROVED_OPTIONS = attribute(
  'unapproved_options',
  description: 'List of unapproved options settings',
  default: ['Indexes']
)

control "V-13735" do
  title "Directory indexing must be disabled on directories not containing
index files."
  desc  "Directory options directives are directives that can be applied to
further restrict access to file and directories.  If a URL which maps to a
directory is requested, and there is no DirectoryIndex (e.g., index.html) in
that directory, then mod_autoindex will return a formatted listing of the
directory which is not acceptable."
  impact 0.5
  tag "gtitle": "WA000-WWA058"
  tag "gid": "V-13735"
  tag "rid": "SV-32755r1_rule"
  tag "stig_id": "WA000-WWA058 A22"
  tag "fix_id": "F-29248r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "To view the Indexes value enter the following command:

grep \"Indexes\" /usr/local/apache2/conf/httpd.conf.

Review all uncommented Options statements for the following value: -Indexes

If the value is found on the Options statement, and it does not have a
preceding ‘-‘, this is a finding.

Notes:
- If the value does NOT exist, this is a finding.
- If all enabled Options statement are set to None this is not a finding.
"
  tag "fix": "Edit the httpd.conf file and add an \"-\" to the Indexes setting,
or set the options directive to None. "

  describe apache_conf(APACHE_CONF_FILE) do
    its('Options') { should be_in APPROVED_OPTIONS }
    its('Options') { should_not be_in UNAPPROVED_OPTIONS }
  end
end

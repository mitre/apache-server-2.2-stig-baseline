APACHE_CONF_FILE = attribute(
  'apache_conf_file',
  description: 'define path for the apache configuration file',
  default: "/etc/httpd/conf/httpd.conf"
)

APPROVED_OPTIONS = attribute(
  'approved_options',
  description: 'List of approved options settings',
  default: ['-FollowSymLinks', 'None']
)

UNAPPROVED_OPTIONS = attribute(
  'unapproved_options',
  description: 'List of unapproved options settings',
  default: ['FollowSymLinks']
)

control "V-13732" do
  title "The \"–FollowSymLinks” setting must be disabled.

"
  desc  "The Options directive configures the web server features that are
available in particular directories. The FollowSymLinks option controls the
ability of the server to follow symbolic links. A symbolic link allows a file
or a directory to be referenced using a symbolic name raising a potential
hazard if symbolic linkage is made to a sensitive area. When web scripts are
executed and symbolic links are allowed, the web user could be allowed to
access locations on the web server that are outside the scope of the web
document root or home directory."
  impact 0.5
  tag "gtitle": "WA000-WWA052"
  tag "gid": "V-13732"
  tag "rid": "SV-40129r1_rule"
  tag "stig_id": "WA000-WWA052 A22"
  tag "fix_id": "F-34186r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "To view the Options value enter the following command:

grep \"Options\" /usr/local/apache2/conf/httpd.conf.

Review all uncommented Options statements for the following value:
-FollowSymLinks

If the value is found with an Options statement, and it does not have a
preceding ‘-‘, this is a finding.

Notes:
- If the value does NOT exist, this is a finding.
- If all enabled Options statement are set to None this is not a finding."
  tag "fix": "Edit the httpd.conf file and set the value of \"FollowSymLinks\"
to \"-FollowSymLinks\"."

  describe apache_conf(APACHE_CONF_FILE) do
    its('Options') { should be_in APPROVED_OPTIONS }
    its('Options') { should_not be_in UNAPPROVED_OPTIONS }
  end
end

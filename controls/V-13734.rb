APACHE_CONF_FILE = attribute(
  'apache_conf_file',
  description: 'define path for the apache configuration file',
  default: "/etc/httpd/conf/httpd.conf"
)

APPROVED_OPTIONS = attribute(
  'approved_options',
  description: 'List of approved options settings',
  default: ['-MultiView', 'None']
)

UNAPPROVED_OPTIONS = attribute(
  'unapproved_options',
  description: 'List of unapproved options settings',
  default: ['MultiView']
)


control "V-13734" do
  title "The MultiViews directive must be disabled."
  desc  "Directory options directives are directives that can be applied to
further restrict access to file and directories. MultiViews is a per-directory
option, meaning it can be set with an Options directive within a $Directory,
$Location or $Files section in httpd.conf, or (if AllowOverride is properly
set) in .htaccess files. The effect of MultiViews is as follows: if the server
receives a request for /some/dir/foo, if /some/dir has MultiViews enabled, and
/some/dir/foo does not exist, then the server reads the directory looking for
files named foo.*, and effectively fakes up a type map which names all those
files, assigning them the same media types and content-encodings it would have
if the client had asked for one of them by name. It then chooses the best match
to the client's requirements."
  impact 0.5
  tag "gtitle": "WA000-WWA056"
  tag "gid": "V-13734"
  tag "rid": "SV-32754r1_rule"
  tag "stig_id": "WA000-WWA056 A22"
  tag "fix_id": "F-29247r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "To view the MultiViews value enter the following command:

grep \"MultiView\" /usr/local/apache2/conf/httpd.conf.

Review all uncommented Options statements for the following value: -MultiViews

If the value is found on the Options statement, and it does not have a
preceding ‘-‘, this is a finding.

Notes:
- If the value does NOT exist, this is a finding.
- If all enabled Options statement are set to None this is not a finding.
"
  tag "fix": "Edit the httpd.conf file and add the \"-\" to the MultiViews
setting, or set the options directive to None.
"

  describe apache_conf(APACHE_CONF_FILE) do
    its('Options') { should be_in APPROVED_OPTIONS }
    its('Options') { should_not be_in UNAPPROVED_OPTIONS }
  end
end

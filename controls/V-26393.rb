control "V-26393" do
  title "The ability to override the access configuration for the OS root
directory must be disabled."
  desc  "The Apache OverRide directive allows for .htaccess files to be used to
override much of the configuration, including authentication, handling of
document types, auto generated indexes, access control, and options. When the
server finds an .htaccess file (as specified by AccessFileName) it needs to
know which directives declared in that file can override earlier access
information. When this directive is set to None, then .htaccess files are
completely ignored. In this case, the server will not even attempt to read
.htaccess files in the file system. When this directive is set to All, then any
directive which has the .htaccess Context is allowed in .htaccess files."
  impact 0.5
  tag "gtitle": "WA00547"
  tag "gid": "V-26393"
  tag "rid": "SV-33232r1_rule"
  tag "stig_id": "WA00547 A22"
  tag "fix_id": "F-29497r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "Enter the following command:

more /usr/local/Apache2.2/conf/httpd.conf.

Review the httpd.conf file and search for the following directive:

Directory

For every root directory entry (i.e. <Directory />) ensure the following entry
exists:

AllowOverride None

If the statement above is not found in the root directory statement, this is a
finding.

If Allow directives are included in the root directory statement, this is a
finding.

If the root directory statement is not listed at all, this is a finding.
"
  tag "fix": "Edit the httpd.conf file and add or set the value of
AllowOverride to \"None\".
"
  
APACHE_CONF_DIR= attribute(
  'apache_conf_dir',
  description: 'location of apache conf directory',
  default: '/etc/httpd/conf'
)
  
  describe command("awk '/<Directory \\/>/,/<\\/Directory>/' #{input('apache_conf_file')}") do
    its('stdout') { should match "AllowOverride None" }
  end
end

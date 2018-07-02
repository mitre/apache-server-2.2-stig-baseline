control "V-26327" do
  title "The URL-path name must be set to the file path name or the directory
path name."
  desc  "The ScriptAlias directive controls which directories the Apache server
\"sees\" as containing scripts.  If the directive uses a URL-path name that is
different than the actual file system path, the potential exists to expose the
script source code."
  impact 0.5
  tag "gtitle": "WA00560"
  tag "gid": "V-26327"
  tag "rid": "SV-33229r1_rule"
  tag "stig_id": "WA00560 A22"
  tag "fix_id": "F-29427r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "Enter the following command:

grep \"ScriptAlias\" /usr/local/apache2/conf/httpd.conf.

If any enabled ScriptAlias directive do not have matching URL-path and
file-path or directory-path entries, this is a finding.
"
  tag "fix": "Edit the httpd.conf file and set the ScriptAlias URL-path and
file-path or directory-path entries."
end


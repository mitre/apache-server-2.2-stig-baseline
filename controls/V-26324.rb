control "V-26324" do
  title "Web server options for the OS root must be disabled."
  desc  "The Apache Options directive allows for specific configuration of
options, including execution of CGI, following symbolic links, server side
includes, and content negotiation. The Options directive for the root OS level
is used to create a default minimal options policy that allows only the minimal
options at the root directory level. Then for specific web sites or portions of
the web site, options may be enabled as needed and appropriate. No options
should be enabled and the value for the Options Directive should be None."
  impact 0.5
  tag "gtitle": "WA00545"
  tag "gid": "V-26324"
  tag "rid": "SV-33213r1_rule"
  tag "stig_id": "WA00545 A22"
  tag "fix_id": "F-29422r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "Enter the following command:

more /usr/local/Apache2.2/conf/httpd.conf.

Review the httpd.conf file and search for the following  directive:

Directory

For every root directory entry (i.e. <Directory />) ensure the following entry
exists:

Options None

If the statement above is not found in the root directory statement, this is a
finding.

If Allow directives are included in the root directory statement, this is a
finding.

If the root directory statement is not found at all, this is a finding."
  tag "fix": "Ensure the root directory has the appropriate Options assignment."
end


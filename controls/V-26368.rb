APACHE_AUTHORIZED_MODULES= attribute(
  'apache_authorized_modules',
  description: 'List of  authorized apache modules.',
  default: [
           ]
)
APACHE_UNAUTHORIZED_MODULES= attribute(
  'apache_unauthorized_modules',
  description: 'List of  unauthorized apache modules.',
  default: [
            "autoindex_module"
           ]
)

control "V-26368" do
  title "Automatic directory indexing must be disabled."
  desc  "To identify the type of web servers and versions software installed it
is common for attackers to scan for icons or special content specific to the
server type and version. A simple request like
http://example.com/icons/apache_pb2.png may tell the attacker that the server
is Apache 2.2 as shown below. The many icons are used primary for auto
indexing, which is recommended to be disabled."
  impact 0.5
  tag "gtitle": "WA00515"
  tag "gid": "V-26368"
  tag "rid": "SV-33219r1_rule"
  tag "stig_id": "WA00515 A22"
  tag "fix_id": "F-29492r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "Enter the following command:

/usr/local/Apache2.2/bin/httpd –M.

This will provide a list of all loaded modules. If autoindex_module is found,
this is a finding."
  tag "fix": "Edit the httpd.conf file and remove autoindex_module."

  apache = command("httpd -M").stdout.split

  describe APACHE_UNAUTHORIZED_MODULES do
    it { should_not be_in apache }
  end
end

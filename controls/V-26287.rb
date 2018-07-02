APACHE_AUTHORIZED_MODULES= attribute(
  'apache_authorized_modules',
  description: 'List of  authorized apache modules.',
  default: [
            "core_module",
            "http_module",
            "so_module",
            "mpm_prefork_module"
           ]
)
APACHE_UNAUTHORIZED_MODULES= attribute(
  'apache_unauthorized_modules',
  description: 'List of  unauthorized apache modules.',
  default: [
            "dav_module",
            "dav_fs_module",
            "dav_lock_module"
           ]
)

control "V-26287" do
  title "Web Distributed Authoring and Versioning (WebDAV) must be disabled."
  desc  "The Apache mod_dav and mod_dav_fs modules support WebDAV ('Web-based
Distributed Authoring and Versioning') functionality for Apache. WebDAV is an
extension to the HTTP protocol which allows clients to create, move, and delete
files and resources on the web server. WebDAV is not widely used, and has
serious security concerns as it may allow clients to modify unauthorized files
on the web server. Therefore, the WebDav modules mod_dav and mod_dav_fs should
be disabled."
  impact 0.5
  tag "gtitle": "WA00505"
  tag "gid": "V-26287"
  tag "rid": "SV-33216r1_rule"
  tag "stig_id": "WA00505 A22"
  tag "fix_id": "F-29390r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "Enter the following command:

/usr/local/Apache2.2/bin/httpd –M.

This will provide a list of all loaded modules.  If any of the following
modules are found, this is a finding.

dav_module
dav_fs_module
dav_lock_module"
  tag "fix": "Edit the httpd.conf file and remove the following modules:

dav_module
dav_fs_module
dav_lock_module"

  apache = command("httpd -M").stdout.split

  describe APACHE_UNAUTHORIZED_MODULES do
    it { should_not be_in apache }
  end
end

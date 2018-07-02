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
            "userdir_module"
           ]
)

control "V-26302" do
  title "User specific directories must not be globally enabled."
  desc  "The UserDir directive must be disabled so that user home directories
are not accessed via the web site with a tilde (~) preceding the username. The
directive also sets the path name of the directory that will be accessed. The
user directories should not be globally enabled since it allows anonymous
access to anything users may want to share with other users on the network.
Also consider that every time a new account is created on the system, there is
potentially new content available via the web site."
  impact 0.5
  tag "gtitle": "WA00525"
  tag "gid": "V-26302"
  tag "rid": "SV-33221r1_rule"
  tag "stig_id": "WA00525 A22"
  tag "fix_id": "F-29401r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "Enter the following command:

/usr/local/Apache2.2/bin/httpd –M.

This will provide a list of all loaded modules. If userdir_module is listed,
this is a finding."
  tag "fix": "Edit the httpd.conf file and remove userdir_module."

  apache_loaded_modules = command("httpd -M").stdout.split

  describe APACHE_UNAUTHORIZED_MODULES do
    it { should_not be_in apache_loaded_modules }
  end
end

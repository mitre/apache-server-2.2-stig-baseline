APACHE_CONF_FILE = attribute(
  'apache_conf_file',
  description: 'define path for the apache configuration file',
  default: "/etc/httpd/conf/httpd.conf"
)

APACHE_OWNER = attribute(
  'apache_owner',
  description: "The apache owner",
  default: 'apache'
)

SYS_ADMIN = attribute(
  'sys_admin',
  description: "The system adminstrator",
  default: ['root']
)

APACHE_GROUP = attribute(
  'apache_group',
  description: "The apache group",
  default: 'apache'
)

SYS_ADMIN_GROUP = attribute(
  'sys_admin_group',
  description: "The system adminstrator group",
  default: ['root']
)

control "V-2256" do
  title "The access control files are owned by a privileged web server account."
  desc  "This check verifies that the key web server system configuration files
are owned by the SA or Web Manager controlled account. These same files which
control the configuration of the web server, and thus its behavior, must also
be accessible by the account which runs the web service. If these files are
altered by a malicious user, the web server would no longer be under the
control of its managers and owners; properties in the web server configuration
could be altered to compromise the entire server platform.

  "
  impact 0.5
  tag "gtitle": "WG280"
  tag "gid": "V-2256"
  tag "rid": "SV-6880r1_rule"
  tag "stig_id": "WG280"
  tag "fix_id": "F-6761r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "System Administrator"
  tag "check": "This check verifies that the SA or Web Manager controlled
account owns the key web server files. These same files, which control the
configuration of the web server, and thus its behavior, must also be accessible
by the account that runs the web service process.

If it exists, the following file need to be owned by a privileged account.

.htaccess
httpd.conf

Use the command find / -name httpd.conf to find the file
Change to the Directory that contains the httpd.conf file
Use the command ls -l httpd.conf to determine ownership of the file

-The Web Manager or the SA should own all the system files and directories.
-The configurable directories can be owned by the WebManager or equivalent
user.

Permissions on these files should be 660 or more restrictive.

If root or an authorized user does not own the web system files and the
permission are not correct, this is a finding."
  tag "fix": "The site needs to ensure that the owner should be the
non-privileged web server account or equivalent which runs the web service;
however, the group permissions represent those of the user accessing the web
site that must execute the directives in .htacces."

  begin
    apache_conf_handle = apache_conf(APACHE_CONF_FILE)
    authorized_sa_user_list = SYS_ADMIN.clone << APACHE_OWNER
    authorized_sa_group_list = SYS_ADMIN_GROUP.clone << APACHE_GROUP
    doc_root = apache_conf_handle.DocumentRoot.map{ |element| element.gsub(/"/, '') }[0]

    access_control_files = [ '.htaccess',
                            '.htpasswd']

    apache_conf_handle.params

    describe apache_conf_handle do
      its ('params') { should_not be_empty }
    end

    access_control_files.each do |file|
      file_path = command("find / -name #{file}").stdout.chomp

      if file_path.empty?
        describe "Skip Message" do
          skip "Skipped: Access control file #{file} not found"
        end
      end

      file_path.split.each do |file|
        describe file(file) do
        its('owner') { should be_in authorized_sa_user_list }
        its('group') { should be_in authorized_sa_group_list }
          its('mode')  { should cmp <= 0660 }
        end
      end
    end

    describe file(APACHE_CONF_FILE) do
      its('owner') { should be_in authorized_sa_user_list }
      its('group') { should be_in authorized_sa_group_list }
      its('mode')  { should cmp <= 0660 }
    end

      describe file(doc_root) do
        its('owner') { should be_in authorized_sa_user_list }
        its('group') { should be_in authorized_sa_group_list }
      end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil }
    end
  end
end

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

control "V-2255" do
  title "The web server’s htpasswd files (if present) must reflect proper
ownership and permissions"
  desc  "In addition to OS restrictions, access rights to files and directories
can be set on a web site using the web server software.  That is, in addition
to allowing or denying all access rights, a rule can be specified that allows
or denies partial access rights.  For example, users can be given read-only
access rights to files, to view the information but not change the files.

    This check verifies that the htpasswd file is only accessible by system
administrators or web managers, with the account running the web service having
group permissions of read and execute.  htpasswd is a utility used by Netscape
and Apache to provide for password access to designated web sites.  I
  "
  impact 0.5
  tag "gtitle": "WG270"
  tag "gid": "V-2255"
  tag "rid": "SV-36478r2_rule"
  tag "stig_id": "WG270 A22"
  tag "fix_id": "F-6758r2_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "System Administrator"
  tag "check": "To locate the htpasswd file enter the following command:

Find / -name htpasswd
Permissions should be r-x r - x - - - (550)

If permissions on htpasswd are greater than 550, this is a finding.

Owner should be the SA or Web Manager account, if another account has access to
this file, this is a finding.
"
  tag "fix": "The SA or Web Manager account should own the htpasswd file and
permissions should be set to 550."

  begin

    authorized_sa_user_list = SYS_ADMIN.clone << APACHE_OWNER
    authorized_sa_group_list = SYS_ADMIN_GROUP.clone << APACHE_GROUP

    htpasswd = command('find / -name .htpasswd').stdout.chomp
    htpasswd.split.each do |htpwd|
      describe file(htpwd) do
        its('mode') { should cmp <= 0550 }
        its('owner') { should be_in authorized_sa_user_list }
        its('group') { should be_in authorized_sa_group_list }
      end
    end

    if htpasswd.empty?
      describe "Skip Message" do
        skip "Skipped: .htpasswd file not found"
      end
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil }
    end
  end
end

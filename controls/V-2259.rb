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

control "V-2259" do
  title "Web server system files must conform to minimum file permission
requirements."
  desc  "This check verifies that the key web server system configuration files
are owned by the SA or the web administrator controlled account. These same
files that control the configuration of the web server, and thus its behavior,
must also be accessible by the account that runs the web service. If these
files are altered by a malicious user, the web server would no longer be under
the control of its managers and owners; properties in the web server
configuration could be altered to compromise the entire server platform."
  impact 0.5
  tag "gtitle": "WG300"
  tag "gid": "V-2259"
  tag "rid": "SV-32938r1_rule"
  tag "stig_id": "WG300 A22"
  tag "fix_id": "F-29268r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "Apache directory and file permissions and ownership should be
set per the following table.. The installation directories may vary from one
installation to the next.  If used, the WebAmins group should contain only
accounts of persons authorized to manage the web server configuration,
otherwise the root group should own all Apache files and directories.

If the files and directories are not set to the following permissions or more
restrictive, this is a finding.

To locate the ServerRoot directory enter the following command.
grep ^ ServerRoot /usr/local/apache2/conf/httpd.conf

/Server
root dir
apache\t      root\tWebAdmin\t771/660

/apache/cgi-bin    root\tWebAdmin\t775/775
/apache/bin\t       root\tWebAdmin\t550/550
/apache/config     root\tWebAdmin\t770/660
/apache/htdocs    root\tWebAdmin\t775/664
/apache/logs       root\tWebAdmin\t750/640

NOTE:  The permissions are noted as directories / files"
  tag "fix": "Use the chmod command to set permissions on the web server system
directories and files as follows.

root dir
apache\t      root\tWebAdmin\t771/660
/apache/cgi-bin    root\tWebAdmin\t775/775
/apache/bin\t       root\tWebAdmin\t550/550
/apache/config     root\tWebAdmin\t770/660
/apache/htdocs    root\tWebAdmin\t775/664
/apache/logs       root\tWebAdmin\t750/640


"
  begin
    authorized_sa_user_list = SYS_ADMIN.clone << APACHE_OWNER
    authorized_sa_group_list = SYS_ADMIN_GROUP.clone << APACHE_GROUP

    describe.one do
      describe file('/usr/sbin/httpd') do
        its('owner') { should be_in authorized_sa_user_list }
        its('group') { should be_in authorized_sa_group_list }
        its('mode') { should cmp <= 0550 }
      end
      describe file('/usr/sbin/httpd') do
        it { should be_owned_by APACHE_OWNER }
        its('group') { should cmp APACHE_GROUP }
        its('mode') { should cmp <= 0550 }
      end
    end
    describe.one do
      describe file('/etc/httpd/') do
        its('owner') { should be_in authorized_sa_user_list }
        its('group') { should be_in authorized_sa_group_list }
        its('mode') { should cmp <= 0770 }
      end
      describe file('/etc/httpd/') do
        it { should be_owned_by APACHE_OWNER }
        its('group') { should cmp APACHE_GROUP }
        its('mode') { should cmp <= 0660 }
      end
    end
    describe.one do
      describe file('/etc/httpd/conf.d') do
        its('owner') { should be_in authorized_sa_user_list }
        its('group') { should be_in authorized_sa_group_list }
        its('mode') { should cmp <= 0770 }
      end
      describe file('/etc/httpd/conf.d') do
        it { should be_owned_by APACHE_OWNER }
        its('group') { should cmp APACHE_GROUP }
        its('mode') { should cmp <= 0660 }
      end
    end
    describe.one do
      describe file('/etc/httpd/modules') do
        its('owner') { should be_in authorized_sa_user_list }
        its('group') { should be_in authorized_sa_group_list }
        its('mode') { should cmp <= 0770 }
      end
      describe file('/etc/httpd/modules') do
        it { should be_owned_by APACHE_OWNER }
        its('group') { should cmp APACHE_GROUP }
        its('mode') { should cmp <= 0660 }
      end
    end
    describe.one do
      describe file('/var/www/cgi-bin/') do
        its('owner') { should be_in authorized_sa_user_list }
        its('group') { should be_in authorized_sa_group_list }
        its('mode') { should cmp <= 1775 }
      end
      describe file('/var/www/cgi-bin/') do
        it { should be_owned_by APACHE_OWNER }
        its('group') { should cmp APACHE_GROUP }
        its('mode') { should cmp <= 0664 }
      end
    end
    describe.one do
      describe file('/var/log/httpd') do
        its('owner') { should be_in authorized_sa_user_list }
        its('group') { should be_in authorized_sa_group_list }
        its('mode') { should cmp <= 0750 }
      end
      describe file('/var/log/httpd') do
        it { should be_owned_by APACHE_OWNER }
        its('group') { should cmp APACHE_GROUP }
        its('mode') { should cmp <= 0640 }
      end
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil }
    end
  end

end

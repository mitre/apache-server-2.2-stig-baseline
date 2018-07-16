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

control "V-2248" do
  title "Web administration tools must be restricted to the web manager and the
web manager’s designees."
  desc  "All automated information systems are at risk of data loss due to
disaster or compromise. Failure to provide adequate protection to the
administration tools creates risk of potential theft or damage that may
ultimately compromise the mission.  Adequate protection ensures that server
administration operates with less risk of losses or operations outages.  The
key web service administrative and configuration tools must be accessible only
by the authorized web server administrators. All users granted this authority
must be documented and approved by the ISSO. Access to the IIS Manager will be
limited to authorized users and administrators. "
  impact 0.5
  tag "gtitle": "WG220"
  tag "gid": "V-2248"
  tag "rid": "SV-32948r2_rule"
  tag "stig_id": "WG220 A22"
  tag "fix_id": "F-26807r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "System Administrator"
  tag "check": "Determine which tool or control file is used to control the
configuration of the web server.

If the control of the web server is done via control files, verify who has
update access to them. If tools are being used to configure the web server,
determine who has access to execute the tools.

If accounts other than the SA, the web manager, or the web manager designees
have access to the web administration tool or control files, this is a finding.
"
  tag "fix": "Restrict access to the web administration tool to only the web
manager and the web manager’s designees."


  begin

    authorized_sa_user_list = SYS_ADMIN.clone << APACHE_OWNER
    authorized_sa_group_list = SYS_ADMIN_GROUP.clone << APACHE_GROUP

    apache_conf_handle = apache_conf(APACHE_CONF_FILE)
    apache_conf_handle.params

    describe apache_conf_handle do
      its ('params') { should_not be_empty }
    end

    describe file(APACHE_CONF_FILE) do
      its('owner') { should be_in authorized_sa_user_list }
      its('group') { should be_in authorized_sa_group_list }
      its('mode')  { should cmp <= 0660 }
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil }
    end
  end
end

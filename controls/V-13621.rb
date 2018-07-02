APACHE_DISALLOWED_FILE_LIST = attribute(
  'apache_disallowed_file_list',
  description: 'File list of  documentation, sample code, example applications, and tutorials.',
  default: ["/usr/share/man/man8/apachectl.8.gz"]
)

APACHE_EXCEPTION_FILES = attribute(
  'apache_allowed_file_list',
  description: 'File list of allowed documentation, sample code, example applications, and tutorials.',
  default: [
           ]
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

control "V-13621" do
  title "All web server documentation, sample code, example applications, and
tutorials must be removed from a production web server."
  desc  "Web server documentation, sample code, example applications, and
tutorials may be an exploitable threat to a web server. A production web server
may only contain components that are operationally necessary (e.g., compiled
code, scripts, web-content, etc.). Delete all directories that contain samples
and any scripts used to execute the samples. If there is a requirement to
maintain these directories at the site on non-production servers for training
purposes, have NTFS permissions set to only allow access to authorized users
(i.e., web administrators and systems administrators). Sample applications or
scripts have not been evaluated and approved for use and may introduce
vulnerabilities to the system."
  impact 0.7
  tag "gtitle": "WG385"
  tag "gid": "V-13621"
  tag "rid": "SV-32933r1_rule"
  tag "stig_id": "WG385 A22"
  tag "fix_id": "F-29260r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "severity_override_guidance": "Any sample application or sample
executable script found on the production web server will be a CAT I finding.

Any web server documentation or sample file found on the production web server
and accessible to web users or non-administrators will be a CAT III finding.

Any web server documentation or sample file found on the production web server
and accessible only to SAs or to web administrators is permissible and not a
finding.
"
  tag "responsibility": "Information Assurance Officer"
  tag "check": "Query the SA to determine if all directories that contain
samples and any scripts used to execute the samples have been removed from the
server. Each web server has its own list of sample files. This may change with
the software versions, but the following are some examples of what to look for
(This should not be the definitive list of sample files, but only an example of
the common samples that are provided with the associated web server. This list
will be updated as additional information is discovered.):

ls -Ll /usr/local/apache2/manual.

If there is a requirement to maintain these directories at the site for
training or other such purposes, have permissions or set the permissions to
only allow access to authorized users. If any sample files are found on the web
server, this is a finding."
  tag "fix": "Ensure sample code and documentation have been removed from the
web server."

  begin

    authorized_sa_user_list = SYS_ADMIN.clone << APACHE_OWNER
    authorized_sa_group_list = SYS_ADMIN_GROUP.clone << APACHE_GROUP

    APACHE_DISALLOWED_FILE_LIST.each do |file|
      describe file(file) do
        it { should_not exist }
      end
    end

    APACHE_EXCEPTION_FILES.each do |file|
      describe file(file) do
        its('owner') { should be_in authorized_sa_user_list }
        its('group') { should be_in authorized_sa_group_list }
        its('mode') { should cmp '640' }
      end
    end
  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil }
    end
  end
end

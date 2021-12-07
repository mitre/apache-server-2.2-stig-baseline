
APACHE_MIN_VER = attribute(
  'apache_min_ver',
  description: 'Minimum Web vendor-supported version.',
  default: '2.2.0'
)

APACHE_PATH= attribute(
  'apache_path',
  description: 'Path for the apache configuration file',
  default: "/usr/sbin"
)

control "V-2246" do
  title "Web server software must be a vendor-supported version."
  desc  "Many vulnerabilities are associated with older versions of web server
software. As hot fixes and patches are issued, these solutions are included in
the next version of the server software. Maintaining the web server at a
current version makes the efforts of a malicious user to exploit the web
service more difficult."
  impact 0.7
  tag "gtitle": "WG190"
  tag "gid": "V-2246"
  tag "rid": "SV-36441r2_rule"
  tag "stig_id": "WG190 A22"
  tag "fix_id": "F-2295r5_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "System Administrator"
  tag "check": "To determine the version of the Apache software that is running
on the system. Use the command:

httpd –v

httpd2 –v

If the version of Apache is not at the following version or higher, this is a
finding.

Apache httpd server version 2.2 - Release 2.2.31 (July 2015)

Note: In some situations, the Apache software that is being used is supported
by another vendor, such as Oracle in the case of the Oracle Application Server
or IBMs HTTP Server.
The versions of the software in these cases may not match the above mentioned
version numbers. If the site can provide vendor documentation showing the
version of the web server is supported, this would not be a finding.
"
  tag "fix": "Install the current version of the web server software and
maintain appropriate service packs and patches."

  version = command('httpd -v').stdout.lines.first.split('/').last.split( ).first

   describe version do
        it {should cmp >= '2.2.31'}
   end
  
#  begin
#    describe package('httpd') do
#      its('version') { should cmp >= '2.2.31' }
#    end
#  rescue Exception => msg
#    describe "Exception: #{msg}" do
#      it { should be_nil }
#    end
#  end
end

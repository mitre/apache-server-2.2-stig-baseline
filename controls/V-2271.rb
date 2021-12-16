MONITORINGSOFTWARE = attribute(
  'monitoring_software',
  description: "Monitoring software for CGI or equivalent programs",
  default: ['audit', 'auditd']
)

control "V-2271" do
  title "Monitoring software must include CGI or equivalent programs in its
scope."
  desc  "By their very nature, CGI type files permit the anonymous web user to
interact with data and perhaps store data on the web server. In many cases, CGI
scripts exercise system-level control over the server’s resources. These files
make appealing targets for the malicious user. If these files can be modified
or exploited, the web server can be compromised. These files must be monitored
by a security tool that reports unauthorized changes to these files.


  "
  impact 0.5
  tag "gtitle": "WG440"
  tag "gid": "V-2271"
  tag "rid": "SV-32927r2_rule"
  tag "stig_id": "WG440 A22"
  tag "fix_id": "F-29255r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "CGI or equivalent files must be monitored by a security tool
that reports unauthorized changes. It is the purpose of such software to
monitor key files for unauthorized changes to them. The reviewer should query
the ISSO, the SA, and the web administrator and verify the information provided
by asking to see the template file or configuration file of the software being
used to accomplish this security task. Example file extensions for files
considered to provide active content are, but not limited to, .cgi, .asp,
.aspx, .class, .vb, .php, .pl, and .c.

If the site does not have a process in place to monitor changes to CGI program
files, this is a finding."
  tag "fix": "Use a monitoring tool to monitor changes to the CGI or equivalent
directory. This can be done with something as simple as a script or batch file
that would identify a change in the file.
"

  begin
    describe.one do
      MONITORINGSOFTWARE.each do |software|
        describe package(software) do
          it{ should be_installed }
        end
      end
    end
  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil }
    end
  end
end



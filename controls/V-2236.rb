DISALLOWED_COMPILER_LIST = attribute(
  'disallowed_compiler_list',
  description: "List of disallowed compilers",
  default: []
)

control "V-2236" do
  title "Installation of a compiler on production web server is prohibited."
  desc  "The presence of a compiler on a production server facilitates the
malicious user’s task of creating custom versions of programs and installing
Trojan Horses or viruses. For example, the attacker’s code can be uploaded and
compiled on the server under attack."
  impact 0.5
  tag "gtitle": "WG080"
  tag "gid": "V-2236"
  tag "rid": "SV-32956r3_rule"
  tag "stig_id": "WG080 A22"
  tag "fix_id": "F-29279r4_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "Query the SA and the Web Manager to determine if a compiler is
present on the server.  If a compiler is present, this is a finding.

NOTE:  If the web server is part of an application suite and a compiler is
needed for installation, patching, and upgrading of the suite or if the
compiler is embedded and can't be removed without breaking the suite, document
the installation of the compiler with the ISSO/ISSM and verify that the
compiler is restricted to administrative users only.  If documented and
restricted to administrative users, this is not a finding.
"
  tag "fix": "Remove any compiler found on the production web server, but if
the compiler program is needed to patch or upgrade an application suite in a
production environment or the compiler is embedded and will break the suite if
removed, document the compiler installation with the ISSO/ISSM and ensure that
the compiler is restricted to only administrative users."

  begin
    if inspec.os.family.eql?("redhat")
      compiler_list = command('yum search all compiler').stdout.scan(/^(\S+)\s:\s/).flatten
    elsif inspec.os.family.eql?("debian")
      compiler_list = command('apt-cache search compiler').stdout.scan(/^(\S+)\s-\s/).flatten
    end


    compiler_list.each do |compiler|
      describe package(compiler) do
        it { should_not be_installed }
      end
    end

    DISALLOWED_COMPILER_LIST.each do |compiler|
      describe package(compiler) do
        it { should_not be_installed }
      end
    end

  rescue Exception => msg
    describe "Exception: #{msg}" do
      it { should be_nil }
    end
  end
end

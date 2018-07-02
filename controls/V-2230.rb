APACHE_CONF_FILE = attribute(
  'apache_conf_file',
  description: 'Path for the apache configuration file',
  default: "/etc/httpd/conf/httpd.conf"
)

APACHE_BACKUP_REPOSITORY = attribute(
  'apache_backup_repository',
  description: 'Path for the apache home directory',
  default: '/etc/httpd/'
)

control "V-2230" do
  title "Backup interactive scripts on the production web server are
prohibited."
  desc  "Copies of backup files will not execute on the server, but they can be
read by the anonymous user if special precautions are not taken. Such backup
copies contain the same sensitive information as the actual script being
executed and, as such, are useful to malicious users. Techniques and systems
exist today that search web servers for such files and are able to exploit the
information contained in them.

    Backup copies of files are automatically created by some text editors such
as emacs and edit plus. The emacs editor will write a backup file with an
extension ~ added to the name of the original file. The edit plus editor will
create a .bak file. Of course, this would imply the presence and use of
development tools on the web server, which is a finding under WG130. Having
backup scripts on the web server provides one more opportunity for malicious
persons to view these scripts and use the information found in them.

  "
  impact 0.3
  tag "gtitle": "WG420"
  tag "gid": "V-2230"
  tag "rid": "SV-6930r1_rule"
  tag "stig_id": "WG420 A22"
  tag "fix_id": "F-27282r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "System Administrator"
  tag "check": "This check is limited to CGI/interactive content and not static
HTML.

Search for backup copies of CGI scripts on the web server or ask the SA or the
Web Administrator if they keep backup copies of CGI scripts on the web server.

Common backup file extensions are: *.bak, *.old, *.temp, *.tmp, *.backup,
*.??0. This would also apply to .jsp files.

UNIX:
find / name “*.bak” –print
find / name “*.*~” –print
find / name “*.old” –print

If files with these extensions are found in either the document directory or
the home directory of the web server, this is a finding.

If files with these extensions are stored in a repository (not in the document
root) as backups for the web server, this is a finding.

If files with these extensions have no relationship with web activity, such as
a backup batch file for operating system utility, and they are not accessible
by the web application, this is not a finding.
"
  tag "fix": "Ensure that CGI backup scripts are not left on the production web
server."
begin
  dirs = ['/var/www', APACHE_BACKUP_REPOSITORY]

  apache_conf_handle = apache_conf(APACHE_CONF_FILE)

  describe apache_conf_handle do
    its ('params') { should_not be_empty }
  end

  apache_conf_handle.http.entries.each do |http|
    dirs.push(http.params['root']) unless http.params['root'].nil?
  end

  apache_conf_handle.servers.entries.each do |server|
    dirs.push(server.params['root']) unless server.params['root'].nil?
  end

  apache_conf_handle.locations.entries.each do |location|
    dirs.push(location.params['root']) unless location.params['root'].nil?
  end

  dirs.flatten!.uniq!

  dirs.each do |dir|
    next unless directory(dir).exist?
    describe "List of backup NINGX and/or CGI scripts found in #{dir}" do
      subject { command("find #{dir} -name '.?*' -not-name '.ht*' -or-name '*~' -or-name '*.bak' -or-name '*.old*'").stdout.chomp.split }
      it { should be_empty }
    end
  end
rescue Exception => msg
  describe "Exception: #{msg}" do
    it { should be_nil }
  end
end
end

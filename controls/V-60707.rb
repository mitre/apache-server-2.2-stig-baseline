APACHE_SSL_FILE = attribute(
  'apache_ssl_file',
  description: 'define path for the apache ssl file',
  default: "/etc/httpd/conf.d/ssl.conf"
)

control "V-60707" do
  title "The web server must remove all export ciphers from the cipher suite."
  desc  "During the initial setup of a Transport Layer Security (TLS)
connection to the web server, the client sends a list of supported cipher
suites in order of preference.  The web server will reply with the cipher suite
it will use for communication from the client list.  If an attacker can
intercept the submission of cipher suites to the web server and place, as the
preferred cipher suite, a weak export suite, the encryption used for the
session becomes easy for the attacker to break, often within minutes to hours."
  impact 0.5
  tag "gtitle": "WG345"
  tag "gid": "V-60707"
  tag "rid": "SV-75159r1_rule"
  tag "stig_id": "WG345 A22"
  tag "fix_id": "F-66387r2_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "Locate the Apache httpd.conf and ssl.conf file if available.
Open the httpd.conf and ssl.conf file with an editor and search for the
following uncommented directive: SSLCipherSuite
For all enabled SSLCipherSuite directives, ensure the cipher specification
string contains the kill cipher from list option for all export cipher suites,
i.e., !EXPORT, which may be abbreviated !EXP.  If the SSLCipherSuite directive
does not contain !EXPORT or there are no enabled SSLCipherSuite directives,
this is a finding.
"
  tag "fix": "Update the cipher specification string for all enabled
SSLCipherSuite directives to include !EXPORT."

  describe apache_conf(APACHE_SSL_FILE) do
    its('SSLCipherSuite') { should include /(!EXPORT|!EXP)/ }
  end
end

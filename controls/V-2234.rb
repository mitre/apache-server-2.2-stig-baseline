control "V-2234" do
  title "Public web server resources must not be shared with private assets."
  desc  "It is important to segregate public web server resources from private
resources located behind the DoD DMZ in order to protect private assets. When
folders, drives or other resources are directly shared between the public web
server and private servers the intent of data and resource segregation can be
compromised.

    In addition to the requirements of the DoD Internet-NIPRNet DMZ STIG that
isolates inbound traffic from the external network to the internal network,
resources such as printers, files, and folders/directories will not be shared
between public web servers and assets located within the internal network.


  "
  impact 0.5
  tag "gtitle": "WG040"
  tag "gid": "V-2234"
  tag "rid": "SV-32957r1_rule"
  tag "stig_id": "WG040 A22"
  tag "fix_id": "F-29280r1_fix"
  tag "cci": []
  tag "nist": ["Rev_4"]
  tag "documentable": false
  tag "responsibility": "Web Administrator"
  tag "check": "Determine whether the public web server has a two-way trusted
relationship with any private asset located within the network. Private web
server resources (e.g., drives, folders, printers, etc.) will not be directly
mapped to or shared with public web servers.

If sharing is selected for any web folder, this is a finding.

The following checks indicate inappropriate sharing of private resources with
the public web server:

If private resources (e.g., drives, partitions, folders/directories, printers,
etc.) are shared with the public web server, then this is a finding.
"
  tag "fix": "Configure the public web server to not have a trusted
relationship with any system resource that is also not accessible to the
public. Web content is not to be shared via Microsoft shares or NFS mounts."

  only_if { false } # this will always skip
end

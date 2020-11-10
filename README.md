# apache_server_baseline

Baseline InSpec profile testing configuration of Apache HTTPD Server per Apache site 2.2 STIG

## Description

This InSpec compliance profile is a collection of automated tests for Apache server compliance with the [DISA Apache 2.2 STIG](https://iasecontent.disa.mil/stigs/zip/U_Apache_2-2_UNIX_V1R10_STIG.zip).

InSpec is an open-source run-time framework and rule language used to specify compliance, security, and policy requirements for testing any node in your infrastructure.

## Requirements

- [ruby](https://www.ruby-lang.org/en/) at least 2.4
- [InSpec](http://inspec.io/) at least version 2.1
    - Install via ruby gem: `gem install inspec`
- Linux server, to test

## Usage
Use InSpec to run this profile to check compliance with the the DISA Apache 
site 2.2 STIG. InSpec makes it easy to run tests wherever you need. More options 
listed here: [InSpec cli](http://inspec.io/docs/reference/cli/)

#### Run with locally download profile
The locally downloaded profile is the preferred way to use this profile as it 
allows you to setup a consistent attributes.yml

These commands can be run from any command prompt/terminal with inspec installed 
and git

``` bash
# Clone Inspec Profile
$ git clone https://github.com/mitre/apache-server-2.2-stig-baseline.git

# Run profile locally (assuming you have not changed directories since cloning)
# This will display compliance level at the prompt, and generate a JSON file 
# for export called output.json
$ inspec exec apache-server-2.2-stig-baseline --reporter cli json:output.json

# Run profile with custom settings defined in attributes.yml against the target 
# server example.com. 
$ inspec exec apache-server-2.2-stig-baseline -t ssh://user@password:example.com --attrs attributes.yml --reporter cli json:output.json

# Run profile with: custom attributes, ssh keyed into a custom target, and sudo.
$ inspec exec apache-server-2.2-stig-baseline -t ssh://user@hostname -i /path/to/key --sudo --attrs attributes.yml --reporter cli json:output.json
```

#### Run with remote profile
You may choose to run the profile via a remote url, this has the advantage of always being up to date.
The disadvantage is you may wish to modify controls, which is only possible when downloaded.
Also, the remote profile is unintuitive for passing in attributes, which modify the default values of the profile.
``` bash
inspec exec https://gitlab.mitre.org/inspec/apache_server_baseline/repository/master/archive.tar.gz
```

## Attributes (Configuration)
You may alter the default settings of the profile by creating/modifying a yaml 
encoded 'attributes' file. The following yaml code details the currently 
supported attributes, and can also be viewed as the attributes.yml file in this 
repository.

``` yaml
# Description: Apache home Directory
apache_home: '/etc/httpd/'

# Description: Apache conf Directory
apache_conf_dir: '/etc/httpd/conf'

# Description: Apache library Directory
apache_lib_dir: '/usr/share/java/apache'

# Description: Apache service Name
apache_service_name: 'httpd'

# Description: apache username
apache_user: 'apache'

# Description: Port of the apache instance
apache_port: '8084'

# Description: Group owner of files/directories
apache_group: 'apache'

# Description: User owner of files/directories
apache_owner: 'apache'
```

## Contributors + Kudos

- Craig Chaffee
- Nikhil Sharma
- The MITRE InSpec Team

## License and Author

### Authors

- Author:: Craig Chaffee
- Author:: Nikhil Sharma

### License 

* This project is licensed under the terms of the Apache license 2.0 (apache-2.0)

### NOTICE  

© 2020 The MITRE Corporation.  

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.  

### NOTICE
MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  

### NOTICE  

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx  

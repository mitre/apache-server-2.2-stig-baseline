# apache_site_baseline

Baseline InSpec profile testing configuration of Apache HTTPD Server per Apache site 2.2 STIG

## Description

This InSpec compliance profile is a collection of automated tests for Apache site compliance with the [DISA Apache 2.2 STIG](https://iasecontent.disa.mil/stigs/zip/U_Apache_2-2_UNIX_V1R10_STIG.zip).

InSpec is an open-source run-time framework and rule language used to specify compliance, security, and policy requirements for testing any node in your infrastructure.

## Requirements

- [ruby](https://www.ruby-lang.org/en/) at least 2.4
- [InSpec](http://inspec.io/) at least version 2.1
    - Install via ruby gem: `gem install inspec`
- Linux server, to test

## Usage
InSpec makes it easy to run tests wherever you need. More options listed here: [InSpec cli](http://inspec.io/docs/reference/cli/)

### Run with remote profile:
You may choose to run the profile via a remote url, this has the advantage of always being up to date.
The disadvantage is you may wish to modify controls, which is only possible when downloaded.
Also, the remote profile is unintuitive for passing in attributes, which modify the default values of the profile.
``` bash
inspec exec https://gitlab.mitre.org/inspec/apache_site_baseline/repository/master/archive.tar.gz
```

Another option is to download the profile then run it, this allows you to edit specific instructions and view the profile code.
``` bash
# Clone Inspec Profile
$ git clone https://gitlab.mitre.org/inspec/apache_site_baseline.git

# Run profile locally (assuming you have not changed directories since cloning)
$ inspec exec apache_site_baseline

# Run profile locally with custom settings defined in attributes.yml
$ inspec exec apache_site_bsaeline --attrs attributes.yml

# Alternatively, run a single test
$ inspec exec apache_site_baseline --controls a_control_name
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

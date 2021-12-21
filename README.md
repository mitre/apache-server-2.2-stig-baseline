# apache-server-2.2-stig-baseline 

InSpec Profile to validate the secure configuration of apache-server-2.2-stig-baseline, against [DISA's](https://iase.disa.mil/stigs/Pages/index.aspx) Apache HTTPD Server per Apache site 2.2 STIG Ver 1, Rel 10

#### Container-Ready: Profile updated to adapt checks when the running against a containerized instance of MySQL, based on reference container: (docker pull httpd) at https://hub.docker.com/_/httpd

## Getting Started  

__For the best security of the runner, always install on the runner the _latest version_ of InSpec and supporting Ruby language components.__ 
The latest versions and installation options are available at the [InSpec](http://inspec.io/) site.

## Tailoring to Your Environment
The following inputs must be configured in an inputs ".yml" file for the profile to run correctly for your specific environment. More information about InSpec inputs can be found in the [InSpec Profile Documentation](https://www.inspec.io/docs/reference/profiles/).

``` yaml
# Description: Apache home Directory
apache_home: ''

# Description: Apache conf Directory
apache_conf_dir: ''

# Description: Apache library Directory
apache_lib_dir: ''

# Description: Apache service Name
apache_service_name: ''

# Description: apache username
apache_user: ''

# Description: Port of the apache instance
apache_port: ''

# Description: Group owner of files/directories
apache_group: ''

# Description: User owner of files/directories
apache_owner: ''
```

# Running This Baseline Directly from Github

Against a _**locally-hosted**_ instance (i.e., InSpec installed on the target host)
```
inspec exec https://github.com/mitre/apache-server-2.2-stig-baseline/archive/master.tar.gz --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
Against a _**docker-containerized**_ instance (i.e., InSpec installed on the node hosting the container):
```
inspec exec https://github.com/mitre/apache-server-2.2-stig-baseline/archive/master.tar.gz -t docker://<instance_id> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```


### Different Run Options

  [Full exec options](https://docs.chef.io/inspec/cli/#options-3)

## Running This Baseline from a local Archive copy 

If your runner is not always expected to have direct access to GitHub, use the following steps to create an archive bundle of this baseline and all of its dependent tests:

(Git is required to clone the InSpec profile using the instructions below. Git can be downloaded from the [Git](https://git-scm.com/book/en/v2/Getting-Started-Installing-Git) site.)

When the __"runner"__ host uses this profile baseline for the first time, follow these steps: 

```
mkdir profiles
cd profiles
git clone https://github.com/mitre/apache-server-2.2-stig-baseline
inspec archive apache-server-2.2-stig-baseline
inspec exec <name of generated archive> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```
For every successive run, follow these steps to always have the latest version of this baseline:

```
cd apache-server-2.2-stig-baseline
git pull
cd ..
inspec archive apache-server-2.2-stig-baseline --overwrite
inspec exec <name of generated archive> --input-file=<path_to_your_inputs_file/name_of_your_inputs_file.yml> --reporter=cli json:<path_to_your_output_file/name_of_your_output_file.json>
```

## Viewing the JSON Results

The JSON results output file can be loaded into __[heimdall-lite](https://heimdall-lite.mitre.org/)__ for a user-interactive, graphical view of the InSpec results. 

The JSON InSpec results file may also be loaded into a __[full heimdall server](https://github.com/mitre/heimdall)__, allowing for additional functionality such as to store and compare multiple profile runs.

## Authors
* Craig Chaffee
* Nikhil Sharma

## Special Thanks 
* Mohamed El-Sharkawi - [HackerShark](https://github.com/HackerShark)
* Shivani Karikar - [karikarshivani](https://github.com/karikarshivani)

## Contributing and Getting Help
To report a bug or feature request, please open an [issue](https://github.com/mitre/apache-server-2.2-stig-baseline/issues/new).

### NOTICE

© 2018-2020 The MITRE Corporation.

Approved for Public Release; Distribution Unlimited. Case Number 18-3678.

### NOTICE

MITRE hereby grants express written permission to use, reproduce, distribute, modify, and otherwise leverage this software to the extent permitted by the licensed terms provided in the LICENSE.md file included with this project.

### NOTICE  

This software was produced for the U. S. Government under Contract Number HHSM-500-2012-00008I, and is subject to Federal Acquisition Regulation Clause 52.227-14, Rights in Data-General.  

No other use other than that granted to the U. S. Government, or to those acting on behalf of the U. S. Government under that Clause is authorized without the express written permission of The MITRE Corporation. 

For further information, please contact The MITRE Corporation, Contracts Management Office, 7515 Colshire Drive, McLean, VA  22102-7539, (703) 983-6000.  

### NOTICE  

DISA STIGs are published by DISA IASE, see: https://iase.disa.mil/Pages/privacy_policy.aspx  

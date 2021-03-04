# Package Development README

Overview of how the the CIDS OpenWrt package is setup.

When the package is compiled/installed, all the relevant files are placed in the '/etc/capstone-ids/' directory

cids-service is a file that is placed in /etc/init.d/ so that CIDS can start at bootup and run as a service on the router

A symbolic link is created from etc/capstone-ids/cids-start to /usr/bin/cids

cids-start is a simple Bash script which does three things:
1.) Installs necessary packages and pip modules if they are not already installed
2.) Check the config file to see if the email alerting system has been setup. It it hasn't the relevant information will be put in a log file
3.) Start the actual IDS


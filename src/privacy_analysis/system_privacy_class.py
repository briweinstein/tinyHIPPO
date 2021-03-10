#! /usr/bin/env python3
import os

class Privacy_Analysis_System:
  def __init__(self):
    pass

<<<<<<< HEAD
  def analyze_system_configs(self):
    self.__check_encryption()
    self.__check_package_upgrades()


  ############################################################################################## 
  ### Private Helper Functions
  ############################################################################################## 

  # Validate the router encryption type is not weak
  def __check_encryption(self):
=======
  def analyze_system_configs(self):                                                                                        # Validate the router encryption type is not weak
    # Validate the router encryption type is not weak
>>>>>>> 175f750... rebased, moved to src
    with open("/etc/config/wireless", "r") as wireless_config_file:
      data = wireless_config_file.read()
      if ("psk'" in data) or ("wep" in data):
        #TODO: alert("Weak encryption is in use. Switch to WPA2 from WPA or WEP.")
        print("Weak encryption found")

<<<<<<< HEAD
  ############################################################################################## 

  # Check for package upgrades
  def __check_package_upgrades(self):
=======
    # Check for package upgrades
>>>>>>> 175f750... rebased, moved to src
    upgradable = os.popen("opkg list-upgradable").read()
    if upgradable != "":
      #TODO: alert("Packages are available for an update.")
      print("Package update found.")

<<<<<<< HEAD
  ############################################################################################## 


=======
>>>>>>> 175f750... rebased, moved to src

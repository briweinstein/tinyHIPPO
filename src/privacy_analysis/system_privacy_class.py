#! /usr/bin/env python3
import os

class Privacy_Analysis_System:
  def __init__(self):
    pass

  def analyze_system_configs(self):
    self.__check_encryption()
    self.__check_package_upgrades()


  ############################################################################################## 
  ### Private Helper Functions
  ############################################################################################## 

  # Validate the router encryption type is not weak
  def __check_encryption(self):
    with open("/etc/config/wireless", "r") as wireless_config_file:
      data = wireless_config_file.read()
      if ("psk'" in data) or ("wep" in data):
        #TODO: alert("Weak encryption is in use. Switch to WPA2 from WPA or WEP.")
        print("Weak encryption found")

  ############################################################################################## 

  # Check for package upgrades
  def __check_package_upgrades(self):
    upgradable = os.popen("opkg list-upgradable").read()
    if upgradable != "":
      #TODO: alert("Packages are available for an update.")
      print("Package update found.")

  ############################################################################################## 



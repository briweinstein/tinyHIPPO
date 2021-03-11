#! /usr/bin/env python3
import os

class Privacy_Analysis_System:
  def __init__(self):
    pass

  def analyze_system_configs(self):
    self.__check_encryption()
    self.__check_package_upgrades()
    self.__check_root_password()
    self.__check_dropbear_config()

  ############################################################################################## 
  ### Private Helper Functions
  ############################################################################################## 

  # Validate the router encryption type is not weak
  def __check_encryption(self):
    weak_encryption_modes =	["none'", "wep", "owe'",
				 "psk'", "psk+", "psk-",
				 "wpa'", "wpa+", "wpa-"]
    data = self.__get_file_contents("/etc/config/wireless")
    if data is None:
      return
    for mode in weak_encryption_modes:
      if ("encryption '" + mode) in data:
        #TODO: alert("Weak encryption is in use. Switch to WPA2 from " + mode + ".")
        print("Weak encryption found")

  ############################################################################################## 

  # Check for package upgrades
  def __check_package_upgrades(self):
    # Check for package upgrades
    upgradable = os.popen("opkg list-upgradable").read()
    if upgradable != "":
      #TODO: alert("Packages are available for an update.")
      print("Package update found.")

  ############################################################################################## 

  # Check if a root password has been set
  def __check_root_password(self):
    data = self.__get_file_contents("/etc/shadow")
    if (data is not None) and ("root::" in data):
      #TODO: alert("No root password set. Set a root password.")
      print("No root password set.")

  ############################################################################################## 

  # Checks the dropbear configuration for root login and password login
  def __check_dropbear_config(self):
    data = self.__get_file_contents("/etc/config/dropbear")
    if (data is not None) and ("RootPasswordAuth 'on'" in data):
      #TODO: alert("Root user can login via ssh. Consider disabling this for security purposes.")
      print("Root user can login via ssh.")
    if "PasswordAuth 'on'" in data:
      #TODO: alert("Password login via ssh is allowed. Consider only allowing keypair login via ssh.")
      print("Password login via ssh is allowed.")

  ############################################################################################## 

  # Opens a file and returns the data
  def __get_file_contents(self, filename):
    # Depending on the file and the setup, the file may not exist. Try to avoid errors
    try:
      with open(filename, "r") as file:
        data = file.read()
        return data
    except:
      return

  ############################################################################################## 





include $(TOPDIR)/rules.mk

# Name, version and release number
# The name and version of your package are used to define the variable to point to the build directory of your package: $(PKG_BUILD_DIR)
PKG_NAME:=tinyHIPPO
PKG_VERSION:=0.1
PKG_RELEASE:=1

# Source settings (i.e. where to find the source codes)
# This is a custom variable, used below
SOURCE_DIR:=src/

include $(INCLUDE_DIR)/package.mk

# Package definition; instructs on how and where our package will appear in the overall configuration menu ('make menuconfig')
define Package/tinyHIPPO
	SECTION:=examples
	CATEGORY:=Examples
	DEPENDS:=+python3 +scapy +python3-pip +sqlite3-cli +nmap +python3-sqlalchemy
	TITLE:=Capstone IDS Project for CY4930, Northeastern University
endef

# Package description; a more verbose description on what our package does
define Package/tinyHIPPO/description
	A simple intrusion detection and privacy protection system for IoT devices
endef

# Package preparation instructions; create the build directory and copy the source code.
# The last command is necessary to ensure our preparation instructions remain compatible with the patching system.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -r $(SOURCE_DIR)/* $(PKG_BUILD_DIR)
	$(Build/Patch)
endef

# Package install instructions; create a directory inside the package to hold our executable, and then copy the executable we built previously into the folder
define Package/tinyHIPPO/install
	$(INSTALL_DIR) $(1)/etc/tinyHIPPO
	# Install all the source files
	$(INSTALL_DIR) $(1)/etc/tinyHIPPO/src
	$(CP) $(PKG_BUILD_DIR)/src/* $(1)/etc/tinyHIPPO/src/
	# Install all the setup files
	$(INSTALL_DIR) $(1)/etc/tinyHIPPO/setup
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/setup/tinyHIPPO_db_setup.sql $(1)/etc/tinyHIPPO/setup
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/setup/tinyHIPPOstart $(1)/etc/tinyHIPPO
	# Install all the core files and configs
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/tiny_hippo_run.py $(1)/etc/tinyHIPPO
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/config.py $(1)/etc/tinyHIPPO
	$(INSTALL_DATA) $(PKG_BUILD_DIR)/config.json $(1)/etc/tinyHIPPO
	# Install the symbolic
	$(INSTALL_DIR) $(1)/usr/bin
	ln -s /etc/tinyHIPPO/tinyHIPPOstart $(1)/usr/bin/tinyHIPPO
	# Install the service files
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/setup/tinyHIPPOservice $(1)/etc/init.d/tinyHIPPOservice
endef

# This command is always the last, it uses the definitions and variables we give above in order to get the job done
$(eval $(call BuildPackage,tinyHIPPO))

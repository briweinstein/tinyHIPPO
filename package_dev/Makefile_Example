include $(TOPDIR)/rules.mk

# Name, version and release number
# The name and version of your package are used to define the variable to point to the build directory of your package: $(PKG_BUILD_DIR)
PKG_NAME:=cids
PKG_VERSION:=1.0
PKG_RELEASE:=1

# Source settings (i.e. where to find the source codes)
# This is a custom variable, used below
SOURCE_DIR:=src/

include $(INCLUDE_DIR)/package.mk

# Package definition; instructs on how and where our package will appear in the overall configuration menu ('make menuconfig')
define Package/cids
	SECTION:=examples
	CATEGORY:=Examples
	DEPENDS:=+python3 +python3-pytz +scapy +python3-pip
	TITLE:=Capstone IDS Project for CY4930, Northeastern University
endef

# Package description; a more verbose description on what our package does
define Package/cids/description
	A simple intrusion detection system for IoT devices
endef

# Package preparation instructions; create the build directory and copy the source code. 
# The last command is necessary to ensure our preparation instructions remain compatible with the patching system.
define Build/Prepare
	mkdir -p $(PKG_BUILD_DIR)
	cp -r $(SOURCE_DIR)/* $(PKG_BUILD_DIR)
	$(Build/Patch)
endef

# Package build instructions; invoke the target-specific compiler to first compile the source file, and then to link the file into the final executable
define Build/Compile
	# We honestly don't need to do anything here
	#mv $(PKG_BUILD_DIR)/cids.py $(PKG_BUILD_DIR)/cids
endef

# Package install instructions; create a directory inside the package to hold our executable, and then copy the executable we built previously into the folder
define Package/cids/install
	$(INSTALL_DIR) $(1)/etc/capstone-ids
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cids-start $(1)/etc/capstone-ids
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/config.json $(1)/etc/capstone-ids
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/check-config.py $(1)/etc/capstone-ids
	$(INSTALL_DIR) $(1)/usr/bin
	ln -s /etc/capstone-ids/cids-start $(1)/usr/bin/cids
	$(INSTALL_DIR) $(1)/etc/init.d
	$(INSTALL_BIN) $(PKG_BUILD_DIR)/cids-service $(1)/etc/init.d/cids-service
endef

# This command is always the last, it uses the definitions and variables we give above in order to get the job done
$(eval $(call BuildPackage,cids))

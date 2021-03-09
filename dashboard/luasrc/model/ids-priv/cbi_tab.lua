m = Map("cbi_file", translate("First Tab Form"), translate("Please fill out the form below")) -- cbi_file is the config file in /etc/config
d = m:section(TypedSection, "info", "Part A of the form")  -- info is the section called info in cbi_file
a = d:option(Value, "name", "Name"); a.optional=false; a.rmempty = false;  -- name is the option in the cbi_file
return m

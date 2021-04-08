module("luci.controller.ids-priv.ids_tab", package.seeall)  --notice that new_tab is the name of the file new_tab.lua
    function index()
        entry({"admin", "ids_tab"}, firstchild(), "Alert Dashboard", 60).dependent=false  
        entry({"admin", "ids_tab", "settings"}, call("get_page", "/ids-priv/settings/"), "Config", 1)
        entry({"admin", "ids_tab", "ids_alerts"}, call("get_page", "/ids-priv/ids-alerts/"), "IDS Dashboard" , 2)
        entry({"admin", "ids_tab", "privacy_alerts"}, call("get_page", "/ids-priv/privacy-alerts/"), "Privacy Dashboard", 3)
        
        -- Entry for incoming requests to save config, request is sent from the JS in the .HTM file (formvalue set to JSON of config options)
       -- entry({"admin", "ids_tab", "config", "save"}, call("action_save_config")).sysauth=false
    end

    function get_page(route)
        local http = require("socket.http")
        local body, code, headers, status = http.request("localhost:5000"..route)
        luci.http.prepare_content("text/html")
        luci.http.write(body)
    end


    function action_save_config()
        -- Load content from POST
        local config, config_length = luci.http.content()
        if (not config or config_length < 1) then
            luci.http.status(400, "Bad Request")
            return
        end
    
        -- Get contents of HTTP POST as JSON
        local payload = luci.jsonc.parse(tostring(config))

        -- Open configuration file as JSON
        local conf = io.open("/etc/tinyHIPPO/config.json", 'r')
        local conf_contents = conf:read("*all")
        local configuration = {}
        if (conf_contents ~= nil and conf_contents ~= "") then
            configuration = luci.jsonc.parse(conf_contents)
        end

        -- Write over existing configuration if no errors reading files
        if (payload and payload.mac_addrs) then
            configuration.mac_addrs = payload.mac_addrs
        else 
            -- Send 400 back indicated bad input
            luci.http.status(400, "Bad value for configuration: " + tostring(payload))
            return
        end 

        -- Write JSON file, and make it *pretty*,
        conf:close()
        conf = io.open("/etc/tinyHIPPO/config.json", 'w')
        conf:write((string.gsub(luci.jsonc.stringify(configuration, true) .. "\n", "\\/", "/")))
        conf:close()

        -- Return OK so client side doesn't get upset
        luci.http.prepare_content("application/json")
        luci.http.write_json({ code = 200, payload=luci.jsonc.stringify(payload) })
    end

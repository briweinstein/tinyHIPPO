module("luci.controller.ids-priv.ids_tab", package.seeall)  --notice that new_tab is the name of the file new_tab.lua
    function index()
        entry({"admin", "ids_tab"}, firstchild(), "Alert Dashboard", 60).dependent=false  
        entry({"admin", "ids_tab", "config"}, template("ids-priv/config"), "Config", 1)
        entry({"admin", "ids_tab", "ids_alerts"}, template("ids-priv/ids_page"), "IDS Dashboard" , 2)  
        entry({"admin", "ids_tab", "priv_alerts"}, template("ids-priv/priv_page"), "Privacy Dashboard", 3) 
        
        -- Entry for incoming requests to save config, request is sent from the JS in the .HTM file (formvalue set to JSON of config options)
        -- sysauth is a little bugged, so I've disabled it for the time being (Cookie is sent, not being read)
        entry({"admin", "ids_tab", "config", "save"}, call("action_save_config")).sysauth=false
    end
    
    function action_save_config()
        local config, config_length = luci.http.content()
        if (not config or config_length < 1) then
            luci.http.status(400, "Bad Request")
            return
        end
    
        -- TODO: Save 'config' to fill here
        conf = io.open("/etc/ids_config/config.json", 'w')
        conf:write(config)
        conf:close()

        luci.http.prepare_content("application/json")
        luci.http.write_json({ code = 200 })
    end

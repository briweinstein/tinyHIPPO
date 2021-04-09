module("luci.controller.ids-priv.ids_tab", package.seeall)  --notice that new_tab is the name of the file new_tab.lua
    function index()
        entry({"admin", "ids_tab"}, firstchild(), "Alert Dashboard", 60).dependent=false  
        entry({"admin", "ids_tab", "settings"}, template("ids-priv/config"), "Config", 1)
        entry({"admin", "ids_tab", "ids_alerts"}, template("ids-priv/ids_page"), "IDS Dashboard" , 2)
        entry({"admin", "ids_tab", "privacy_alerts"}, template("ids-priv/priv_page"), "Privacy Dashboard", 3)
        
        -- Entry for incoming requests to save config, request is sent from the JS in the .HTM file (formvalue set to JSON of config options)
    end

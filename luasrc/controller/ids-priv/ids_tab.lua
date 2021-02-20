module("luci.controller.ids-priv.ids_tab", package.seeall)  --notice that new_tab is the name of the file new_tab.lua
 function index()
     entry({"admin", "ids_tab"}, firstchild(), "Alert Dashboard", 60).dependent=false  
     entry({"admin", "ids_tab", "ids_alerts"}, template("ids-priv/ids_page"), "IDS Dashboard" , 1)  
     entry({"admin", "ids_tab", "priv_alerts"}, template("ids-priv/priv_page"), "Privacy Dashboard", 2)  
end

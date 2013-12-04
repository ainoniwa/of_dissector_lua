Openflow 1.3 dissector
===============================
Openflow 1.3 protocol dissector for wireshark written by lua.

Refer to https://www.opennetworking.org/images/stories/downloads/sdn-resources/onf-specifications/openflow/openflow-spec-v1.3.2.pdf


Usage
=====

Windows
-------
#. Commentout the "disable_lua=true" in "%WIRESHARK%\\init.lua". (Probably configured)
#. of13.lua copy to under the "%WIRESHARK%\\plugins\\<version>" or "%APPDATA%\\Wireshark\\plugins".

e.g.: C:\\Program Files\\Wireshark\\plugins\\1.10.3\\of13.lua


Unix/Linux
----------
#. Commentout the "disable_lua=true" in /etc/wireshark/init.lua
#. of13.lua copy to "/usr/share/wireshark/plugins", "/usr/local/share/wireshark/plugins" or "$HOME/.wireshark/plugins".

e.g.: /home/user/.wireshark/plugins/of13.lua


Now
===
* Now, plugin can dissect the below.

 * OFPT_FEATURES_REPLY
 * OFPT_GET_CONFIG_REPLY
 * OFPT_SET_CONFIG
 * OFPT_PACKET_IN
 * OFPT_PACKET_OUT
 * OFPT_FLOW_MOD
 * OFPT_MULTIPART_REQUEST
 * OFPT_MULTIPART_REPLY

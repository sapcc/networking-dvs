networking-dvs
=============

Openstack L2 networking components for VMware DVS

L2 DVS Agent
-------------------
The DVS Agent uses the `vcenter_util.VCenter` object to monitor the VCenter for new VMs with a property-collector and then queries the Neutron RPC for the segmentation id and device-uuid.
If configures then the VLAN-ID in the DVS Port accordingly. DV-Switch and DVS-Port group remain untouched.

To ensure that the changes are applied to the correct port in the face of parallel changes outside of the control of the agent,
the `configVersion` attribute is tracked.


Firewall Driver
-------------------
Builds up on L2 DVS Agent and relies on the mapping of neutron-ids to DV-Switch & DVS-Port-ID established in `vcenter_util.VCenter` (and the L2 DVS Agent).
The given firewall rules are translated to tracking- and marking rules, which are then applied to the ports affected.
The rules compilations are taken from https://github.com/Mirantis/vmware-dvs



How to run
-------------------

Install on devstack

clone repo into /opt/stack
::
  cd ./networking-dvs
  python setup.py install


check and modify /etc/neutron/plugins/ml2/ml2_conf_vmware.ini
add dvs mechanism driver to /etc/neutron/plugins/ml2/ml2_conf.ini
add dvs firewall to /etc/neutron/plugins/ml2/ml2_conf.ini
::
  [securitygroup]
  firewall_driver = networking_dvs.plugins.ml2.drivers.mech_dvs.agent.dvs_firewall.DvsSecurityGroupsDriver

restart neutron server with dvs ml2 config
::
  /usr/local/bin/neutron-server --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini --config-file /etc/neutron/plugins/ml2/ml2_conf_vmware_dvs.ini


Start DVS agent
::
  /usr/local/bin/neutron-dvs-agent --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini --config-file /etc/neutron/plugins/ml2/ml2_conf_vmware_dvs.ini

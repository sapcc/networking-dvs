# networking-dvs
Openstack L2 networking components for VMware DVS


Install on devstack

clone repo into /opt/stack

cd ./networking-dvs

python setup.py install


check and modify /etc/neutron/plugins/ml2/ml2_conf_vmware.ini

add dvs mechanism driver to /etc/neutron/plugins/ml2/ml2_conf.ini

add dvs firewall to /etc/neutron/plugins/ml2/ml2_conf.ini

[securitygroup]
firewall_driver = networking_dvs.plugins.ml2.drivers.mech_dvs.agent.dvs_firewall.DvsSecurityGroupsDriver

restart neutron server with dvs ml2 config

/usr/local/bin/neutron-server --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini --config-file /etc/neutron/plugins/ml2/ml2_conf_vmware_dvs.ini


Start DVS agent

/usr/local/bin/neutron-dvs-agent --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini --config-file /etc/neutron/plugins/ml2/ml2_conf_vmware_dvs.ini
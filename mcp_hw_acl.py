# Script Header
# Id: mcp_hw_acl, v 1
# Copyright (c) 2006 Cisco Systems, Inc.
#
# Name: mcp_hw_acl
#
# Purpose: Automation of ACL smoke test on MCP.
#          This script has the following test cases -
#               * verify standard ACL functionality
#               * verify extended ACL functionality
#               * verify IPv6 ACL functionality
#
# Author:
#
# Topology:One target platform with a router conected to each
# of its two interfaces
#
#   +-----------+     +-----------------+     +-------------+
#   | Router1   |-----| Unit Under Test |-----|  Router2    |
#   +-----------+     +-----------------+     +-------------+
# Synopsis:
#  mcp_hw_acl <-uut <target device> -uutInt1 <int> -uutInt2 <int> \
#    -rtr1 <router 1> -rtr2 <router 2> -rtr1Int <int> -rtr2Int <int>>
#
# Sample Usage:
#
# Pass/Fail Criteria:
#
# Notes:
#
# Known Bugs:
#
# Todo:
#
# See Also:
#
# End of Header
#
#######################################################################
###                 TEST SCRIPT INITIALIZATION BLOCK                ###
#######################################################################
#
# AtsAuto package would include all of the relevant packages
# required for ATS Automation: Tclx, Expect, Atslog, Cisco, Csccon, Control,
#                              Parser, Catlib, AEtest, Autoeasy, Async
#
# Following needed for pre/post router check
#
# Needs to be reset for each run because of AM
#
# Similarly, specify the optional arguments to the script
# along with the argument type here
#
# Procedure Header
# Name:
#   config_router
#
# Purpose:
#   Configure the router with given configs
#
# Synopsis:
#   config_router <router_name> <configs>
#
# Arguments:
#  rtr_name - Name of the router
#  config_arr - Router configuration
#
# Return Values:
#    0      - Configuration succeeded
#  configErr  - Number of config errors
#
# Description:
#  This procedure configures the router with a given
#  config array and checks whether there are any
#  configuration errors
################################################################

from ats.aetest import CommonSetup
from ats.topology import loader
from ats.log.utils import banner,title
from ats import aetest
from ats import topology
from csccon import Csccon
import re,pdb,time
import string
import os,sys
import argparse
import logging
import pprint

logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

parameters = {}
mandatory_parameters = {'uut1', 'rtr1', 'rtr2', 'uutInt1', 'uutInt2','rtr1Int', 'rtr2Int'}

#global variable
uutInt1IPv6 = '1::2'
uutInt2IPv6 = '3::2'
rtr1IPv6 = '1::1'
rtr2IPv6 = '3::1'
rtr2lo101IPv6 = '101::101'

#######################################################################
###                          PING TEST                              ###
#######################################################################

def ping_test(device, ip, ipv6= False):
    ping_flag = "fail"
    ping_try = 5
    while (ping_flag == "fail" and ping_try > 0):
        logger.info("Ping Attempt : %d" % (5 - ping_try + 1))
        try:
            if ipv6 == True:
                result = device.execute("ping ipv6 "+ip)
                ping_res = re.search('Success rate is (\d+)',result)
            else:
                result = device.execute("ping " +ip)
                ping_res = re.search('Success rate is (\d+)',result)
            if (int(ping_res.group(1)) >= 80):
                ping_flag = "success"
                break
            else:
                ping_flag = "fail"
                ping_try = ping_try - 1
        except csccon.exceptions.InvalidCliError as e:
            logger.error("Invalid Ping Command %s" % e)
            ping_flag = "fail"
            break
        except Exception as e:
            logger.error("Unknown Error....Exiting!!!")
            ping_flag = "fail"
            break
    if (ping_flag == "success"):
        return 1
    else:
        return 0


#######################################################################
###                      COMMON SETUP SECTION                       ###
#######################################################################

class ScriptCommonSetup(aetest.CommonSetup):

    logger.info(banner('Executing common_setup section'))
    @aetest.subsection
    def validate_params(self, testbed, **parameters):
        for parameter in parameters:
            assert parameter in mandatory_parameters, \
            self.failed("Missing parameter % from mandatory_parameters" % parameter)

    @aetest.subsection
    def get_testbed_info(self, uut1, rtr1, rtr2, uutInt1, uutInt2, rtr1Int, testbed, **parameters):

        logger.info('Connecting to Router')
        uut1 = testbed.devices[uut1]
        rtr1 = testbed.devices[rtr1]
        rtr2 = testbed.devices[rtr2]

        self.parent.parameters['uut1'] = uut1
        self.parent.parameters['rtr1'] = rtr1
        self.parent.parameters['rtr2'] = rtr2

        uut1.connect()
        assert uut1.connected, "Could not connect to device: %" % uut1.name
        rtr1.connect()
        assert rtr1.connected, "Could not connect to device: %" % rtr1.name
        rtr2.connect()
        assert rtr2.connected, "Could not connect to device: %" % rtr2.name


        uut1.execute("show version")

        logger.info("Configuring uut1 Interfaces IP address")
        try:
            uut1_config = '''
                ip routing
                ipv6 unicast-routing
                ipv6 cef distributed
                !
                ipv6 access-list smoke-ipv6
                permit icmp any host {} log-input
                permit icmp any any nd-ns
                permit icmp any any nd-na
                deny icmp any any log-input
                !
                interface {}
                ip address 1.1.1.254 255.255.255.0
                ipv6 address {}
                ipv6 nd ra suppress
                no shut
                !
                interface {}
                ip address 3.3.3.254 255.255.255.0
                ipv6 address {}
                ipv6 nd ra suppress
                no shut
                !
                ip route 101.101.101.101 255.255.255.255 3.3.3.3
                ipv6 route ::/0 {}
            '''.format((rtr2lo101IPv6),(uutInt1),(uutInt1IPv6 +"/64"),(uutInt2),(uutInt2IPv6+'/64'),(rtr2IPv6))
            uut1.configure(uut1_config)

        except Exception as e:
            logger.info("uut1 configuration error")
            self.failed(goto=['exit'])

        logger.info("Configuring rtr1 Interfaces IP address")
        try:
            rtr1_Config = '''
            ip routing
            ipv6 unicast-routing
            ipv6 cef
            !
            interface {}
            ip address 1.1.1.1 255.255.255.0
            ipv6 address {}
            ipv6 nd ra suppress
            no shut
            !
            ip route 101.101.101.0 255.255.255.0 1.1.1.254
            ip route 3.3.3.0 255.255.255.0 1.1.1.254
            ipv6 route ::/0 {}
            '''.format((rtr1Int),(rtr1IPv6 +"/64"),(uutInt1IPv6))
            rtr1.configure(rtr1_Config)

        except Exception as e:
            logger.info("rtr1 configuration error")
            self.failed(goto=['exit'])

        logger.info("Configuring rtr2 Interfaces IP address")
        try:
            rtr2_config = '''
            ip routing
            ipv6 unicast-routing
            ipv6 cef
            !
            interface {}
            ip address 3.3.3.3 255.255.255.0
            ipv6 address {}
            ipv6 nd ra suppress
            no shut
            !
            interface Loopback101
            ip address 101.101.101.101 255.255.255.255
            ipv6 address {}
            !
            ip route 1.1.1.0 255.255.255.0 3.3.3.254
            ipv6 route ::/0 {}

            '''.format((rtr1Int),(rtr2IPv6+'/64'),(rtr2lo101IPv6+'/64'),(uutInt2IPv6))
            rtr2.configure(rtr2_config)

        except Exception as e:
            logger.info("rtr2 configuration error")
            self.failed(goto=['exit'])

        logger.info('Setup configure sccessfully')

#######################################################################
###                          TESTCASE BLOCK                         ###
#######################################################################

class IP_Connectivity(aetest.Testcase):
    uid = "IP_Connectivity"
    @aetest.test
    def section_test(self,uut1,rtr1,rtr2):
        logger.info(banner("IP Connectivity"))
        logger.info("Verifying ping before ACL configuration")

        target_ip_1 = "101.101.101.101"
        target_ip_2 = "3.3.3.3"

        #router per_check need to here

        uut1.execute("set platform software trace all debug")

        logger.info("Verify IP connectivity between routers")

        time.sleep(10)

        #Verify IP connectivity between routers
        #ipv4 ping test
        if not ping_test(rtr1, target_ip_1, ipv6 = False):
            self.failed('Ping failed between rtr1 and rtr2')
        else:
            logger.info('Connectivity between rtr1 and rtr2 successfull')

        if not ping_test(rtr1, target_ip_2, ipv6 = False):
            self.failed('Ping failed between rtr1 and rtr2')
        else:
            logger.info('Connectivity between rtr1 and rtr2 successfull')

        #ipv6 ping test
        if not ping_test(rtr1, rtr2IPv6, ipv6 = True):
            self.failed('ICMP IPv6 ping test failed between rtr1 and rtr2')
        else:
            logger.info('ipv6 connectivity between rtr1 and rtr2 successfull')

        if not ping_test(rtr1, rtr2lo101IPv6, ipv6 = True):
            self.failed('ICMP IPv6 ping test failed between rtr1 and rtr2')
        else:
            logger.info('ipv6 connectivity between rtr1 and rtr2 successfull')

        #neighbors check
        try:
            uut1.execute("show ipv6 neighbors")
            rtr1.execute("show ipv6 neighbors")
            rtr2.execute("show ipv6 neighbors")
        except Exception as e:
            logger.info("IPv6 Connectivity Failure")

        logger.info(banner("ACL configuration successfull"))

class Standard_ACL(aetest.Testcase):
    uid = "Standard_ACL"
    @aetest.test
    def section_test(self,uut1,rtr1,rtr2,uutInt1):
        logger.info(banner("Standard ACL"))
        logger.info("Verifying Standard ACL Functionality")

        #configuring standard ACL
        try:
            uut1_config = '''
            access-list 1 deny any
            interface {}
            ip access-group 1 in
            '''.format((uutInt1))
            uut1.configure(uut1_config)

        except Exception as e:
            self.failed("Config Error when configuring Standard ACL")


        #The following commands are added for debugging

        uut1.execute("show run")
        uut1.execute("show platform software access-list rp active statistics")
        uut1.execute("show platform software access-list fp active statistics")
        time.sleep(10)
        uut1.execute("show interface %s" % (uutInt1))

        #########comment (need to check with team)
        #########deb platform hardware cpp feature acl datapath ip

        #Ping rtr2 from rtr1 and ensure ping fails

        target_ip = "101.101.101.101"
        ping_status_ipv4 = rtr1.execute("ping " +target_ip )
        output_value_ipv4 = re.search('Success rate is (\d*)',ping_status_ipv4)
        if int(output_value_ipv4.group(1)) == 0:
            logger.info("Ping result is 0")
        else:
            self.failed("Ping failed")

        time.sleep(10)
        uut1.execute("show interface {}".format(uutInt1))

        #Ensure Match counters on the deny ACL
        showACL = uut1.execute("show ip access-list 1")
        ace_match_count = re.search('(\d) matches',showACL)
        if int(ace_match_count.group(1)) in range(1,11):
            if int(ace_match_count.group(1)) > 5:
                logger.info("Match count for deny ACL is {} instead of 5".format(ace_match_count.group(1)))
        else:
            self.failed("Cannot get match count for deny ace")

        #Unbind ACL from interface and ensure Ping Succeeds
        try:
            uut1_config = '''
            interface {}
            no ip access-group 1 in
            '''.format((uutInt1))
            uut1.configure(uut1_config)
        except Exception as e:
            self.failed("Config Error when unbinding ACL from interface")

        #The following commands are added for debugging
        uut1.execute("show platform software access-list rp active statistics")
        uut1.execute("show platform software access-list fp active statistics")

        #Ensure Ping succeeds
        target_ip = "101.101.101.101"
        if not ping_test(rtr1, target_ip, ipv6 = False):
            self.failed('Ping fails after unbinding ACL')
        else:
            logger.info('ping successfull')

    def cleanup(self):
        try:
            uut1_config = '''
            no ip access-list standard 1
            interface {}
            no ip access-group 1 in
            '''.format((uutInt1))
            uut1.configure(uut1_config)
        except Exception as e:
            self.failed("Config Error when unconfiguring Standard ACL")

class Extended_ACL(aetest.Testcase):
    uid = "Extended_ACL"
    @aetest.test
    def section_test(self,uut1,rtr1,rtr2,uutInt2):
        logger.info(banner("Extended ACL"))
        logger.info("Verifying Extended ACL functionality")

        try:
            uut1_config = '''
            access-list 101 permit ip any host 101.101.101.101
            interface {}
            ip access-group 101 out
            '''.format((uutInt2))
            uut1.configure(uut1_config)
        except Exception as e:
            self.failed("Config Error when configuring Extended ACL")

        #The following commands are added for debugging
        uut1.execute("show platform software access-list rp active statistics")
        uut1.execute("show platform software access-list fp active statistics")

        #Ping rtr2 IP 3.3.3.3 from rtr1 and ensure ping fails
        target_ip = "3.3.3.3"
        ping_status_ipv4 = rtr1.execute("ping " +target_ip )
        output_value_ipv4 = re.search('Success rate is (\d+)',ping_status_ipv4)
        if int(output_value_ipv4.group(1)) >0:
            self.failed("Ping allowed while it must have been denied due to default deny at the end")

        #Ping rtr2 loopback 101.101.101.101 and ensure ping passes
        target_ip = "101.101.101.101"
        if not ping_test(rtr1, target_ip, ipv6 = False):
            self.failed('Ping failed inspite of permit ACE')
        else:
            logger.info('ping successfull')

        time.sleep(10)
        #verify ACL match counters
        showACL = uut1.execute("show ip access-list 101")
        print(showACL)
        ace_match_count = re.search('(\d) matches',showACL)
        print(ace_match_count)
        if int(ace_match_count.group(1)) in range(1,11):
            if int(ace_match_count.group(1)) != 5:
                logger.info("Cannot get match count for deny ace {}".format(ace_match_count.group(1)))
            else:
                logger.info("Ping failed inspite of permit ACE")

        #Unconfigure ACL and ensure Ping succeeds to rtr2IP
        try:
            uut1_config ='''
            interface {}
            no ip access-group 101 out
            no access-list 101 permit ip any host 101.101.101.101
            '''.format((uutInt2))
            uut1.configure(uut1_config)
        except Exception as e:
            logger.info("Config Error when unconfiguring extended ACL")
            self.failed(goto=['exit'])

        #The following commands are added for debugging
        uut1.execute("show platform software access-list rp active statistics")
        uut1.execute("show platform software access-list fp active statistics")

        #Ensure Ping succeeds
        target_ip = "3.3.3.3"
        if not ping_test(rtr1, target_ip, ipv6 = False):
            self.failed('Ping fails after unconfiguring ACL')
        else:
            logger.info('ping successfull')

class IPv6_ACL(aetest.Testcase):
    uid = "IPv6_ACL"
    @aetest.test
    def section_test(self, uut1, rtr1, rtr2, uutInt2):

        logger.info(banner("IPv6 ACL"))
        logger.info("Verifying IPv6 ACL functionality")

        acl_name = "smoke-ipv6"
        acl_cmd = "show ipv6 access-list smoke-ipv6"

        try:
            uut1_config ='''
            interface {}
            ipv6 traffic-filter smoke-ipv6 out
            '''.format((uutInt2))
            uut1.configure(uut1_config)

        except Exception as e:
            logger.info("Config Error when configuring Extended ACL")
            self.failed(goto=['exit'])

        #The following command is added for debugging
        uut1.execute("show platform software access-list rp active statistics")
        uut1.execute("show platform software access-list fp active statistics")
        uut1.execute("show ipv6 access-list")
        uut1.execute("show log")

        time.sleep(10)

        permit_pkt = 18
        deny_pkt = 8

        rtr2.execute("show log")

        #Ping the rtr2 IP in the deny list from rtr1 and ensure ping fails

        ping_status_ipv4 = rtr1.execute("ping ipv6 " +rtr2IPv6+' repeat 8')
        output_value_ipv4 = re.search('Success rate is (\d+)',ping_status_ipv4)
        if int(output_value_ipv4.group(1)) > 0 :
            self.failed("IPv6 Ping should fail for the denied IP address")

        uut1.execute("show log")
        #Ping rtr2 loopback and ensure ping passes
        ping_status_ipv4 = rtr1.execute("ping ipv6 " + rtr2lo101IPv6+' repeat 18')
        output_value_ipv4 = re.search('Success rate is (\d+)',ping_status_ipv4)
        if int(output_value_ipv4.group(1)) != 100:
            self.failed("Ping failed for the permitted ip address")

        uut1.execute("show log")
        time.sleep(30)

        #The following commands are added for debugging
        uut1.execute("show platform software access-list rp active statistics")
        uut1.execute("show platform software access-list fp active statistics")

        #set acl_val [router_show -device  $uut -cmd $acl_cmd]
        acl_val = uut1.execute(acl_cmd)

        matches = re.findall('(\d+) matches',acl_val)

        if int(matches[0]) == permit_pkt and int(matches[1]) == deny_pkt:
            logger.info("show ipv6 access-list stats is correct")
        else:
            logger.info("show ipv6 access-list stats is wrong")
            logger.info("Expected {} permit matches & {} deny matches".format(permit_pkt,deny_pkt))
            self.failed("Got permit:{} deny:{}".format(matches[0],matches[1]))


        uut1.execute("request platform software trace rotate all")
        time.sleep(10)

        try:
            uut1_config = '''
            interface {}
            no ipv6 traffic-filter smoke-ipv6 out
            '''.format((uutInt2))
            uut1.configure(uut1_config)
        except Exception as e:
            logger.info("Config Error when unconfiguring Standard ACL")

#######################################################################
##                    COMMON CLEANUP SECTION                        ###
#######################################################################

class CommonCleanup(aetest.CommonCleanup):

    @aetest.subsection
    def section_cleanup(self, uut1, rtr1, rtr2, uutInt2, uutInt1, rtr1Int, rtr2Int):

        logger.info("In common_cleanup section")
        uut1_config ='''
        no ip access-list standard 1
        no ip access-list ext 101
        no ipv6 access-list smoke-ipv6
        interface {}
        no ip address 1.1.1.254 255.255.255.0
        no ipv6 address {}
        no ip access-group 1 in
        shut
        interface {}
        no ip address 3.3.3.254 255.255.255.0
        no ipv6 address {}
        no ip access-group 101 out
        shut
        no ip route 101.101.101.101 255.255.255.255 3.3.3.3
        no ipv6 route ::/0 {}
        '''.format((uutInt1),(uutInt1IPv6 +"/64"),(uutInt2),(uutInt2IPv6 +"/64"),(rtr2IPv6))
        uut1.configure(uut1_config)

        rtr1_Config ='''
        interface {}
        no ip address 1.1.1.1 255.255.255.0
        no ipv6 address {}
        shut
        no ip route 101.101.101.0 255.255.255.0 1.1.1.254
        no ip route 3.3.3.0 255.255.255.0 1.1.1.254
        no ipv6 route ::/0 {}
        '''.format((rtr1Int),(rtr1IPv6+"/64"),(uutInt1IPv6))
        rtr1.configure(rtr1_Config)

        rtr2_Config ='''
        interface {}
        no ip address 3.3.3.3 255.255.255.0
        no ipv6 address {}
        shut
        interface Loopback101
        no ip address 101.101.101.101 255.255.255.255
        no ipv6 address {}
        no ip route 1.1.1.0 255.255.255.0 3.3.3.254
        no ipv6 route ::/0 {}
        '''.format((rtr2Int),(rtr2IPv6+"/64"),(rtr2lo101IPv6+"/64"),(uutInt2IPv6))
        rtr2.configure(rtr2_Config)
        
        logger.info(banner("Cleanup section successfull"))

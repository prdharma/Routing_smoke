# Script Header
# $Id: mcp_hw_qos
# Copyright (c) 2006 Cisco Systems, Inc.
#Name: mcp_hw_qos
#
# Purpose: Automation of QoS smoke test on MCP.
#          This script has the following test cases - 
#               * verify IP Connectivity before QoS test
#               * verify QoS ingress classification and marking
#               * verify QoS egress classification and marking
#               * verify QoS input and output service-policies
#               * verify QoS classification works after editing ACL
#
#               Please refer to the smoke test wishlist page for details:
#               http://bcnl01.cisco.com/twiki/bin/view/MCP/SmokeTestDescription
#
# Author: 
#         
# Topology: One target platform with a router conected to each of its two interfaces
#
#   +-----------+     +-----------------+     +-------------+
#   | Router1   |-----| Unit Under Test |-----|  Router2    |
#   +-----------+     +-----------------+     +-------------+
# Synopsis:
#  mcp_hw_qos <-uut1 <target device> -rtr1 <router 1> -rtr2 <router 2> \
#  	-rtr1Int <int> -rtr2Int <int>>
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
#######################################################################
###                 TEST SCRIPT INITIALIZATION BLOCK                ###
#######################################################################

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
mandatory_parameters = {'uut1', 'rtr1', 'rtr2', 'uutInt1', 'uutInt2', 'rtr1Int', 'rtr2Int'}

#The below testcase are depend in IP_Connectivity_qos.
#MCP-ST-IFT-006,MCP-ST-IFT-007,MCP-ST-IFT-008 and MCP-ST-IFT-009
#Note : For single tc vaildation need to execute before IP_Connectivity_qos.

#global variable
uutInt1IP = '1.1.1.254'
uutInt2IP = '3.3.3.254'
rtr1IP = '1.1.1.1'
rtr2IP = '3.3.3.3'
rtr2lo101IP = '101.101.101.101'


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
    def get_testbed_info(self, uut1, rtr1, rtr2, uutInt1, uutInt2, rtr1Int, rtr2Int, testbed, **parameters):
    
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
        
        #Grab the pre router check info before we config the UUT
        
        uut1.execute("show version")
        
        #
        logger.info("Configuring uut1 Interfaces IP address")
        try:
            uut1_config = '''
            ip routing
            #ip cef  
            no cdp run
            !
            interface {}
            ip address {} 255.255.255.0
            no shut
            no cdp enable
            exit
            !
            no arp {}
            !
            interface {}
            ip address {} 255.255.255.0
            no shut
            no cdp enable
            exit
            !
            ip route {} 255.255.255.255 {}
            !
            no arp {}
            '''.format((uutInt1),(uutInt1IP),(rtr1IP),(uutInt2),(uutInt2IP),(rtr2lo101IP),(rtr2IP),(rtr2IP))
            uut1.configure(uut1_config)
        except Exception as e:
            logger.info("uut1 configuration error")
            self.failed(goto=['exit'])
           
        logger.info("Configuring rtr1 Interfaces IP address")   
        try:
            rtr1_Config = '''
            ip cef
            !
            interface {}
            ip address {} 255.255.255.0
            no shut
            no cdp enable
            no keepalive
            exit
            !
            ip route 0.0.0.0 0.0.0.0 {}
            !
            no arp {}
            '''.format((rtr1Int),(rtr1IP),(uutInt1IP),(uutInt1IP))
            rtr1.configure(rtr1_Config)
        except Exception as e:              
            logger.info("rtr1 configuration error")
            self.failed(goto=['exit'])        
           
        logger.info("Configuring rtr2 Interfaces IP address")
        
        try:
            rtr2_config = '''
            ip cef
            !
            interface {}
            ip address {} 255.255.255.0
            no shut
            no cdp enable
            no keepalive
            exit
            !
            interface Loopback101
            ip address {} 255.255.255.255
            !
            ip route 0.0.0.0 0.0.0.0 {}
            !
            no arp {}
            '''.format((rtr2Int),(rtr2IP),(rtr2lo101IP),(uutInt2IP),(uutInt2IP))
            rtr2.configure(rtr2_config)
        except Exception as e:
            logger.info("rtr2 configuration error")
            self.failed(goto=['exit'])
            
        logger.info(banner('Setup configuration sccessfull'))
        
 
#######################################################################
###                          Ping test                              ###
#######################################################################

def ping_test(device, ip, count = '5', ipv6= False):
    ping_flag = "fail"
    ping_try = 5
    while (ping_flag == "fail" and ping_try > 0):
        logger.info("Ping Attempt : %d" % (5 - ping_try + 1))
        try:
            if ipv6 == True:
                result = device.execute("ping ipv6 "+ ip +" repeat "+count)
                ping_res = re.search('Success rate is (\d+)',result)
            else:
                result = device.execute("ping " +ip +" repeat "+count)
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
###                          TESTCASE BLOCK                         ###
#######################################################################


class IP_Connectivity_qos (aetest.Testcase):
    uid = "IP_Connectivity_qos"
    @aetest.test
    def section_test(self, uut1, rtr1, rtr2):
        logger.info(banner("Verify IP Connectivity before QoS test"))
        logger.info("Verifying ping before QoS configuration")
        logger.info(title('Setup'))
        
        # Verify IP connectivity between routers
        if not ping_test(rtr1, rtr2IP, ipv6 = False):
            self.failed('Connectivity failure between rtr1 and rtr2')
        else:
            logger.info('ping successfull')

class MCP_ST_IFT_006(aetest.Testcase): 
    uid = "MCP_ST_IFT_006"           
    @aetest.test
    def section_test(self, uut1, rtr1, rtr2, uutInt1, rtr2Int):
        logger.info(banner("QoS Input Classification and Marking"))
        logger.info("Verify input 'match-any' classification and precedence marking")
        
        precValue = "3"
        
        #configuring access list
        try:
            uut1_config = '''
            class-map match-any ip
            match any
            !
            policy-map inputPolicy
            class ip
            set ip prec {}
            !
            interface {}
            service-policy input inputPolicy
            '''.format((precValue),(uutInt1))
            uut1.configure(uut1_config)
                    
            rtr2_config = '''
            access-list 121 permit ip any any precedence {}
            !
            interface {}
            ip access-group 121 in
            '''.format((precValue),(rtr2Int))
            rtr2.configure(rtr2_config)
        
            logger.info(banner("acl configuration successfull"))
            
        except Exception as e:
            self.failed("acl configuration error ")       
                
        #Verifying ping goes through to rtr2IP
        if not ping_test(rtr1, rtr2IP, count = '10', ipv6 = False):
            self.failed('Test failed: Packet marking not working')
        else:
            logger.info('Packets getting classified and marked correctly')
        
                
        uut1.execute("show policy-map interface " + uutInt1)

        
        #unconfiguring the policy map and access lists
        try:
            uut1_config = '''
            interface {}
            no service-policy input inputPolicy
            !
            no policy-map inputPolicy
            no class-map ip       
            '''.format((uutInt1))
            uut1.configure(uut1_config)
            
            rtr2_config ='''
            interface {}
            no ip access-group 121 in
            !
            no access-list 121
            '''.format((rtr2Int))
            rtr2.configure(rtr2_config)
        
            logger.info(banner("unconfiguring the policy map and access lists successfull"))
            
        except Exception as e:
            self.failed("unconfiguring error")
     
class MCP_ST_IFT_007(aetest.Testcase):
    uid = "MCP_ST_IFT_007"
    @aetest.test
    def section_test(self, uut1, rtr1, rtr2, uutInt2, rtr2Int):
        logger.info(banner("QoS Output Classification and Marking"))
        logger.info("Verify output acl classification and dscp marking")
        logger.info(title('Setup'))
        
        dscpValue = "46"
        
        #configuring access list
        try:
            uut1_config = '''
            access-list 103 permit ip any any
            !
            class-map match-all acl103
            match access-group 103
            !
            policy-map outputPolicy
            class acl103
            set ip dscp {}
            !
            interface {}
            service-policy output outputPolicy
            '''.format((dscpValue),(uutInt2))
            uut1.configure(uut1_config)
            
            rtr2_config = '''
            access-list 121 permit ip any any dscp {}
            !
            interface {}
            ip access-group 121 in
            '''.format((dscpValue),(rtr2Int))
            rtr2.configure(rtr2_config)
            
            logger.info(banner("acl configuration successfull"))
            
        except Exception as e:
            self.failed("acl configuration error")
        
        #Verifying ping goes through to rtr2IP
        if not ping_test(rtr1, rtr2IP, count = '10', ipv6 = False):
            self.failed("test failed: Packet marking not working")
        else:
            logger.info("Packets getting classified and marked correctly")
   
        #unconfiguring the policy map and access lists
        try:
            uut1_config = '''
            interface {}
            no service-policy output outputPolicy
            !
            no policy-map outputPolicy
            no class-map acl103
            !
            no access-list 103
            '''.format((uutInt2))
            uut1.configure(uut1_config)
                
            rtr2_config = '''
            interface {}
            no ip access-group 121 in
            !
            no access-list 121
            '''.format((rtr2Int))
            rtr2.configure(rtr2_config)
            
            logger.info(banner("unconfiguring the policy map and access lists scuccessfull"))
            
        except  Exception as e:
            self.failed("unconfiguring error")        
           
class MCP_ST_IFT_008(aetest.Testcase):
    uid = "MCP_ST_IFT_008"
    @aetest.test
    def section_test(self, uut1, rtr1, rtr2, uutInt1, uutInt2, rtr2Int):
        logger.info(banner("QoS Classification and Marking - Multiple service-policies"))
        logger.info("Verify ip precedence and dscp classification and marking")
        logger.info(title('Setup'))
            
        precValue = "1"
        dscpValue = "34"
        
        #configuring access list
        try:    
            uut1_config = '''
            access-list 103 permit ip any any
            !
            class-map match-all acl103
            match access-group 103
            !
            class-map match-all prec1
            match ip precedence {} 
            !
            policy-map inputPolicy
            class acl103
            set ip prec {}
            !
            policy-map outputPolicy
            class prec1
            set ip dscp {}
            !
            interface {}
            service-policy input inputPolicy
            '''.format((precValue),(precValue),(dscpValue),(uutInt1))
            uut1.configure(uut1_config)
            
            #FIXME - Temporarily put a 10 second sleep between configuring input and output serive-policies   
        
            time.sleep(10)
            
            uut1_config = '''
            interface {}
            service-policy output outputPolicy
            '''.format((uutInt2))
            uut1.configure(uut1_config)
            
            rtr2_config ='''
            access-list 121 permit ip any any dscp {}
            !
            interface {}
            ip access-group 121 in
            '''.format((dscpValue),(rtr2Int))
            rtr2.configure(rtr2_config)
            
            logger.info(banner("acl configuration successfull"))
        
        except Exception as e:
            self.failed("acl configuration error")
            
        #Verifying ping goes through to rtr2IP    
        if not ping_test(rtr1, rtr2IP, count = '10', ipv6 = False):
            self.failed("test failed: Packet marking not working")
        else:
            logger.info("Packets getting classified and marked correctly")
            
        uut1.execute("show policy-map interface " + uutInt1)
        uut1.execute("show policy-map interface " + uutInt2)
        
        #unconfiguring the policy map and access lists
        try:
            uut1_config ='''
            interface {}
            no service-policy input inputPolicy
            !
            interface {}
            no service-policy output outputPolicy
            !
            no policy-map outputPolicy
            no policy-map inputPolicy
            no class-map prec1
            no class-map acl103
            !
            no access-list 103 
            '''.format((uutInt1),(uutInt2))
            uut1.configure(uut1_config)
            
            rtr2_config ='''
            interface {}
            no ip access-group 121 in
            !
            no access-list 121
            '''.format((rtr2Int))
            rtr2.configure(rtr2_config)
            
            logger.info("unconfiguration scuccessfull")
            
        except Exception as e:
            self.failed("unconfiguration error")

class MCP_ST_IFT_009(aetest.Testcase):
    uid ="MCP_ST_IFT_009"
    @aetest.test
    def section_test(self, uut1, rtr1, rtr2, uutInt2, rtr2Int):
        logger.info(banner("QoS ACL filter edit"))
        logger.info("Verify classification works after editing ACL")
        
        dscpValue = "46"
        
        #configuring access list
        try:
            uut1_config = '''
            access-list 103 permit ip any any
            !
            class-map match-all acl103
            match access-group 103
            !
            policy-map outputPolicy
            class acl103
            set ip dscp {}
            !
            interface {}
            service-policy output outputPolicy
            '''.format((dscpValue),(uutInt2))
            uut1.configure(uut1_config)

            rtr2_config ='''
            access-list 121 permit ip any any dscp {}
            !
            interface {}
            ip access-group 121 in
            '''.format((dscpValue),(rtr2Int))
            rtr2.configure(rtr2_config)

            uut1_config ='''
            no access-list 103 permit ip any any
            access-list 103 permit ip host {} host {}
            '''.format((rtr1IP),(rtr2IP))
            uut1.configure(uut1_config)
            
        except Exception as e:
            self.failed("Configuration error")

        #Verifying ping goes through to rtr2IP
        if not ping_test(rtr1, rtr2IP, count = '10', ipv6 = False):
            self.failed("test failed: Packet marking not working")
        else:
            logger.info("Packets getting classified and marked correctly")
            
        #unconfiguring the policy map and access lists
        try:
            uut1_config ='''
            interface {}
            no service-policy output outputPolicy
            !
            no policy-map outputPolicy
            no class-map acl103
            !
            no access-list 103
            '''.format((uutInt2))
            uut1.configure(uut1_config)

            rtr2_config ='''
            interface {}
            no ip access-group 121 in
            !
            no access-list 121  
            '''.format((rtr2Int))
            rtr2.configure(rtr2_config)
                
            logger.info("policy map and access lists configuration scuccessfull")
                
        except Exception as e:
            logger.info("configuration error")       

#######################################################################
##                    COMMON CLEANUP SECTION                        ###
#######################################################################         

class CommonCleanup(aetest.CommonCleanup):
    @aetest.subsection
    def section_cleanup(self, uut1, rtr1, rtr2, uutInt2, uutInt1, rtr1Int, rtr2Int):
    
        logger.info(banner("common_cleanup section"))
        
       # unconfiguration section            
       # unconfiguration section            
        try:
            logger.info("uut1 unconfiguration")        
            uut1_Unconfig = '''
            interface {}
            no ip address
            shut
            exit
            !
            interface {}
            no ip address
            shut
            exit
            !
            no ip route {} 255.255.255.255 {}
            '''.format((uutInt1),(uutInt2),(rtr2lo101IP),(rtr2IP))
            uut1.configure(uut1_Unconfig)
        except Exception as e:
            self.failed("rtr2 configuration error")         
                          
        try:
            logger.info("rtr1 unconfiguration")         
            rtr1_unconfig ='''
            interface {}
            no ip address
            shut
            exit
            !
            no ip route 0.0.0.0 0.0.0.0 {}
            '''.format((rtr1Int),(uutInt1IP))
            rtr1.configure(rtr1_unconfig)
        except Exception as e:    
            self.failed("rtr1 unconfiguration error")
        
        try:
            logger.info("rtr2 unconfiguration") 
            rtr2_unconfig ='''
            interface {}
            no ip address
            shut
            exit
            !
            interface Loopback101
            no ip address {} 255.255.255.255
            no interface Loopback101
            !
            no ip route 0.0.0.0 0.0.0.0 {}
            '''.format((rtr2Int),(rtr2lo101IP),(uutInt2IP))
            rtr2.configure(rtr2_unconfig)
        except Exception as e:    
            self.failed("rtr2 unconfiguration error")
            
        logger.info("unconfiguration successfull")

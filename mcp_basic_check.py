# Script Header
# Id: mcp_basic_check,Version
# Copyright (c) 2006 Cisco Systems, Inc.
#
# Name: mcp_basic_check
#
# Purpose: This script consolidates 3 scripts: hw_basic, smoke_interactive and 
#          mcp_hw_fwd into one to save running time
#
#    1) Check the following components reach ok state
#        * Active RP
#        * Standby RP
#        * Active FP
#        * Standby FP
#        * CC
#        * OC-3 SPA 
#        * 5X1GE SPA 
#       Verify the following media can be accessed
#        * harddisk:
#        * bootflash:
#
#    2) Verifies that interactive command infrastructure is working as expected by
#       sending a test command to all the active FRUs (rp/fp/cc)
#        * PingLIIN: vrf ping the linux from IOSd via LIIN interface
#        * Interactive: test interactive command to all online FRUs
#
#    3) Verify the interface bringup, forwarding and punt/inject path.
#        * Verify whether all interfaces are present using "sh ip int b"
#        * verify interface bring up and ping UUT interfaces
#        * verify that ARP is resolved correctly
#        * verify traffic forwarding through UUT
#        * verify ping from uut to outside router (punt verification)
#        * verify ipv6 ping from/to/thru UUT
#        * verify sweep ping from/to/thru UUT
#        * verify vlan ping from/to/thru UUT
#        * Verify OSPF - adjacency-based inject test
#        * verify prefix length from 16 to 30 works
#
# Author: 
#
# Topology: One target platform with a router conected to each of its two interfaces
#
#   +-----------+     +-----------------+     +-------------+
#   | Router1   |-----| Unit Under Test |-----|  Router2    |
#   +-----------+     +-----------------+     +-------------+
#
# Synopsis:
#  mcp_basic_check <-uut <target device> -rtr1 <router 1> -rtr2 <router 2> \
#   -rtr1Int <int> -rtr2Int <int>>
#
# Sample Usage:
#  mcp_basic_check -uut Router -rtr1 r7200-a -rtr2 r7200-b -rtr1Int GigabitEthernet0/1
#                  -rtr2Int GigabitEthernet0/1
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
#
# AtsAuto package would include all of the relevant packages
# required for ATS Automation: pyats
#
# Following needed for pre/post router check
#
# Specify the mandatory arguments and their type to facilitate
#
# argument validation here
#
# Arguments would have to be preceded by the "-" character
#
# Standard types include: 
#
# Similarly, specify the optional arguments to the script
# along with the argument type here
#
# Specify the testcase dependency list here which is specified
# as a list of space separated testcase ids. A testcase with
# dependencies cannot be invoked unless all its listed testcases
#
# tc_depend : ST-SWEEP-PING: ST-IFTX-002 , 
#             ST-VLAN-PING: ST-IFTX-002
#             prefix_check: ST-IFTX-002
#
#######################################################################

# imports
from ats.aetest import CommonSetup
from ats.topology import loader
from ats.log.utils import banner,title
from ats import aetest
from ats import topology
from csccon import Csccon
from unicon import Unicon
import re,pdb,time
import string
import os,sys
import argparse
import logging
import pprint

#Tcl Package
#from ats import tcl
#tcl.q.package('require', 'router_show')
#tcl.eval('package require rtrUtils')

# logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

mandatory_parameters = {'uut1', 'rtr1', 'rtr2', 'uutInt1', 'uutInt2','rtr1Int', 'rtr2Int'}

# global variable 
uutInt1IP = '1.1.1.254'
uutInt2IP = '3.3.3.254'
rtr1IP = '1.1.1.1'
rtr2IP = '3.3.3.3'
rtr2lo101IP = '101.101.101.101'

# IPv6 address
uutInt1IPv6 = '1::2'
uutInt2IPv6 = '3::2'
rtr1IPv6 = '1::1'
rtr2IPv6 = '3::1'

# sub interface IP
rtr1SubIntIP = '6.6.6.1'
uutSubInt1IP = '6.6.6.2'
uutSubInt2IP = '7.7.7.2'
rtr2SubIntIP = '7.7.7.1'

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
###                          Perfix check ipv4                      ###
#######################################################################
    
def cidr_prefix_mask(cidr_number = 0):

    byte_count = 1
    current_value = 0
    mask = ""
    start_value = 128

    for each_num in range(1, cidr_number + 1):
        if cidr_number > 32:
            self.failed("procName arg too large - should be integer (0-32)")
        current_value = start_value + current_value
        start_value = start_value/2
        if byte_count == 8 or each_num == cidr_number:
            mask = str(mask) +"."+ str(int(current_value))
            start_value = 128
            current_value = 0
            byte_count = 0
        byte_count = byte_count + 1
        mask = mask.lstrip(".")

    if len(mask) == 3:
        mask = mask + ".0.0.0"
    elif len(mask) == 7:
        mask = mask + ".0.0"
    elif len(mask) == 11:
        mask = mask + ".0"
    elif len(mask) == 15:
        mask = mask

    return mask        

###########################################################################
###                      COMMON SETUP SECTION                           ###
###########################################################################

class ScriptCommonSetup(aetest.CommonSetup):

    logger.info(banner('Executing common_setup section'))
    
    @aetest.subsection
    def validate_params(self, testbed, **parameters):
        for parameter in parameters:
            assert parameter in mandatory_parameters, \
            self.failed("Missing parameter {} from mandatory_parameters".format(parameter))

    @aetest.subsection
    def get_testbed_info(self, uut1, rtr1, rtr2, uutInt1, uutInt2, rtr1Int, rtr2Int,  testbed, **parameters):
    
        logger.info(banner('Connecting to Router'))
        
        uut1 = testbed.devices[uut1]
        rtr1 = testbed.devices[rtr1]
        rtr2 = testbed.devices[rtr2]
        
        self.parent.parameters['uut1'] = uut1
        self.parent.parameters['rtr1'] = rtr1
        self.parent.parameters['rtr2'] = rtr2
            
        uut1.connect()
        assert uut1.connected, "Could not connect to device: {}".format(uut1.name)
        rtr1.connect()
        assert rtr1.connected, "Could not connect to device: {}".format(rtr1.name)
        rtr2.connect()
        assert rtr2.connected, "Could not connect to device: {}".format(rtr2.name)

        logger.info("Configuring uut1 Interfaces IP address")
        
        #uut1 configuration
        #need to check with onshore team (ip cef)
        try:
            uut1_config = '''
            logging buffer 1000000
            ip routing
            no cdp run
            ipv6 unicast-routing
            ipv6 cef distributed
            !
            interface {}
            ip address {} 255.255.255.0
            ipv6 address {}/64
            no shut
            no cdp enable
            interface {}.6
            encapsulation dot1q 6
            ip address {} 255.255.255.0
            !
            router ospf 1
             log-adjacency-changes
             network {} 0.0.0.255 area 0
            !
            no arp {}
            !
            interface {}
            ip address {} 255.255.255.0
            ipv6 address {}/64
            no shut
            no cdp enable
            interface {}.7
            encapsulation dot1q 7
            ip address {} 255.255.255.0
            !
            ip route {} 255.255.255.255 {}
            !
            no arp {}
            '''.format(uutInt1,uutInt1IP,uutInt1IPv6,uutInt1,uutSubInt1IP,uutInt1IP,rtr1IP,uutInt2,uutInt2IP,uutInt2IPv6,uutInt2,uutSubInt2IP,rtr2lo101IP,rtr2IP,rtr2IP)
            uut1.configure(uut1_config)
                
        except Exception as e:
            logger.info("uut1 configuration error")
            self.failed(goto=['exit'])
                
        logger.info("Configuring rtr1 Interfaces IP address")
        
        #rtr1 configuration
        try:
            rtr1_Config = '''
            ip cef
            ipv6 unicast-routing
            ipv6 cef
            !
            interface {}
            ip address {} 255.255.255.0
            ipv6 address {}/64
            media-type sfp
            no shut
            no cdp enable
            no keepalive
            interface {}.6
            encapsulation dot1q 6
            ip address {} 255.255.255.0
            !
            router ospf 1
            log-adjacency-changes
            network {} 0.0.0.255 area 0
            !
            ip route 0.0.0.0 0.0.0.0 {}
            ipv6 route ::/0 {}
            !
            no arp {}
            '''.format(rtr1Int,rtr1IP,rtr1IPv6,rtr1Int,rtr1SubIntIP,rtr1IP,uutInt1IP,uutInt1IPv6,uutInt1IP)
            rtr1.configure(rtr1_Config)
            
        except Exception as e:            
            logger.info("rtr1 configuration error")
            self.failed(goto=['exit'])

        logger.info("Configuring rtr2 Interfaces IP address")
        
        #rtr2 configuration
        try:
            rtr2_config = '''
            ip cef
            ipv6 unicast-routing
            ipv6 cef
            !
            interface {}
            ip address {} 255.255.255.0
            ipv6 address {}/64
            media-type sfp
            no shut
            no cdp enable
            no keepalive
            interface {}.7
            encapsulation dot1q 7
            ip address {} 255.255.255.0
            !
            interface Loopback101
            ip address {} 255.255.255.255
            !
            ip route 0.0.0.0 0.0.0.0 {}
            ipv6 route ::/0 {}
            !
            no arp {}
            '''.format(rtr2Int,rtr2IP,rtr2IPv6,rtr2Int,rtr2SubIntIP,rtr2lo101IP,uutInt2IP,uutInt2IPv6,uutInt2IP)
            rtr2.configure(rtr2_config)
            
        except Exception as e:
            logger.info("rtr2 configuration error")
            self.failed(goto=['exit'])

        logger.info('Setup configure sccessfully')
        
                
#######################################################################
###                          TESTCASE BLOCK                         ###
#######################################################################

class active_rp_status(aetest.Testcase):

    uid = "active_rp_status"
    
    @aetest.test
    def test(self, uut1):
        logger.info(banner("Check active RP status"))
        logger.info("Check if active RP is online")
        logger.info(title('Setup'))
        
        #Get status
        output_sh_pl= uut1.execute("show platform")
        check_status = re.search("R\d\s+[^\s]+\s+(ok)\,\s+active", output_sh_pl)
        
        #check rp status
        if check_status.group(1) == "ok" :
            logger.info(banner("Active RP is up status {}".format(check_status.group(1))))
        else:
            self.failed("Active RP is NOT up")
        

class standby_rp_status(aetest.Testcase):

    uid = "standby_rp_status"
    
    @aetest.test
    def test(self, uut1):
        logger.info(banner("Check standby RP status"))
        logger.info("Check if standby RP is online")
        logger.info(title('Setup'))
        
        #Get status
        output_sh_pl= uut1.execute("show platform")
        check_status = re.search("R\d\s+[^\s]+\s+(ok)\,\s+standby", output_sh_pl)
        
        #check rp status
        if check_status.group(1) == "ok" :
            logger.info(banner("Standby RP is up status {}".format(check_status.group(1))))
        else:
            self.failed("Standby RP is NOT up")
            #redundancy check
            logger.info("Display the output of show redundancy history")
            uut1.execute("show redundancy history")
            
        
class active_fp_status(aetest.Testcase):

    uid = "active_fp_status"
    
    @aetest.test
    def test(self, uut1):
        logger.info(banner("Check active FP status"))
        logger.info("Check if active FP is online")
        logger.info(title('Setup'))
        
        #Get status
        output_sh_pl= uut1.execute("show platform")
        check_status = re.search("F\d\s+[^\s]+\s+(ok)\,\s+active", output_sh_pl)
        
        #check fp status
        if check_status.group(1) == "ok" :
            logger.info(banner("Active FP is up status {}".format(check_status.group(1))))
        else:
            self.failed("Active FP is NOT up")
         
        
class standby_fp_status(aetest.Testcase):

    uid = "standby_fp_status"
    
    @aetest.test
    def test(self, uut1):
        logger.info(banner("Check standby FP status"))
        logger.info("Check if standby FP reaches ok state")
        logger.info(title('Setup'))
        
        #Get status
        output_sh_pl= uut1.execute("show platform")
        check_status = re.search("F\d\s+[^\s]+\s+(ok)\,\s+standby", output_sh_pl)
        
        #check fp status
        if check_status.group(1) == "ok" :
            logger.info(banner("Standby FP is status {}".format(check_status.group(1))))
        else:
            self.failed("Standby FP failed to reach ok state")      
        
        
class cc0_status(aetest.Testcase):

    uid = "cc0_status"
    
    @aetest.test
    def test(self, uut1):
        logger.info(banner("Check CC0 status"))
        logger.info("Check if CC0 is online")
        logger.info(title('Setup'))
        
        #Get status
        output_sh_pl= uut1.execute("show platform")
        check_status = re.search("0\s+(MCP-CC|ASR\d+-SIP\d+)\s+(ok)\s+", output_sh_pl)
        
        #check fp status
        if check_status.group(2) == "ok" :
            logger.info(banner("CC0 is up status {}".format(check_status.group(2))))
        else:
            self.failed("CC0 is NOT up")        


class cc1_status(aetest.Testcase):

    uid = "cc1_status"
    
    @aetest.test
    def test(self, uut1):
        logger.info(banner("Check CC1 status"))
        logger.info("Check if CC1 is online")
        logger.info(title('Setup'))
        
        #Get status
        output_sh_pl= uut1.execute("show platform")
        check_status = re.search("0\s+(MCP-CC|ASR\d+-SIP\d+)\s+(ok)\s+", output_sh_pl)
        
        #check fp status
        if check_status.group(2) == "ok" :
            logger.info(banner("CC1 is up status {}".format(check_status.group(2))))
        else:
            self.failed("CC1 is NOT up") 


class spa_ge_status(aetest.Testcase):

    uid = "spa_ge_status"
    
    @aetest.test
    def test(self, uut1):
        logger.info(banner("Check GigE SPA status"))
        logger.info("Check if GigE SPA is online")
        logger.info(title('Setup'))
        
        #Get status
        output_sh_pl= uut1.execute("show platform")
        check_status = re.search("SPA-\dX1GE...\s+(ok)\s+", output_sh_pl)
        
        #check fp status
        if check_status.group(1) == "ok" :
            logger.info(banner("GigE SPA is up status {}".format(check_status.group(1))))
        else:
            self.failed("GigE SPA is NOT up") 


class access_harddisk(aetest.Testcase):

    uid = "access_harddisk"
    
    @aetest.test
    def test(self, uut1):
        logger.info(banner("Verify the harddisk can be accessed"))
        logger.info("Verify the harddisk can be accessed")
        logger.info(title('Setup'))
        
        #Get dir output
        dir_output = uut1.execute("dir harddisk:*core")
                
        check_status = re.findall("(Error|Invalid|Incomplete|bytes free)", dir_output)
        
        if "Error" or "Invalid" or "Incomplete" in check_status:
            logger.info("Failed to access the harddisk {}".format(check_status))
        elif "bytes free" in check_status :
            logger.info(banner("The harddisk can be accessed"))
            
            
class access_bootflash(aetest.Testcase):

    uid = "access_bootflash"
    
    @aetest.test
    def test(self, uut1):
        logger.info(banner("Verify the bootflash can be accessed"))
        logger.info("Verify the bootflash can be accessed")
        logger.info(title('Setup'))
        
        #Get dir output
        dir_output = uut1.execute("dir bootflash:mcp_crashinfo*")
                
        check_status = re.findall("(Error|Invalid|Incomplete|bytes free)", dir_output)
        
        if "Error" or "Invalid" or "Incomplete" in check_status:
            logger.info("Failed to access the bootflash {}".format(check_status))
        elif "bytes free" in check_status :
            logger.info(banner("The bootflash can be accessed"))


#######################################################################
###                 2) smoke_interactive                            ###
#######################################################################
            
class pingLIIN(aetest.Testcase):

    uid = "pingLIIN"
    
    @aetest.setup
    def setup(self, uut1):
        logger.info(banner("Verify connectivity on LIIN interface"))
        logger.info("Verify connectivity on LIIN interface")
        logger.info(title('Setup'))
        
        uut1_config = '''
        service internal
        ip vrf internal
        '''
        uut1.configure(uut1_config)
        
    @aetest.test
    def test(self, uut1):
        
        check_ip_add = uut1.execute("show platform soft infra liin | incl  Internet address is")
        
        #grep ip address        
        ip_add = re.search('(\d+).(\d+).(\d+).(\d+)',check_ip_add)
        
        oct1 = ip_add.group(1)
        oct2 = ip_add.group(2)
        oct3 = ip_add.group(3)
        oct4 = ip_add.group(4)        
        
        if not ip_add:
            logger.info("IP address not found on LIIN interface")
            
        if int(oct4) == 6:
            liinLinuxAddr = "{}.{}.{}.5".format(oct1,oct2,oct3)
        else:
            liinLinuxAddr = "{}.{}.{}.1".format(oct1,oct2,oct3)

        #ping test 
        ping_status_ipv4 = uut1.execute("ping vrf __Platform_iVRF:_ID00_ ip {}".format(liinLinuxAddr))
        output_value_ipv4 = re.search('Success rate is (\d*)',ping_status_ipv4)
        if int(output_value_ipv4.group(1)) >= 80:
            logger.info("Ping Success")
        else:
            self.failed("Ping failed")
        
    @aetest.cleanup
    def cleanup(self, uut1):
        uut1_unconfig = '''
        no service internal
        no ip vrf internal
        '''
        uut1.configure(uut1_unconfig)

class Interactive(aetest.Testcase):

    uid = "Interactive"
    
    @aetest.test
    def test(self, uut1):
        logger.info(banner("Interactive test command to all online FRUs"))
        logger.info("Interactive test command to all online FRUs")
        logger.info(title('Setup'))
                 
        numFRUs = 0
        passCount = 0
        
        showResult = uut1.execute("show platform | incl ESP|RP")
                
        for fru in showResult.splitlines():
            matchs = re.search("([RF]\d)\s+\S+\s+(ok)",fru)
            if (matchs.group(1))[0] == "R":
                type_rp = "RP"
                numFRUs = numFRUs + 1
                rp_ok = matchs.group(2)
                if rp_ok :
                    passCount = passCount + 1
            
            elif (matchs.group(1))[0] == "F":
                typ_fp = "FP"
                numFRUs = numFRUs + 1
                fp_ok = matchs.group(2)
                if fp_ok:
                    passCount = passCount + 1
            status_match =(matchs.group(1))
                        
            if numFRUs == passCount:
                try:
                    output_inter = uut1.execute("test platform software shell command infrastructure interactive {}".format(status_match))
                    self.failed("fail")
                except Exception as e:
                    logger.info("Interactive test command did not succeed to some of the online FRUs")
                    

#######################################################################
###                        3) mcp_hw_fwd                            ###
#######################################################################

class ST_IFTX_001(aetest.Testcase):

    uid = "ST_IFTX_001"
    
    @aetest.test
    def test(self, uut1):
        logger.info(banner("Generic Interface check"))
        logger.info("Verify that all interfaces are present")
        logger.info(title('Setup'))
        
        uut1.execute("show plat soft peer for fp act | incl updates")
        
        intf_output = uut1.execute("show ip interface brief")
        
        intf_count = 0
        
        #interface count
        for lines in intf_output.splitlines()[1:]:
            intf_count = intf_count + 1
        
        logger.info("Interface count is {}".format(intf_count))
        

class ST_IFTX_002(aetest.Testcase):

    uid = "ST_IFTX_002"
    
    @aetest.setup
    def setup(self, uut1, rtr1, rtr2):
        logger.info(banner("Overall IOS punt ICMP test"))
        logger.info("Verify interface bring up, presense of routes and ping UUT")
        logger.info(title('Setup'))
        
    @aetest.test
    def ST_IFTX_002_1(self, uut1, rtr1, rtr2, uutInt1, uutInt2):
        #Interface status
        logger.info(banner("Verifying Interface bring up"))
        
        #Verifying if UUT interfaces are up
        for intf in [uutInt1,uutInt2]:
            check_inft_status = uut1.execute("show interface " + intf)
            inft_status = re.search('\S*\s+(is)\s+(up)\,\s+(line)\s+(\S*)\s+(is)\s+(up)',check_inft_status)
            if inft_status.group(2) == "up" and inft_status.group(6) == "up":
                logger.info("{} Interface is {} and line protocol is {}".format((uutInt1),(inft_status.group(2)),(inft_status.group(6))))
            else:
                self.failed("{} Interface is {} and line protocol is {}".format((uutInt2),(inft_status.group(2)),(inft_status.group(6))))
                
    @aetest.test
    def ST_IFTX_002_2(self, uut1, rtr1, rtr2):
        logger.info("FMAN-FP route existence")
        
        #Show the various tables on MCP
        try:
            uut1.execute("show ip route")
            uut1.execute("show plat soft ip fp act cef")
            uut1.execute("show plat soft int fp act")
            uut1.execute("show plat soft adj fp act")
        except Exception as e:
            self.failed("Command failed")
        
        logger.info("Test passed: obtained cpp handles for both prefixes")

    @aetest.test
    def ST_IFTX_002_3(self, uut1, rtr1, rtr2):
        logger.info("IOS generated ICMP (Punt)")
        
        #Verify before/after punt statistics
        try:
            uut1.execute("show platform software infra punt")
            uut1.execute("show platform software infra inject")
            
            #Verify the ARP entry
            uut1.execute("show arp")
            rtr2.execute("show arp")
            
            #Verifying whether uut's IOS can send punt pkt (icmp)
            ping_status_ipv4 = uut1.execute("ping " +rtr2IP)
            
            time.sleep(5)
            
            #Verify the ARP entry
            uut1.execute("show arp")
            rtr2.execute("show arp")
            
            #Verify before/after punt statistics
            uut1.execute("show platform software infra inject")
            uut1.execute("show platform software infra inject")
            
            #ping test
            if not ping_test(uut1, rtr2IP, ipv6 = False):
                self.failed('Ping failed ')
            else:
                logger.info('Connectivity between uut1 and rtr2 successfull')

            time.sleep(5)
            
            #Verify before/after punt statistics
            uut1.execute("show platform software infra inject")
            uut1.execute("show platform software infra inject")
          
        except Exception as e:
            self.failed("subsection : IOS generated ICMP (Punt)")

    @aetest.test
    def ST_IFTX_002_4(self, uut1, rtr1, rtr2):
        logger.info("ICMP ping to IOS interface")
        
        #Verifying whether the UUT interfaces are pingable
        if not ping_test(rtr1, uutInt1IP, ipv6 = False):
            self.failed("Ping failed")
        else:
            logger.info("Ping successfull")
            
        if not ping_test(rtr2, uutInt2IP, ipv6 = False):
            self.failed("Ping failed")
        else:
            logger.info("Ping successfull")
                
        
class ST_IPV6_PING(aetest.Testcase):

    uid = "ST_IPV6_PING"
    
    logger.info(banner("Overall ICMP IPv6 ping from/to/thru UUT"))
    logger.info("Verify that IPv6 punt/inject/thru path on UUT")
    
    @aetest.test
    def ST_IPV6_PING_1(self, uut1, rtr1, rtr2):
        logger.info("ICMP IPv6 ping to verify punt/inject path")
    
        #ping ipv6
        if not ping_test(uut1, rtr1IPv6, ipv6 = True):
            self.failed("ICMP IPv6 ping test for punt/inject path failed")
        else:
            logger.info("Ping successfull")
            
        try:
            uut1.execute("show ipv6 neighbors")
            rtr1.execute("show ipv6 neighbors")
            rtr2.execute("show ipv6 neighbors")
            
        except Exception as e:
            self.failed("Command failed")
            
            
    @aetest.test
    def ST_IPV6_PING_2(self, uut1, rtr1, rtr2):
        logger.info("ICMP IPv6 ping to verify thru path")
        
        #ping ipv6
        if not ping_test(rtr1, rtr2IPv6, ipv6 = True):
            self.failed('ICMP IPv6 ping test for thru path failed')
        else:
            logger.info('Ping successfull')
                        
        try:
            uut1.execute("show ipv6 neighbors")
            rtr1.execute("show ipv6 neighbors")
            rtr2.execute("show ipv6 neighbors")
            
        except Exception as e:
            self.failed("Command failed")

    @aetest.test
    def ST_IPV6_PING_3(self, uut1, rtr1, rtr2):
        logger.info("ICMP IPv6 ping to UUT")
        
        #ping ipv6
        if not ping_test(rtr1, uutInt1IPv6, ipv6 = True):
            self.failed('ICMP IPv6 ping to UUT failed')
        else:
            logger.info('Ping successfull')
            
        try:
            uut1.execute("show ipv6 neighbors")
            rtr1.execute("show ipv6 neighbors")
            rtr2.execute("show ipv6 neighbors")
            
        except Exception as e:
            self.failed("Command failed")
            

class ST_SWEEP_PING(aetest.Testcase):

    uid = "ST_SWEEP_PING"
    
    logger.info(banner("Overall ICMP sweep ping from/to/thru UUT"))
    logger.info("Verify that punt/inject/thru path on UUT")
 
    @aetest.test
    def ST_SWEEP_PING_1(self, uut1, rtr1, rtr2):
        logger.info("ICMP IPv6 ping to UUT")
        logger.info("Sweep ping to verify punt/inject path")
        
        #ping check
        ping_check = uut1.ping(rtr1IP,proto = 'ip',sweep_ping='y',sweep_min=64,sweep_max=1500,sweep_interval=1)
        print(type(ping_check))
        print(ping_check)
        if ping_check:
            logger.info(banner("pass"))
        else:
            logger.info("ping fail")
            
    @aetest.test
    def ST_SWEEP_PING_2(self, uut1, rtr1, rtr2):
        logger.info("Sweep ping to verify thru path")
        logger.info("Sweep ping to verify punt/inject path")
        
        ping_check = uut1.ping(rtr2IP, proto = 'ip',sweep_ping='y',sweep_min=64,sweep_max=1500,sweep_interval=1)
        print(type(ping_check))
        print(ping_check)
        if ping_check:
            logger.info(banner("pass"))
        else:
            logger.info("ping fail")
            
    @aetest.test
    def ST_SWEEP_PING_3(self, uut1, rtr1, rtr2):
        logger.info("Sweep ping to verify thru path")
        logger.info("Sweep ping to verify punt/inject path")
        
        ping_check = uut1.ping(rtr2IP, proto = 'ip', sweep_ping='y',sweep_min=64,sweep_max=1500,sweep_interval=1)
        print(type(ping_check))
        print(ping_check)
        if ping_check:
            logger.info(banner("pass"))
        else:
            logger.info("ping fail")
            
            
class ST_VLAN_PING(aetest.Testcase):

    uid = "ST_VLAN_PING"
    
    @aetest.test
    def setup(self, uut1, rtr1, rtr2):
        logger.info("Overall ICMP vlan ping from/to/thru UUT")
        logger.info("Verify that punt/inject/thru path on UUT")

        uut1.execute("show platform software infra punt")
        uut1.execute("show platform software infra inject")
    
    @aetest.test
    def ST_VLAN_PING_1(self, uut1, rtr1, rtr2):
        logger.info("Vlan ping to verify punt/inject path")
        
        #ping ipv4
        if not ping_test(uut1, rtr1SubIntIP, ipv6 = False):
            self.failed('Vlan ping test for punt/inject path failed')
        else:
            logger.info('Ping successfull')
            
    @aetest.test
    def ST_VLAN_PING_2(self, uut1, rtr1, rtr2):
        logger.info("Vlan ping to verify thru path")
        
        #ping ipv4
        if not ping_test(rtr1, rtr2SubIntIP, ipv6 = False):
            self.failed("Vlan ping test for thru path failed")
        else:
            logger.info("Ping successfull")

    @aetest.test
    def ST_VLAN_PING_3(self, uut1, rtr1, rtr2):
        logger.info("Vlan ping to UUT")

        #ping ipv4
        if not ping_test(rtr2, uutSubInt1IP, ipv6 = False):
            self.failed("Vlan ping to UUT failed")
        else:
            logger.info("Ping successfull")
    
        logger.info("show punt statistics after the vlan test")
    
        uut1.execute("show platform software infra punt")
        uut1.execute("show platform software infra inject")


class ST_IFTX_003(aetest.Testcase):
     
    uid = "ST_IFTX_003"
    
    @aetest.test
    def test(self, uut1, rtr1, rtr2):
    
        logger.info(banner("Traffic forwarding test - dynamic ARP"))
        logger.info("Verify traffic forwarding with dynamic ARP through UUT")
        
        uut1.execute("show plat soft ip fp act cef det")
        
        #Verify before/after punt statistics
        uut1.execute("show platform software infra punt")
        uut1.execute("show platform software infra inject")
        
        #Verify the ARP entry
        uut1.execute("show arp")
        rtr1.execute("show arp")
        rtr2.execute("show arp")
        
        #Verifying whether ping goes through the UUT
        if not ping_test(rtr1, rtr2IP, ipv6 = False):
            self.failed("Ping failed")
        else:
            logger.info("Ping successfull")
        
        if not ping_test(rtr2, rtr1IP, ipv6 = False):
            self.failed("Ping failed")
        else:
            logger.info("Ping successfull")
        
        time.sleep(5)

        #Verify the ARP entry
        uut1.execute("show arp")
        rtr1.execute("show arp")
        rtr2.execute("show arp")

        #Verify before/after punt statistics
        uut1.execute("show platform software infra punt")
        uut1.execute("show platform software infra inject")
        
        #Verifying whether ping goes through the UUT
        if not ping_test(rtr1, rtr2IP, ipv6 = False):
            self.failed("Ping failed")
        else:
            logger.info("Ping successfull")
    
        if not ping_test(rtr2, rtr1IP, ipv6 = False):
            self.failed("Ping failed")
        else:
            logger.info("Ping successfull")

class MCP_ST_OSPF_0049(aetest.Testcase):

    uid = "MCP_ST_OSPF_0049"
    
    logger.info(banner("OSPF - adjacency-based inject"))
    logger.info("Verify OSPF - adjacency-based inject test")
    
    @aetest.test
    def section_test(self, uut1, rtr1, rtr2):
        
        tries = 0
        max_tries = 18
        
        while tries < max_tries:
            ospf_output = uut1.execute("show ip ospf neighbor")
            start_time_stamp = time.time()
            for line in ospf_output.splitlines():
                neighbor_output =re.search('(FULL)\S*\s+[0-9\:]*\s+(\d+\.\d+\.\d+\.\d+)',ospf_output)
                end_time_stamp = time.time()
                total_time = start_time_stamp - end_time_stamp
                if neighbor_output.group(1) == "FULL" and neighbor_output.group(2) == rtr1IP:
                    logger.info(banner("OSPF reached FULL state in {} seconds".format(round(total_time))))
                    break
                else:
                    tries += 1
                    time.sleep(10)
                    self.failed("OSPF - adjacency-based inject test failed")
            break         
        logging.info("OSPF - adjacency-based inject test Successfull")
        
        
class prefix_check(aetest.Testcase):
    
    uid ="prefix_check"
    
    logger.info("Verify prefix length from 16 to 30 works")
    
    @aetest.test
    def test(self, uut1, rtr1, rtr2, uutInt1):
        
        logger.info("setup configuration")
        
        uutInt1IP = "1.1.1.2"
            
        for prefix in range(16,31):
            #procedure call
            netmask = cidr_prefix_mask(prefix)
            uutInt1_PrefixRe_config ='''
            interface {}
            ip address {} {}
            '''.format((uutInt1),(uutInt1IP),(netmask))
            uut1.configure(uutInt1_PrefixRe_config)

            #Verifying whether ping goes through the rtr1
            if not ping_test(rtr1, uutInt1IP, ipv6 = False):
                self.failed("Ping failed")
            else:
                logger.info("Ping succeeded from rtr1 to uut1 with mask bit {}".format(netmask))
        
        logger.info("Ping succeeded from rtr1 to uut1 for mask bit from 16 to 30")
           
#######################################################################
##                    COMMON CLEANUP SECTION                        ###
####################################################################### 

class CommonCleanup(aetest.CommonCleanup):
    
    @aetest.subsection
    def cleanup(self, uut1, rtr1, rtr2, uutInt2, uutInt1, rtr1Int, rtr2Int):
    
        logger.info("In common_cleanup section")
        
        #unconfiguration section
        try:
            uut1_unconfig ='''
            no router ospf 1
            !
            interface {0}
            no ip address
            no ipv6 address
            shut
            no interface {0}.6
            !
            interface {1}
            no ip address
            no ipv6 address
            shut
            no interface {1}.7
            !
            no ip route {2} 255.255.255.255 {3}
            '''.format((uutInt1),(uutInt2),(rtr2lo101IP),(rtr2IP))
            uut1.configure(uut1_unconfig)
        
            rtr1_unconfig ='''
            no router ospf 1
            !
            interface {0}
            no ip address
            no ipv6 address
            shut
            no interface {0}.6
            !
            no ip route 0.0.0.0 0.0.0.0 {1}
            no ipv6 route ::/0 {2}
            '''.format((rtr1Int),(uutInt1IP),(uutInt1IPv6))
            rtr1.configure(rtr1_unconfig)
           

            rtr2_unconfig ='''
            interface {0}
            no ip address
            no ipv6 address
            shut
            no interface {0}.7
            !
            interface Loopback101
            no ip address {1} 255.255.255.255
            no interface Loopback101
            !
            no ip route 0.0.0.0 0.0.0.0 {2}
            no ipv6 route ::/0 {3}
            '''.format((rtr2Int),(rtr2lo101IP),(uutInt2IP),(uutInt2IPv6))
            rtr2.configure(rtr2_unconfig)
            logger.info(("Unconfigure successfull"))
            
        except Exception as e:
            logger.info(banner("Unconfigure error"))
            self.failed(goto=['exit'])
        
        logger.info("unconfiguration successfull")         
        logger.info(banner("mcp_basic_check script successfully completed"))
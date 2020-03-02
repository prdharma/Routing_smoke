# Name: mcp_evc
#
# Purpose: MCP EVC smoketest script
#
# Author: 
#         
#
# References:
#     EDCS-845003 MCP Verison EVC on ASR1000 Test Plan
#
# Description:
#   This script contains the following EVC test cases:
#     - L2 local bridging
#     - split-horizon group
#     - static routing protocol/L3 forwording
#
# Topology:
#
#  +---------+            +---------+             +---------+
#  |         |            |         |             |         |
#  |         |            |         |             |         |
#  |         | ethernet 1 |         | ethernet 2  |         |
#  | router1 +------------+   UUT   +-------------+ router2 |
#  |         |            |         |             |         |
#  |         +            +         |             |         |
#  |         |            |         |             |         |
#  +---------+            +---------+             +---------+
# 
#
# Synopsis:
#  
#
# Mandatory Arguments:
#    -uut1              The UUT name
#    -uutInt1           The UUT interface name connecting to the router1 
#    -uutInt2           The UUT interface name connecting to the router2 
#    -rtr1              The router1 name
#    -rtr1Int           The router1 interface name connecting to the UUT
#    -rtr2              The router2 name
#    -rtr2Int           The router2 interface name connecting to the UUT
#
# Sample Usage:
#
#   
# Pass/Fail Criteria:
#       All test cases pass
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

#######################################################################
###                 TEST SCRIPT INITIALIZATION BLOCK                ###
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

# logging
logger = logging.getLogger(__name__)
logger.setLevel(logging.DEBUG)

mandatory_parameters = {'uut1', 'rtr1', 'rtr2', 'uutInt1', 'uutInt2','rtr1Int', 'rtr2Int'}

#set optional_args : default value  (Need to check the all optional_args)

mask_8 = "255.0.0.0"
mask_16 = "255.255.0.0"
mask_24 = "255.255.255.0"
mask_32 = "255.255.255.255"
uut_efp1 = 10
uut_efp2 = 20
uut_dot1q1 = 100
uut_dot1q2 = 200
uut_bd1 = 2000
uut_bd2 = 3000
uut_rtr1_add = "10.1.1.2"
uut_rtr1_net = "10.1.0.0"
uut_rtr2_add = "20.1.1.2"
uut_rtr2_net = "20.1.0.0"
uut_bdi1_add = "10.1.1.2"
uut_bdi2_add = "20.1.1.2"
uut_dhcp_add = "192.168.1.1"
uut_dhcp_net = "192.168.1.0"
uut_dhcp_excl_1 = "192.168.1.1"
uut_dhcp_excl_2 = "192.168.1.99"
rtr1_dhcp_add = "192.168.1.100"
rtr1_loop_add = "100.100.100.100"
rtr1_loop_net = "100.100.0.0"
rtr1_uut_add = "10.1.1.1"
rtr2_uut_add = "20.1.1.1"
rtr1_rtr2_add = "10.1.1.1"
rtr2_rtr1_add = "10.1.1.2"
itere = 2
delay = 10
pkts_sent = 8
pkts_ping = 100

addr ="10.1.1.2"
src_add ="10.1.1.1"

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

#######################################################################################
###                           verify_ip_connectivity                                ###
#######################################################################################

def verify_ip_connectivity(device,addr,src_add):
  
    logger.info("verify ip connectivity")
       
    #opt_arg
    count = '100'
    size = '100'
    
    #count = 0
    logger.info("inside the proc")

    #uut1 = "Router"
    #src_rtr ='r7200-a'
    #dst_rtr ='r7200-b'
    
    ping_status_ipv4 = device.execute("ping 10.1.1.2 100 100 10.1.1.1")
    logger.info("after command")
    
    #ping_status_ipv4 = device.ping(count ="100",size = "100", addr ="10.1.1.2", src_add ="10.1.1.1")
    if ping_status_ipv4:
       print("sucess")
    else:
       print("fail")
       

#######################################################################################
###                           check_interface_stats                                 ###
#######################################################################################       
        
def check_interface_stats(device, interface, pkt_in, pkt_out):
  
    logger.info("check_interface_status")

    int_count = uut1.execute("show interface {} stats".format(interface))

    for each_line in int_count.splitlines():
        output_int = re.search('Distributed cache\s*(\d+)\s*\d+\s+(\d+)',each_line)
        if output_int:
            in_pkt = int(output_int.group(1))
            out_pkt = int(output_int.group(2))

    if pkt_in < (in_pkt - 10)  or pkt_in > (in_pkt + 10) or pkt_out < (out_pkt- 10) or pkt_out > (out_pkt + 10):
        looger.info( "show interfaces stats is wrong on {}, expected 90 - 110".format(interface))


#######################################################################################
###                  check_qfp_active_feature_l2bd_datapath_bd_count                ###
#######################################################################################

def check_qfp_active_feature_l2bd_datapath_bd_count(device, bd):

    logger.info("check qfp active feature l2bd datapath bd count")

    bd_count = device.execute("show platform hardware qfp active feature l2bd dat bd {} | inc Total bridged".format(bd))
    
    if bd_count:
        l2bd_datapath_bd_count = re.search("pkts\s+\:\s+(\d+)\s*bytes\:\s+(\d+)",bd_count)
    else:
        self.failed("bridged packet counts not showing")
        
    return (bd_counter =l2bd_datapath_bd_count.group(1),l2bd_counter = l2bd_datapath_bd_count.group(2))
    
    
#######################################################################################
###                           check_service_instance_stats                          ###
#######################################################################################      

def check_service_instance_stats (device, interface, efp_id, pkt_in, pkt_out):

    logger.info("check service instance status")

    show_output = uut1.execute("show ethernet service instance id {} interface {} stats".format(efp_id),(interface)))
    
    for lines in show_output.splitlines():
        status_in_out = re.search('(\d+)\s+(\d+)\s+(\d+)\s+(\d+)',lines)
        if status_in_out:
            show_pkt_in = int(status_in_out.group(1))
            show_pkt_out = int(status_in_out.group(3))
    
    if if show_pkt_in  < (in_pkt - 5) or show_pkt_in  > (in_pkt + 5) or show_pkt_out  < (out_pkt - 5) or show_pkt_out  > (out_pkt + 5)::
        looger.info( "efp $efp_id counter is wrong on {}, expect 95-100\n".format(interface))    
    

#######################################################################################
###                           split_horizon_group_check                             ###
#######################################################################################  

def split_horizon_group_check (device, efp, interface, bd, group):

    logger.info("check split-horizon")
 
    show_output = uut1.execute("show platform software ethernet F0 efp id {} interface {}".format((efp)(interface)))
  
    for lines in show_output.splitlines():
    status_output = re.search('Bridge-domain\:\s+(\d+)\,\s+Split-Horizon\:\s+(\d+)',lines)
    if status_output:
        logger.info("split horizon group is wrong for instance {} on interface {}".format((efp)(interface))


###################################################################################
###                                  COMMON SETUP SECTION                       ###
###################################################################################

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
        

##################################################################################
###                               TESTCASE BLOCK                               ###
##################################################################################

class evc_L2_bridging(aetest.Testcase):
    
    uid ="evc_L2_bridging"
    
    @aetest.test
    def test (self, uut1, rtr1, rtr2, uutInt1, uutInt2, rtr1Int, rtr2Int):
        
        logger.info(banner("evc_L2_Bridging"))
        logger.info("Verifying L2 Bridging works")
        
        uut1_config = '''
        interface {0}
        no shut
        service instance {1} ethernet
        encap dot1q {2}
        rewrite ingress tag pop 1 symmetric
        bridge-domain {3}   
        !
        interface {4}
        no shut
        service instance {5} ethernet
        encap dot1q {6}
        rewrite ingress tag pop 1 symmetric
        bridge-domain {3}   
        !
        '''.format((uutInt1),(uut_efp1),(uut_dot1q1),(uut_bd1),(uutInt2),(uut_efp2),(uut_dot1q2))
        uut1.configure(uut1_config)
    
        rtr1_config = '''
        interface {0}
        no shut
        interface {0}.{1}
        encap dot1q {1}
        ip address {2} {3}
        no shut
        '''.format((rtr1Int),(uut_dot1q1),(rtr1_rtr2_add),(mask_8))
        rtr1.configure(rtr1_config)
        
        rtr2_config = ''' 
        interface {0}
        no shut
        interface {0}.{1}
        encap dot1q {1}
        ip address {2} {3}
        no shut
        '''.format((rtr2Int),(uut_dot1q2),(rtr2_rtr1_add),(mask_8))
        rtr2.configure(rtr2_config)
    
        uut1.execute("show ip int brief")
        uut1.execute("show run inter {}".format(uutInt1))
        uut1.execute("show run inter {}".format(uutInt2))
        rtr1.execute("show run inter {}.{}".format((rtr1Int),(uut_dot1q1)))
        rtr2.execute("show run inter {}.{}".format((rtr2Int),(uut_dot1q2)))
        uut1.execute("show bridge-domain")
        
        time.sleep(60)
        
        #ping Test
        if not ping_test(rtr1, rtr2_rtr1_add, ipv6 = False):
            self.failed("Ping failed")
        else:
            logger.info("Ping succeeded")
            
        for each_conf in ["inf_flap","efp_flap","bd_flap"]:           

            if "inf_flap" == each_conf:
                uut1_config = '''
                inter {}
                shut
                !
                inter {}
                shut
                '''.format((uutInt1),(uutInt2))
                uut1.configure(uut1_config)
                
                uut1_config = '''
                inter {}
                no shut
                !
                inter {}
                no shut
                '''.format((uutInt1),(uutInt2))
                uut1.configure(uut1_config)
                
            elif "efp_flap" == each_conf:
                uut1_config = '''
                interface {}
                service instance {} ethernet
                shutdown
                no shut
                !
                interface {}
                service instance {} ethernet
                shutdown
                no shut
                '''.format((uutInt1),(uut_efp1),(uutInt2),(uut_efp2))
                uut1.configure(uut1_config)
                
                time.sleep(5)
                
            elif "bd_flap" == each_conf:
                uut1_config = '''
                bridge-domain {}
                shut
                no shut
                '''.format(uut_bd1)
                uut1.configure(uut1_config)
                
        logger.info("config succeeded")        
                
        time.sleep(10)

        uut1.execute("clear counters")     
        uut1.execute("clear counters")
        uut1.execute("clear counters")
        
        #L2bridge counter (check_qfp_active_feature_l2bd_datapath_bd_count)
        check_l2bd = check_qfp_active_feature_l2bd_datapath_bd_count(uut1, uut_bd1)
        if not check_l2bd :
            self.failed("L2bridge counter not working")
        else:
            bd_counter1 = check_l2bd(0)
            l2bd_counter1 = check_l2bd(1)
            logger.info("pkts count :{} 12bd count : {}".format(bd_counter1,l2bd_counter1)
            
            
        #send packets to verify counter (verify_ip_connectivity)
        #device, src_rtr, src_add, pkt_count, pkts_ping, dst_rtr, dst_add
        connectivity_check = verify_ip_connectivity(rtr1,addr,src_add)
        if not connectivity_check:
            self.failed("ping fail")
        else:
            logger.info("ping sucessfull")
          
         
        #check interface counter
        for intf in [rtr1Int,rtr12Int]:
            if not check_interface_stats(uut1, intf, pkts_ping, pkts_ping):
                logger.info("show interfaces stats is wrong, expect {} plus or minus 10\n".format(pkts_ping))

         
        #check efp counters (check_service_instance_stats)
        efp_dict = { uut_efp1 : uutInt1,  uut_efp2 : uutInt2 }
        
        for efp,intf in efp_dict.items():
            if not check_service_instance_stats(uut1, intf, efp, pkts_ping, pkts_ping):
                logger.info("EFP counter is wrong, expect {} plus or minus 5\n".format(pkts_ping))
        
        #check l2bd counter
        check_l2bd = check_qfp_active_feature_l2bd_datapath_bd_count(uut1, uut_bd1)

        if not check_l2bd :
            self.failed("L2bridge counter not working")
        else:
            bd_counter2 = check_l2bd(0)
            l2bd_counter2 = check_l2bd(1)
            logger.info("pkts count :{} 12bd count : {}".format((bd_counter2),(l2bd_counter2))
            
        if ((bdcount2-bdcount1) < (pkts_ping*2-5)) or  ((bdcount2-bdcount1) > (pkts_ping*2+5)):
            self.failed("l2bd counter is wrong, expect 195-205")           
         
         
    @aetest.cleanup
    def cleanup(self, uut1, rtr1, rtr2, uutInt1, uutInt2, rtr1Int, rtr2Int):
        logger.info("testcase1 unconfig...")
        
        uut1_unconfig = '''
        default interface {}
        default interface {}
        '''.format((uutInt1),(uutInt2))
        uut1.configure(uut1_unconfig)
        
        rtr1_unconfig = '''
        inter {}.{}
        no ip add
        no encap dot1q {}
        '''.format((rtr1Int),(uut_dot1q1),(uut_dot1q1))
        rtr1.configure(rtr1_unconfig)
       
        rtr2_unconfig = '''
        inter {}.{}
        no ip add
        no encap dot1q {}
        '''.format((rtr2Int),(uut_dot1q2),(uut_dot1q2))
        rtr2.configure(rtr2_unconfig)


class split_horizon_group(aetest.Testcase):
    
    uid ="split_horizon_group"
    
    @aetest.test
    def test (self, uut1, rtr1, rtr2, uutInt1, uutInt2, rtr1Int, rtr2Int):
        
        logger.info(banner("split horizon group"))
        logger.info("split horizon group")
        
        uut1_config = '''
        interface {} 
        no shut
        service instance {} ethernet
        encap dot1q {}
        rewrite ingress tag pop 1 symmetric
        bridge-domain {} split-horizon group 0
        !
        interface {}
        no shut
        service instance {} ethernet
        encap dot1q {}
        rewrite ingress tag pop 1 symmetric
        bridge-domain {} split-horizon group 1
        '''.format((uutInt1),(uut_efp1),(uut_dot1q1),(uut_bd1),(uutInt2),(uut_efp2),(uut_dot1q2),(uut_bd1))
        uut1.configure(uut1_config)
          
        
        rtr2_config = '''
        interface {}
        no shut
        interface {}.{}
        encap dot1q {}
        ip address {} $
        no shut
        '''.format((rtr1Int),(rtr1Int),(uut_dot1q1),(uut_dot1q1),(rtr1_rtr2_add),(mask_8))
        rtr2.configure(rtr2_config)
        
        
        rtr2_config = '''
        interface {}
        no shut
        interface {}.{}
        encap dot1q {}
        ip address {} {}
        no shut
        '''.format((rtr2Int),(rtr2Int),(uut_dot1q2),(uut_dot1q2),(rtr2_rtr1_add),(mask_8))


        uut1.execute("show run inter {}".format(uutInt1))
        uut1.execute("show run inter {}".format(uutInt1))
        rtr1.execute("show run inter {}.{}".format((rtr1Int),(uut_dot1q1)))
        rtr2.execute("show run inter {}.{}".format((rtr2Int),(uut_dot1q2)))
        uut1.execute("show bridge-domain")
        
        
        #split_horizon_group_check
        efp_dict = { uut_efp1 : [uutInt1,0] ,uut_efp2 : [uutInt2,1] }
        
        for efp_id, interf_group in efp_dict.items():
            split_horizon_group_check( uut1, efp_id, interf_group[0], uut_bd1, interf_group[1]):
            logger.info("SHG showing wrong")
        
        
        #verify_ip_connectivity need to add
        
        uut1_config = '''
        interface {}
        service instance {} ethernet
        bridge-domain {} split-horizon group 0
        '''.format((uutInt2),(uut_efp2),(uut_bd1))
        uut1.configure(uut1_config)
        
        #split_horizon_group_check
        efp_dict = { uut_efp1 : [uutInt1,0] ,uut_efp2 : [uutInt2,0] }
        
        for efp_id, interf_group in efp_dict.items():
            split_horizon_group_check( uut1, efp_id, interf_group[0], uut_bd1, interf_group[1]):
            logger.info("SHG showing wrong")
        
    @aetest.cleanup
    def cleanup(self, uut1, rtr1, rtr2, uutInt1, uutInt2, rtr1Int, rtr2Int):
        logger.info("testcase2 unconfig...")
        
        uut1_unconfig = '''
        default interface {}
        default interface {}
        '''.format((uutInt1),(uutInt2))
        uut1.configure(uut1_unconfig)
        
        rtr1_unconfig = '''
        inter {}.{}
        no ip add
        no encap dot1q {}
        '''.format((rtr1Int),(uut_dot1q1),(uut_dot1q1))
        rtr1.configure(rtr1_unconfig)
       
        rtr2_unconfig = '''
        inter {}.{}
        no ip add
        no encap dot1q {}
        '''.format((rtr2Int),(uut_dot1q2),(uut_dot1q2))
        rtr2.configure(rtr2_unconfig)

class BDI_L3_STATIC(aetest.Testcase):
    
    uid ="BDI_L3_STATIC"
    
    @aetest.test
    def test (self, uut1, rtr1, rtr2, uutInt1, uutInt2, rtr1Int, rtr2Int):
        
        logger.info(banner("L3 FW/static route"))
        
        
        uut1_config = '''
        !
        interface {0}       
        no shut
        service instance {1} ethernet
        encapsulation dot1q {2}
        rewrite ingress tag pop 1 symmetric
        bridge-domain {3}
        !
        interface {4}
        no shut
        service instance {5} ethernet
        encapsulation dot1q {6}
        rewrite ingress tag pop 1 symmetric
        bridge-domain {7}     
        !
        interface BDI{3}
        ip address {8} {9}
        no shut
        !   
        interface BDI{7}
        ip address {10} {9}
        no shut
        !
        ip route {11} {9} BDI{3}
        !
        interface {0}
        shut
        no shut
        !
        interface {4}
        shut
        no shut
        '''.format((uutInt1)(uut_efp1)(uut_dot1q1)(uut_bd1)(uutInt2)(uut_efp2)(uut_dot1q2)(uut_bd2)(uut_bdi1_add)(mask_16)(uut_bdi2_add)(rtr1_loop_net))
        uu1.configure(uut1_config)
                
        rtr1_config = '''
        !
        interface Loopback100
        ip address {0} {1}
        !
        interface {2}.{3}
        encapsulation dot1Q {3}
        ip address {4} {1}
        !
        ip route {5} {1} {6}
        '''.format((rtr1_loop_add),(mask_16),(rtr1Int),(uut_dot1q1),(rtr1_uut_add),(uut_rtr2_net),(uut_rtr1_add))
        rtr1.configure(rtr1_config)
        
        rtr2_config = '''
        !
        interface {0}.{1}
        encapsulation dot1Q {1}
        ip address {2} {3}
        !
        ip route {4} {3} {5}
        '''.format((rtr2Int)(uut_dot1q2)(rtr2Int)(mask_16)(uut_rtr1_net)(uut_rtr2_add))
        rtr2.configure(rtr2_config)
        
               
        utu1.execute("show run inter $uutInt1")
        uut1.execute("show run inter $uutInt2")
        rtr1.execute("show run inter $rtr1Int.$uut_dot1q1")
        rtr2.execute("show run inter $rtr2Int.$uut_dot1q2")
        uut1.execute("show run inter BDI$uut_bd1")
        uut1.execute("show run inter BDI$uut_bd2")
        uut1.execute("show arp")
        uut1.execute("show inter BDI$uut_bd1")
        uut1.execute("show inter BDI$uut_bd2")
        uut1.execute("show bridge-domain")
        
        time.sleep(60)
        
        #ping Test
        if not ping_test(rtr1, rtr2_uut_add, ipv6 = False):
            self.failed("Ping failed")
        else:
            logger.info("Ping succeeded")
            
        if not ping_test(uut1, rtr1_loop_add, ipv6 = False):
            self.failed("Ping failed")
        else:
            logger.info("Ping succeeded")
                        
            
        for each_conf in ["inf_flap","efp_flap","bd_flap", "bdi_flap"]:           
            
            if "inf_flap" == each_conf:
                uut1_config = '''
                inter {}
                shut
                no shut
                !
                inter {}
                shut
                no shut
                '''.format((uutInt1),(uutInt2))
                uut1.configure(uut1_config)
                
                time.sleep(5)
                
            elif "efp_flap" == each_conf:
                uut1_config = '''
                interface {}
                service instance {} ethernet
                shutdown
                no shut
                !
                interface {}
                service instance {} ethernet
                shutdown
                no shut"
                '''.format((uutInt1),(uut_efp1),(uutInt2),(uut_efp2))
                uut1.configure(uut1_config)
                
                time.sleep(5)
                
            elif "bd_flap" == each_conf:
                uut1_config = '''
                bridge-domain {0}
                shut
                no shut
                !
                bridge-domain {0}
                shut
                no shut"
                '''.format(uut_bd1)
                uut1.configure(uut1_config)
                
                time.sleep(5)
                
            elif "bdi_flap" == each_conf:
                uut1_config ='''
                interface BDI{}
                shut
                no shut
                !
                interface BDI{}
                shut
                no shut
                '''.format((uut_bd1)(uut_bd2))
                uut1.configure(uut1_config)
                
        sleep.time(10)
        
        uut1.execute("clear counters")     
        uut1.execute("clear counters")
        uut1.execute("clear counters")
        
        time.sleep(5)
            
        #Verify IP connectivity between need to add
        
        #check_interface_stats
        
        #verify_ip_connectivity 
        
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
            default interface {}       
            default interface {}
            no interface BDI{}
            no interface BDI{}
            '''.format((uutInt1),(uutInt2),(uut_bd1),(uut_bd2))
            uut1.configure(uut1_unconfig)
        
            rtr1_config ='''
            no interface Loopback100
            !
            interface {}.{}
            no ip address {} {}
            no encap dot1Q $
            !
            no ip route {} {} {}
            '''.format((rtr1Int),(uut_dot1q1),(rtr1_uut_add),(mask_16),(uut_dot1q1),(uut_rtr2_net),(mask_16),(uut_rtr1_add))
            
            rtr2_config ='''        !
            interface {}.{}
            no ip address {} {}
            no encapsulation dot1Q {}
            !
            no ip route {} {} {}
            '''.format((rtr2Int),(uut_dot1q2),(rtr2_uut_add),(mask_16),(uut_dot1q2),(uut_rtr1_net),(mask_16),(uut_rtr2_add))
            
        except as Exception as e:
            self.failed("Unconfig failed")
            
            

   
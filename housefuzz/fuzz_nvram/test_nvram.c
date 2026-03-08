#include<stdio.h>
#include <unistd.h>
#include <stdlib.h>
#include<sys/types.h>
#include<time.h>
#include "nvram.h"

// total 30
char* key_case[] = {"wl0_channel", "usb_info_dev99", "wl0_ssid", "rip_multicast", "schedule_config", "wifi_wep_on4", "wan_fix_dns8",
                    "atm_pcr3", "dhcp_end_ip7", "pppoa_mtu4", "atm_mbs7", "voip_line1_enable", "TR_DRMD_ENABLE", "wl72_auth_mode", "leafp2p_remote_url",
                    "wl69_auth_mode", "wl160_wep", "genie_remote_certificate", "wl241_auth_mode", "acs_url2", "wps_sta_pin", "SC_ACCT_1_SIP_SEC_OUTBOUND_ADDR",
                    "WSC_UUID_Str1", "wl_stbc_rx","lan1_wps_oob", "wsc_device_name", "sso_url_3", "hacvuIV", "wl_hwaddr","wps_pbc_apsta_concurrent"};
char* value[] = {"a", "b", "c", "d", "e", "f"};
int main(){
    pid_t child_pid = fork();
    printf("start testing\n");
    if(child_pid == 0){
        // 子进程， 随机读取写入内容
        int begin, end;
        begin = clock();
        nvram_init_all();
        srand(time(0));
        for(int i = 0; i<10000; i++){
            int operation = rand()%2;
            int key_index = rand()%30;
            int value_index = rand()%6;
            if(operation == 0){
                nvram_get(key_case[key_index]);
            }else{
                nvram_set(key_case[key_index], value[value_index]);
            }
        }
        end = clock();
        printf("child time: %d\n", end-begin);
        printf("child end testing\n");
        
    }else{
        // 主进程，随机读取写入内容
        nvram_init_all();
        int begin, end;
        begin = clock();
        srand(time(0));
        for(int i = 0; i<10000; i++){
            int operation = rand()%2;
            int key_index = rand()%30;
            int value_index = rand()%6;
            if(operation == 0){
                nvram_get(key_case[key_index]);
            }else{
                nvram_set(key_case[key_index], value[value_index]);
            }
        }
        end = clock();
        printf("parent time: %d\n", end-begin);
        printf("parent end testing\n");
    }
    
}
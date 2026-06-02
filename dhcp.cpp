#include <DHCP_Starvation.h>
#include <CLI.h>

int main(int n_args,char **args){
    Interface interface;
    if(!cli_read_interface(interface,n_args,args,"--interface","Interface Name: ")){
        return 1;
    }

    DHCPSTARVATION starvation(interface.name.c_str());
    starvation.execute();
    return 0;
}

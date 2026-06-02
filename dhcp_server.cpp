#include <Packet.h>
#include <Utils.h>
#include <CLI.h>

int main(int n_args,char** args){
    
    Interface interface;
    if(!cli_read_interface(interface,n_args,args,"--interface","Interface Name: ")) return 1;

    int sock = socket(AF_INET,SOCK_DGRAM,0);
    if(sock == -1){
        printf("socket: failed\n");
        return 1;
    }
    
    sockaddr_in saddr = {0};
    saddr.sin_family = AF_INET;
    saddr.sin_port = htons(DHCP_SERVER_PORT);
    saddr.sin_addr.s_addr = interface.in_addr;
    if(bind(sock,(sockaddr*)&saddr,sizeof(saddr)) == -1){
        printf("bind: %s\n",strerror(errno));
        return 1;
    }

    printf("Prescione qualquer tecla para continuar.\n");
    (void)getchar();

    close(sock);

    return 0;
}

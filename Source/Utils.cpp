#include <Utils.h>

void print_percent_bar(int current,int final){
    fprintf(stdout,"\r\033[2K\033[38;5;208m[");
    float percent = (float)current / (float)final;
    int pos = percent * PERCENT_BAR_WIDTH;
    for(int x = 0; x < PERCENT_BAR_WIDTH; ++x){
        if(x < pos){
            printf("#");
        }
        else{
            printf(".");
        }
    }
    fprintf(stdout,"] %d%%\033[0m ",(int)(percent*100));
    fflush(stdout);
    if(percent >= 1.0f){
        printf("\r\033[2K");
    }
}

void clear_stdin(){
	int c;
	while((c = getchar()) != '\n' && c != EOF); 
}
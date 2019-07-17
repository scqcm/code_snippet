
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <getopt.h>
#include <unistd.h>
#include <errno.h>
#include <syslog.h>


static int iptables_init = 0;
static int iptables_get_ssh = 0;
static int iptables_set_ssh_drop = 0;
static int iptables_set_ssh_accept = 0;

static const char short_options[] =
	"h"
	;

#define CMD_LINE_OPT_IPTABLES_INIT              "init"
#define CMD_LINE_OPT_IPTABLES_GET_SSH           "get-ssh"
#define CMD_LINE_OPT_IPTABLES_SET_SSH_DROP      "set-ssh-drop"
#define CMD_LINE_OPT_IPTABLES_SET_SSH_ACCEPT    "set-ssh-accept"

enum {
	/* long options mapped to a short option */

	/* first long only option value must be >= 256, so that we won't
	 * conflict with short options */
	CMD_LINE_OPT_MIN_NUM = 256,
};

static const struct option lgopts[] = {
	{ CMD_LINE_OPT_IPTABLES_INIT, no_argument, &iptables_init, 1},
	{ CMD_LINE_OPT_IPTABLES_GET_SSH, no_argument, &iptables_get_ssh, 1},
    { CMD_LINE_OPT_IPTABLES_SET_SSH_DROP, no_argument, &iptables_set_ssh_drop, 1},
    { CMD_LINE_OPT_IPTABLES_SET_SSH_ACCEPT, no_argument, &iptables_set_ssh_accept, 1},
	{NULL, 0, 0, 0}
};

static void
prg_usage(const char *prgname)
{
	printf("%s\n"
		   "  --init: initialize the iptables\n"
		   "  --get-ssh: 0 is drop, 1 is accept\n"
		   "  --set-ssh-drop: drop the tcp packet of ssh\n"
		   "  --set-ssh-accept: accept the tcp packet of ssh\n",
	       prgname);
}

static int
parse_args(int argc, char **argv)
{
	int opt, ret, timer_secs;
	char **argvopt;
	int option_index;
	char *prgname = argv[0];

	argvopt = argv;

	while ((opt = getopt_long(argc, argvopt, short_options,
				  lgopts, &option_index)) != EOF) {

		switch (opt) {
		/* long options */
		case 0:
			break;

		default:
			prg_usage(prgname);
			return -1;
		}
	}

	if (optind >= 0)
		argv[optind-1] = prgname;

	ret = optind-1;
	optind = 1; /* reset getopt lib */
	return ret;
}

void
popen_cmd(char *cmd)
{
    FILE *fp_cmd;
    
    
    fp_cmd = popen(cmd, "r");
    if (fp_cmd != NULL) {
        syslog(LOG_INFO, "%s. pass success.\n", cmd);
        pclose(fp_cmd);
    } else {
        syslog(LOG_INFO, "%s. pass fail.\n", cmd);
    }
}
#define NGMIMIC_FILEPATH "/hard_disk/boot/ngmimic.config"
//#define NGMIMIC_FILEPATH "./ngmimic.config"

int
main(int argc, char **argv)
{
	int ret;
    int i = 0;
    int groupid;
    char mgt_name[2][256] = {0};
    char line_buf[1024];
    FILE *fp;
    FILE *fp_cmd;
    
    openlog(0, LOG_CONS|LOG_NDELAY|LOG_PID, LOG_USER);
    
	/* parse application arguments */
	ret = parse_args(argc, argv);
	if (ret < 0) {
		syslog(LOG_ERR, "Invalid arguments\n");
        return 0;
    }
    /*get the name of management ports.*/
    fp = fopen(NGMIMIC_FILEPATH, "r");
    if (NULL == fp) {
        syslog(LOG_ERR, "[%s-%d]""Fail to open %s. error_string:%s.\n",
            __FUNCTION__, __LINE__, NGMIMIC_FILEPATH, strerror(errno));
        return 0;
    }
    
    i = 0;
    fgets(line_buf, 1000, fp);
    while (fgets(line_buf, 1000, fp) != NULL) {
        char temp_name[256] = "eth";
        ret = sscanf(line_buf, "eth%[^ ]", temp_name+3);
        temp_name[255] = '\0';
        if (0 == ret) {
            continue;
        }      
        
        ret = sscanf(line_buf, "%*[^ ]%*[ ]%*[^ ]%*[ ]%d", &groupid);
        if (0 == ret) {
            continue;
        }
        
        if (0 == groupid) {
            if (0 == i) {
                memcpy(mgt_name[i], temp_name, strlen(temp_name));
                i++;
            } else {
                memcpy(mgt_name[i], temp_name, strlen(temp_name));
                i++;
                break;
            }
            
        }
    }
    
    if (0 == i) {
        syslog(LOG_ERR, "[%s-%d]""Fail to get MGT port name.",
            __FUNCTION__, __LINE__);
        return 0;
    }
    syslog(LOG_INFO, "mgt1_name = %s\n", mgt_name[0]);
    syslog(LOG_INFO, "mgt2_name = %s\n", mgt_name[1]);
    
    if (iptables_init) {
        while (i) {
            i--;
            memset(line_buf, 0, sizeof(line_buf));
            sprintf(line_buf, "iptables -A INPUT -p tcp --dport 3306 -j DROP -i %s", mgt_name[i]);
            popen_cmd(line_buf);
            
            memset(line_buf, 0, sizeof(line_buf));
            sprintf(line_buf, "iptables -A INPUT -p tcp --dport 22 -j DROP -i %s", mgt_name[i]);
            popen_cmd(line_buf);
            
            memset(line_buf, 0, sizeof(line_buf));
            sprintf(line_buf, "iptables -A INPUT -p tcp --dport 80 -j DROP -i %s", mgt_name[i]);
            popen_cmd(line_buf);

            memset(line_buf, 0, sizeof(line_buf));
            sprintf(line_buf, "iptables -A INPUT -p tcp --dport 2601 -j DROP -i %s", mgt_name[i]);
            popen_cmd(line_buf);

            memset(line_buf, 0, sizeof(line_buf));
            sprintf(line_buf, "iptables -A INPUT -p icmp -j DROP -i %s", mgt_name[i]);
            popen_cmd(line_buf);
        }
    } else if (iptables_get_ssh) {
        char buf[128] = {0};
        memset(line_buf, 0, sizeof(line_buf));
        sprintf(line_buf, "iptables -L INPUT | grep \"dpt:ssh\" | wc -l");   
        fp_cmd = popen(line_buf, "r");
        syslog(LOG_INFO, "%s\n", line_buf);
        fgets(buf,120,fp_cmd);
        pclose(fp_cmd);
        if (atoi(buf)) 
            ret = 1;
        else
            ret = 0;
	printf("%d", ret);
    } else if (iptables_set_ssh_drop) {
        char buf[128] = {0};
        memset(line_buf, 0, sizeof(line_buf));
        sprintf(line_buf, "iptables -L INPUT | grep \"dpt:ssh\" | wc -l");   
        fp_cmd = popen(line_buf, "r");
        syslog(LOG_INFO, "%s\n", line_buf);
        fgets(buf,120,fp_cmd);
        pclose(fp_cmd);
        if (0 == atoi(buf)) {
            while (i) {
                i--;
                memset(line_buf, 0, sizeof(line_buf));  
                sprintf(line_buf, "iptables -A INPUT -p tcp --dport 22 -j DROP -i %s", mgt_name[i]);
                popen_cmd(line_buf);
            }
        }
    } else if (iptables_set_ssh_accept) {
        char buf[128] = {0};
        memset(line_buf, 0, sizeof(line_buf));
        sprintf(line_buf, "iptables -L INPUT | grep \"dpt:ssh\" | wc -l");   
        fp_cmd = popen(line_buf, "r");
        syslog(LOG_INFO, "%s\n", line_buf);
        fgets(buf,120,fp_cmd);
        pclose(fp_cmd);
        if (atoi(buf)) {
            while (i) {
                i--;
                memset(line_buf, 0, sizeof(line_buf));
                sprintf(line_buf, "iptables -D INPUT -p tcp --dport 22 -j DROP -i %s", mgt_name[i]);
                popen_cmd(line_buf);
            }
        }
    }
    
    fclose(fp);
    closelog();
    return ret;
}

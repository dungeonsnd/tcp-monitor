#include "plugin_interface.h"
#include "common_define.h"
#include <unistd.h>
#include <map>
#include <list>

#define VER "0.1"

struct IpPort
{
    unsigned src_ip;
    unsigned src_port;
    unsigned dst_ip;
    unsigned dst_port;
    
    IpPort(){
        src_ip=0;
        src_port=0;
        dst_ip=0;
        dst_port=0;
    }
    bool operator <(const IpPort & other) const
    {
        if(src_ip>other.src_ip)
            return false;
        else if(src_ip<other.src_ip)
            return true;
        else if(src_port>other.src_port)
            return false;
        else if(src_port<other.src_port)
            return true;
        else if(dst_ip>other.dst_ip)
            return false;
        else if(dst_ip<other.dst_ip)
            return true;
        else if(dst_port>other.dst_port)
            return false;
        else if(dst_port<other.dst_port)
            return true;
        else
            return false;
    }
};

struct PacketInfo
{
    time_t _lasttime_all;
    time_t _lasttime_payload;
    time_t _lasttime_flag;
    
    PacketInfo():_lasttime_all(0),_lasttime_payload(0),_lasttime_flag(0)
    {
    }
};

std::map < IpPort , PacketInfo* > g_packet;


#include <pthread.h>
pthread_t thread_id =0;
pthread_mutex_t g_mutex;

static void * thread_start(void *arg)
{    
    while(1)
    {
        usleep(3*1000000);
        
        pthread_mutex_lock(&g_mutex);
        
        printf("    ---- tcp-monitor v%s jeffery dungeonsnd@126.com ---- \n",VER);
        
        // 排序
        std::list <IpPort> lst_IpPort;
        std::list <PacketInfo*> lst_PacketInfo;        
        for(std::map < IpPort , PacketInfo* > ::iterator it =g_packet.begin();
            it!=g_packet.end();it++)
        {
            for(std::list <PacketInfo*>::iterator iter =lst_PacketInfo.begin();
                iter!=lst_PacketInfo.end();iter++)
            {
                if(it->second._lasttime_payload<=iter->_lasttime_payload)
                    break;
            }
        }
        
        // 显示      
        for(std::map < IpPort , PacketInfo* > ::iterator it =g_packet.begin();
            it!=g_packet.end();it++)
        {
            char ip0[20] ={0};
            inet_ntop(AF_INET,(void*)(&it->first.src_ip),ip0,sizeof(ip0));
            char ip1[20] ={0};
            inet_ntop(AF_INET,(void*)(&it->first.dst_ip),ip1,sizeof(ip1));
            printf("%s:%d %s:%d\t", ip0,ntohs(it->first.src_port), ip1,ntohs(it->first.dst_port));

            time_t nowsec =time(NULL)+3600*8;
            
            struct tm gmt;
            bzero(&gmt,sizeof(tm));
            gmtime_r(&(it->second->_lasttime_all), &gmt);
            printf("%02d:%02d:%02d(%dsec)\t",gmt.tm_hour,gmt.tm_min,gmt.tm_sec, 
                it->second->_lasttime_all==0?-1:unsigned(nowsec-it->second->_lasttime_all));
            
            bzero(&gmt,sizeof(tm));
            gmtime_r(&(it->second->_lasttime_payload), &gmt);
            printf("%02d:%02d:%02d(%dsec)\t",gmt.tm_hour,gmt.tm_min,gmt.tm_sec, 
                it->second->_lasttime_payload==0?-1:unsigned(nowsec-it->second->_lasttime_payload));
            
            bzero(&gmt,sizeof(tm));
            gmtime_r(&(it->second->_lasttime_flag), &gmt);
            printf("%02d:%02d:%02d(%dsec)\n",gmt.tm_hour,gmt.tm_min,gmt.tm_sec, 
                it->second->_lasttime_flag==0?-1:unsigned(nowsec-it->second->_lasttime_flag));
        }
        
        pthread_mutex_unlock(&g_mutex);
    }
    return NULL;
}
       
       
int plugin_myapp_parser_entry(const struct PluginData * data)
{
    if(thread_id!=0)
        pthread_mutex_lock(&g_mutex);
    
    IpPort ipport;
    ipport.src_ip =(unsigned)(data->ip_src.s_addr);
    ipport.src_port =data->th_sport;
    ipport.dst_ip =(unsigned)(data->ip_dst.s_addr);
    ipport.dst_port =data->th_dport;
    
    PacketInfo * packetInfo =NULL;
    
    std::map < IpPort , PacketInfo* > ::iterator it =g_packet.find(ipport);
    if(it!=g_packet.end())
    {
        packetInfo =it->second;
    }
    else
    { 
        packetInfo =new PacketInfo();
        g_packet[ipport] =packetInfo;
    }
    
    packetInfo->_lasttime_all =data->tv.tv_sec+3600*8;
    if(data->size_payload>0)
        packetInfo->_lasttime_payload =data->tv.tv_sec+3600*8;
    else
        packetInfo->_lasttime_flag =data->tv.tv_sec+3600*8;
    
    if(thread_id!=0)
        pthread_mutex_unlock(&g_mutex);
        
    if(thread_id==0)
    {
        int rt =pthread_create(&thread_id, NULL,&thread_start, NULL);
        if (rt!=0)
            printf("pthread_create failed! errno=%d,%s \n",errno,strerror(errno));
        pthread_mutex_init(&g_mutex,NULL);
    }
    
    return 0;
}


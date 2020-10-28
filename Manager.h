#include <vector>
#include "Host.h"
#include <functional>
//��װһ��snmp���������̣������ṩһЩ�ӿ�

class Manager
{
public:
    Manager();
    ~Manager();

    void set_func(std::function<bool(Host, snmp_pdu*)> f);
    
    void run();
    void stop();
    void add_host(Host* h);
    void handle_data(Host* h, snmp_pdu* p);
    void set_interval(uint32_t i);

    //�����һ�����������oid�ı�ݽӿ�
    //bool add_host_info(std::vector<char*> hosts, std::vector<char*> oids);

private:
    void init_sessions();
    void asyn_send();
    void wait_request();

private:
    std::vector<Host*>          m_hosts;
    std::function<bool(Host,snmp_pdu*)>   m_handleFunc;   //�����յ���������ʱ�Ĵ�����
    bool                        m_running;
    uint32_t                    m_sendCount = 0;
    uint32_t                    m_loopInterval;
};

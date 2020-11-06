#include "Manager.h"
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <sys/select.h>
#include <string>
#include <iostream>

using namespace std;

Manager* pManager = nullptr;

int async_response(int operation, struct snmp_session *sp, int reqid,struct snmp_pdu *pdu, void *magic)
{
    Host* h = static_cast<Host*>(magic);
    if(pManager)
    {
        if (operation == NETSNMP_CALLBACK_OP_RECEIVED_MESSAGE) 
        {
           pManager->handle_data(STAT_SUCCESS,h,pdu);
        }
        else
        {
           pManager->handle_data(STAT_TIMEOUT,h,pdu);
        }
    }
    else
    {
        cout<<"pManager == nullptr"<<endl;
        return 1;
    }
    return 0;
}

Manager::Manager()
{
    m_running = false;
    m_hosts.clear();
    pManager = this;
    m_loopInterval = 1;
    m_sendCount = 0;
}

Manager::~Manager()
{

}

void Manager::add_host(Host* h)
{
    m_hosts.push_back(h);
}

void Manager::handle_data(int status, Host* h, snmp_pdu* p)
{
    --m_sendCount;
    m_handleFunc(status, *h, p);
}

void Manager::set_interval(uint32_t i)
{
    m_loopInterval = i;
}

void Manager::init_sessions()
{
    
    for(auto &h : m_hosts)
    {
        netsnmp_session     session;
        netsnmp_pdu*        pdu;

        snmp_sess_init(&session);
        session.peername = const_cast<char*>(h->ip.c_str());
        session.retries = 1;
        session.timeout = (long)(5 * 1000000L);;
        session.remote_port = 161;
        
        //session.version = SNMP_VERSION_2c;
        //session.community = (u_char*)strdup("public");
        //session.community_len = strlen("public");

        //snmpwalk -v 3 -a MD5 -A testUserA -x DES -X testUserX -l authPriv -u user localhost system

        
        session.version = SNMP_VERSION_3;
        session.securityName = strdup("user");
        session.securityNameLen = strlen(session.securityName);

        const char *auth_v3_passphrase = "testUserA";
        const char *priv_v3_passphrase = "testUserX";


        session.securityLevel = SNMP_SEC_LEVEL_AUTHPRIV;

        session.securityAuthProto = usmHMACMD5AuthProtocol;
        session.securityAuthProtoLen = USM_AUTH_PROTO_MD5_LEN;
        session.securityAuthKeyLen = USM_AUTH_KU_LEN;
       
        session.securityPrivProto = usmDESPrivProtocol;
        session.securityPrivProtoLen = USM_PRIV_PROTO_DES_LEN;
        session.securityPrivKeyLen = USM_PRIV_KU_LEN;


        if (generate_Ku(session.securityAuthProto,
             session.securityAuthProtoLen,
             (u_char *) auth_v3_passphrase, strlen(auth_v3_passphrase),
             session.securityAuthKey,
             &session.securityAuthKeyLen) != SNMPERR_SUCCESS)
        {  
           snmp_log(LOG_ERR,
                 "Error generating Ku from authentication pass phrase. \n");
           exit(1);
        }  

        if (generate_Ku(session.securityAuthProto,
             session.securityAuthProtoLen,
             (u_char *) priv_v3_passphrase, strlen(priv_v3_passphrase),
             session.securityPrivKey,
             &session.securityPrivKeyLen) != SNMPERR_SUCCESS)
        {
           snmp_log(LOG_ERR,"Error generating Ku from authentication pass phrase. \n");
           exit(1);
        }

        session.callback = async_response;
        session.callback_magic = h;

        h->pSession = snmp_open(&session);
    }
}

void Manager::asyn_send()
{
    for(auto &h : m_hosts)
    {
        struct snmp_pdu* pdu = snmp_pdu_create(SNMP_MSG_GET);
        for(auto &oid : h->listOid)
        {
            snmp_add_null_var(pdu, oid.o, oid.length);
        }
        if(snmp_send(h->pSession, pdu))
        {
            ++m_sendCount;
        }
        else
        {
            //cout<<"snmp_send error!"<<endl;
            snmp_perror("snmp_send");
            snmp_free_pdu(pdu);
        }
    }
}

void Manager::wait_request()
{
    while(m_sendCount>0)
    {

       int fds = 0, block = 1;
       fd_set fdset;
       struct timeval timeout;

       FD_ZERO(&fdset);
       snmp_select_info(&fds, &fdset, &timeout, &block);
       fds = select(fds, &fdset, NULL, NULL, block ? NULL : &timeout);
       if (fds < 0) {
          perror("select failed");
          exit(1);
       }
       if (fds)
           snmp_read(&fdset);
       else
           snmp_timeout();
   }
}


void Manager::run()
{
    m_running = true;
    if(m_hosts.empty())
    {
        cout<<"no host!"<<endl;
        return;
    }
    init_sessions();

    //while(m_running)
    //{
        asyn_send();
        wait_request();
        //sleep(m_loopInterval);
    //}
}

void Manager::stop()
{
    
}

void Manager::set_func(std::function<bool(int, Host, snmp_pdu*)> f)
{
    m_handleFunc = f;
}


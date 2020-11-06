#include "Manager.h"
#include <stdlib.h>
#include <iostream>
using namespace std;

const char* hosts[2]={
    "127.0.0.2",
    "127.0.0.1"
};

const char* oids[4]={
    ".1.3.6.1.2.1.1.1.0",
    ".1.3.6.1.2.1.1.3.0",
    ".1.3.6.1.2.1.1.4.0",
    ".1.3.6.1.2.1.1.5.0"
};

void print_result(int status, struct snmp_session* sp, struct snmp_pdu* pdu);

bool test(int status, Host h, snmp_pdu* p)
{
    //cout<<" test called"<<endl;
    print_result(status, h.pSession, p);
}

void print_result(int status, struct snmp_session* sp, struct snmp_pdu* pdu)
{
    /*
    struct variable_list *vp;
    vp = pdu->variables;

    if(!pdu->errstat == SNMP_ERR_NOERROR)
    {
        cout<<"errstst false!"<<endl;
        exit(1);
    }
    char buf[1024];
    while(vp)
    {
        snprint_variable(buf, sizeof(buf), vp->name, vp->name_length, vp);
        fprintf(stdout, "%s : %s\n", sp->peername, buf);
        vp = vp->next_variable;
    }
    */

  char buf[1024];
  struct variable_list *vp;
  int ix;
  struct timeval now;
  struct timezone tz;
  struct tm *tm;

  //gettimeofday(&now, &tz);
  //tm = localtime(&now.tv_sec);
  //fprintf(stdout, "%.2d:%.2d:%.2d.%.6d ", tm->tm_hour, tm->tm_min, tm->tm_sec,now.tv_usec);
  
  switch (status) 
  {
     case STAT_SUCCESS:
                        vp = pdu->variables;
                        if (pdu->errstat == SNMP_ERR_NOERROR) 
                        {
                           while (vp) 
                           {
                              snprint_variable(buf, sizeof(buf), vp->name, vp->name_length, vp);
                              fprintf(stdout, "%s: %s\n", sp->peername, buf);
	                      vp = vp->next_variable;
                           }
                        }      
                        else 
                        {
                           for (ix = 1; vp && ix != pdu->errindex; vp = vp->next_variable, ix++);
                           if (vp) 
                              snprint_objid(buf, sizeof(buf), vp->name, vp->name_length);
                           else 
                              strcpy(buf, "(none)");
      
                           fprintf(stdout, "%s: %s: %s\n",sp->peername, buf, snmp_errstring(pdu->errstat));
                        } 
                        break;
     case STAT_TIMEOUT:
                        fprintf(stdout, "%s: Timeout\n", sp->peername);
                        break;
     case STAT_ERROR:
                        snmp_perror(sp->peername);
  }
}

int main()
{
    Manager m;
    
    SOCK_STARTUP;
    init_snmp("snmpapp");

    for(int i=0; i<2; i++)
    {
        Host *h = new Host();;
        h->hostName = "Host"+std::to_string(i);
        h->ip = std::string(hosts[i]);
        h->pSession = nullptr;
        h->listOid.clear();
        for(int j=0; j<4; j++)
        {
            cc_oid o;
            o.length = MAX_OID_LEN;
            if(!read_objid(oids[j], o.o, &o.length))
            {
                cout<<"read_objid failed!"<<endl;
                return 1;
            }
            h->listOid.push_back(o);
        }
        m.add_host(h);
    }

    m.set_func(test);
    m.run();
    //while(1)
    //;
}

#pragma once

#include "stdafx.h"

#include <string>
using namespace std;

#include <libssh2.h>
#include <libssh2_sftp.h>

#ifdef HAVE_WINDOWS_H
# include <windows.h>
#endif
#ifdef HAVE_WINSOCK2_H
# include <winsock2.h>
#endif
#ifdef HAVE_SYS_SOCKET_H
# include <sys/socket.h>
#endif
#ifdef HAVE_NETINET_IN_H
# include <netinet/in.h>
#endif
# ifdef HAVE_UNISTD_H
#include <unistd.h>
#endif
# ifdef HAVE_ARPA_INET_H
#include <arpa/inet.h>
#endif

#include <sys/types.h>
#include <fcntl.h>
#include <errno.h>
#include <stdio.h>
#include <ctype.h>
#include <string>

class CSshConnect
{
public:
    CSshConnect();
    ~CSshConnect();
    bool Connect();
    bool Disconnect();
    bool SendCmdAndReceive( string strCmd, string & strReceive, string & strStdError );
    bool SetHostAddr( string strHost );
    bool SetUserPass( string strUserName, string strPassword );
    bool SetConnectTimeout( unsigned int uiTimeoutMs );
private:
    int WaitSocket(int socket_fd, LIBSSH2_SESSION *session);            
    bool CreateSocket();

    string m_strUserName;
    string m_strPassword;
    string m_strCommand;
    string m_strHostAddr;

    LIBSSH2_SESSION * m_pSession;
    LIBSSH2_CHANNEL * m_pChannel;
    int m_sock;
    int m_rc;
    unsigned int m_uiTimeoutUs; //defaulted to 1sec timeout
};

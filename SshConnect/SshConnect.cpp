//=============================================================================
// Copyright (C) 2012 Sierra Wireless Inc. All rights reserved.
//
// File:                SshConnect.cpp
//
// Class(es):   CSshConnect
//
// Author(s):   
//
// Summary:             Wrapper class of libssh2 to connect, disconnect, send and receive information to remote SSH server
//
// Notes:               
//
//=============================================================================
// Version   Date          Author  Change    Description
//-----------------------------------------------------------------------------
//   4.2.0   07-Nov-2014   B.L.    00000     Created class. To be used in BFT.
//   4.2.0   07-Nov-2014   B.L.    00000     Added destructor. Minor modification to Disconnect().
//   4.2.0   07-Nov-2014   B.L.    00000     Added CreateSocket() helper, SetConnectTimeout(). Adjusted spacing format.
//   4.2.0   10-Nov-2014   B.L.    00000     Added m_sock and m_pSession checks in SendCmdAndReceive().
//   4.2.0   14-Nov-2014   B.L.    00000     Added strStdError parameter to SendCmdAndReceive() for standard error messages.
//   4.2.0   15-Nov-2014   B.L.    00000     Changed to use libssh2_channel_write() instead of libssh2_channel_exec() in SendCmdAndReceive(). Moved libssh2_channel_shell() from Connect() to SendCmdAndReceive(). Commented out stdout fprintf statements.
//=============================================================================

#include "stdafx.h"

#include "SshConnect.h"

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

using namespace std;

CSshConnect::CSshConnect() : m_uiTimeoutUs(1000000), m_pSession(0), m_pChannel(0), m_sock(0), m_rc(0)
{

}

CSshConnect::~CSshConnect()
{
    Disconnect();
}

bool CSshConnect::Connect( void )
{
    const char *fingerprint;
    char *userauthlist;
    int auth_pw = 0;

    bool bRet = true;

    bRet = CreateSocket();
    if( !bRet )
    {
        return false;
    }

    /* Create a m_pSession instance and start it up. This will trade welcome
     * banners, exchange keys, and setup crypto, compression, and MAC layers
     */
    m_pSession = libssh2_session_init();
    if (libssh2_session_handshake(m_pSession, m_sock)) {
        fprintf(stderr, "Failure establishing SSH m_pSession\n");
        return false;
    }

    /* At this point we havn't authenticated. The first thing to do is check
     * the hostkey's fingerprint against our known hosts Your app may have it
     * hard coded, may go to a file, may present it to the user, that's your
     * call
     */
    fingerprint = libssh2_hostkey_hash(m_pSession, LIBSSH2_HOSTKEY_HASH_SHA1);
//    fprintf(stdout, "Fingerprint: ");
//    for(int i = 0; i < 20; i++) {
//        fprintf(stdout, "%02X ", (unsigned char)fingerprint[i]);
//    }
//    fprintf(stdout, "\n");

    /* check what authentication methods are available */
    userauthlist = libssh2_userauth_list(m_pSession, m_strUserName.c_str(), m_strUserName.length());
//    fprintf(stdout, "Authentication methods: %s\n", userauthlist);
    if (strstr(userauthlist, "password") != NULL) {
        auth_pw |= 1;
    }
    if (strstr(userauthlist, "keyboard-interactive") != NULL) {
        auth_pw |= 2;
    }
    if (strstr(userauthlist, "publickey") != NULL) {
        auth_pw |= 4;
    }

    if (auth_pw & 1) {
        /* We could authenticate via password */
        if ( libssh2_userauth_password( m_pSession, m_strUserName.c_str(), m_strPassword.c_str() ) ) {
            fprintf( stderr, "Ssh authentication by password failed!\n");
            return false;
        } else {
//            fprintf( stdout, "Ssh authentication by password succeeded.\n");
        }
    } /*else if (auth_pw & 2) {
      // Or via keyboard-interactive
      if (libssh2_userauth_keyboard_interactive(m_pSession, username,
      &kbd_callback) ) {
      fprintf(stderr,
      "\tAuthentication by keyboard-interactive failed!\n");
      goto shutdown;
      } else {
      fprintf(stderr,
      "\tAuthentication by keyboard-interactive succeeded.\n");
      }
      } else if (auth_pw & 4) {
      // Or by public key 
      if (libssh2_userauth_publickey_fromfile(m_pSession, username, keyfile1,
      keyfile2, password)) {
      fprintf(stderr, "\tAuthentication by public key failed!\n");
      goto shutdown;
      } else {
      fprintf(stderr, "\tAuthentication by public key succeeded.\n");
      }
      } */
    else {
        fprintf(stderr, "Ssh no supported authentication methods found!\n");
        return false;
    }

    /* Request a shell */
    if (!(m_pChannel = libssh2_channel_open_session(m_pSession))) {
        fprintf(stderr, "Ssh unable to open a m_pSession\n");
        return false;
    }

    /* Some environment variables may be set,
     * It's up to the server which ones it'll allow though
     */
    //libssh2_channel_setenv(m_pChannel, "FOO", "bar");

    ///* Request a terminal with 'vanilla' terminal emulation
    // * See /etc/termcap for more options
    // */
    //if (libssh2_channel_request_pty(m_pChannel, "vanilla")) {
    //    fprintf(stderr, "Failed requesting pty\n");
    //    goto skip_shell;
    //}

    return bRet;
}

bool CSshConnect::Disconnect( void )
{
    bool bRet = true;

    if( m_sock )
    {
        if( m_pSession )
        {
            libssh2_session_disconnect(m_pSession, "Normal Shutdown");
            libssh2_session_free(m_pSession);
            m_pSession = 0;
        }
    }

#ifdef WIN32
    if( m_sock )
    {
        closesocket(m_sock);
        m_sock = 0;
    }
#else
    if( m_sock )
    {
        close(m_sock);
        m_sock = 0;
    }
#endif
//    fprintf(stdout, "all done!\n");

    libssh2_exit();

    return bRet;
}

int CSshConnect::WaitSocket(int socket_fd, LIBSSH2_SESSION *m_pSession)
{
    int rc;
    struct timeval timeout;
    fd_set fd;
    fd_set *writefd = NULL;
    fd_set *readfd = NULL;
    int dir;

    timeout.tv_sec = 0;
    timeout.tv_usec = m_uiTimeoutUs;

    FD_ZERO(&fd);

    FD_SET(socket_fd, &fd);

    /* now make sure we wait in the correct direction */
    dir = libssh2_session_block_directions(m_pSession);

    if(dir & LIBSSH2_SESSION_BLOCK_INBOUND)
        readfd = &fd;

    if(dir & LIBSSH2_SESSION_BLOCK_OUTBOUND)
        writefd = &fd;

    rc = select(socket_fd + 1, readfd, writefd, NULL, &timeout);

    return rc;
}

bool CSshConnect::CreateSocket()
{
    unsigned long hostaddr;
    struct sockaddr_in sin;

#ifdef WIN32
    WSADATA wsadata;

    WSAStartup(MAKEWORD(2,0), &wsadata);
#endif

    hostaddr = inet_addr( m_strHostAddr.c_str() );

    m_rc = libssh2_init(0);
    if (m_rc != 0) {
        fprintf (stderr, "libssh2 initialization failed (%d)\n", m_rc);
        return false;
    }

    /* Ultra basic "connect to port 22 on localhost".  Your code is
     * responsible for creating the socket establishing the connection
     */
    m_sock = socket(AF_INET, SOCK_STREAM, 0);

    sin.sin_family = AF_INET;
    sin.sin_port = htons(22); //port 22
    sin.sin_addr.s_addr = hostaddr;

    // Set the socket I/O mode: In this case FIONBIO
    // enables or disables the blocking mode for the 
    // socket based on the numerical value of iMode.
    // If iMode = 0, blocking is enabled; 
    // If iMode != 0, non-blocking mode is enabled.
    unsigned long iMode = 1;
    int iResult = ioctlsocket(m_sock, FIONBIO, &iMode);
    if (iResult != NO_ERROR)
    {   
        fprintf( stderr, "Ssh ioctlsocket failed with error: %ld\n", iResult);
        return false;
    }

    int iRet = connect(m_sock, (struct sockaddr*)(&sin), sizeof(struct sockaddr_in));

    // If connected, it will return 0, or error
    if( iRet == SOCKET_ERROR )
    {
        long int Err = WSAGetLastError();
        // Check if the error was WSAEWOULDBLOCK, where we'll wait.
        if (Err == WSAEWOULDBLOCK)
        {
//            fprintf( stdout, "\nConnect() returned WSAEWOULDBLOCK. Need to Wait..");
            fd_set         Write, Err;
            TIMEVAL        Timeout;

            FD_ZERO(&Write);
            FD_ZERO(&Err);
            FD_SET(m_sock, &Write);
            FD_SET(m_sock, &Err);

            Timeout.tv_sec  = 0;
            Timeout.tv_usec = m_uiTimeoutUs; // your timeout

            iRet = select (0,                // ignored
                           NULL,           // read,
                           &Write,        // Write Check
                           &Err,            // Error check
                           &Timeout);

            if( iRet == 0 )
            {
                fprintf( stderr, "Ssh Connect Timeout (%d Sec).", Timeout.tv_sec);
                return false;
            }
            else
            {
                if (FD_ISSET(m_sock, &Write))
                {
//                    fprintf( stdout, "\nConnected...");
                    return true;
                }
                if (FD_ISSET(m_sock, &Err))
                {
                    fprintf( stderr,"Ssh Select() Error.");
                    return false;
                }
            }
        }
        else
            fprintf( stderr, "Ssh connect Error %d", WSAGetLastError() );
        return false;
    }
    else
    {
//        printf("\nWoooo!! got connected with NO Waiting!!");
        return true;
    }
}

bool CSshConnect::SendCmdAndReceive( string strCmd, string & strReceive, string & strStdError )
{
    bool bRet = true;
    
    if( !m_sock || !m_pSession )
    {
        bRet = false;
        return bRet;
    }

    int bytecount = 0;
    
    strReceive = "";
    strStdError = "";

    /* At this point the shell can be interacted with using
     * libssh2_channel_read()
     * libssh2_channel_read_stderr()
     * libssh2_channel_write()
     * libssh2_channel_write_stderr()
     *
     * Blocking mode may be (en|dis)abled with: libssh2_channel_set_blocking()
     * If the server send EOF, libssh2_channel_eof() will return non-0
     * To send EOF to the server use: libssh2_channel_send_eof()
     * A m_pChannel can be closed with: libssh2_channel_close()
     * A m_pChannel can be freed with: libssh2_channel_free()
     */

    /* Exec non-blocking on the remove host */
    while( NULL == ( m_pChannel = libssh2_channel_open_session(m_pSession) ) &&
           LIBSSH2_ERROR_EAGAIN == libssh2_session_last_error(m_pSession,NULL,NULL,0) )
    {
        WaitSocket(m_sock, m_pSession);
    }
    if( 0 == m_pChannel )
    {
        fprintf(stderr,"Ssh channel open session error\n");
        bRet = false;
        return bRet;
    }
    
    /* Open a SHELL on that pty */
    if (libssh2_channel_shell(m_pChannel)) {
        fprintf(stderr, "Ssh unable to request shell\n");
        return false;
    }
        
//    while( LIBSSH2_ERROR_EAGAIN == ( m_rc = libssh2_channel_exec( m_pChannel, strCmd.c_str() ) ) ) //some commands doesn't get executed for unknown reason
    while( LIBSSH2_ERROR_EAGAIN == ( m_rc = libssh2_channel_write(m_pChannel, strCmd.c_str(), strlen(strCmd.c_str())) ) )
    {
        WaitSocket(m_sock, m_pSession);
    }
    libssh2_channel_send_eof( m_pChannel );
    if( m_rc < 0 )
    {
        fprintf(stderr," Ssh channel write error\n");
        bRet = false;
        return bRet;
    }

    for( ;; )
    {
        /* loop until we block */
        int rc;
        do
        {
            char buffer[0x4000];
            rc = libssh2_channel_read( m_pChannel, buffer, sizeof(buffer) );
            if( rc > 0 )
            {
                bytecount += rc;
//                fprintf(stderr, "Read %d number of bytes.\n", bytecount);
                buffer[rc] = 0; // terminate the string
                strReceive += string( buffer ); //save string to output
            }
            else {
                if( rc != LIBSSH2_ERROR_EAGAIN )
                {
                    /* no need to output this for the EAGAIN case */
                    //fprintf(stderr, "libssh2_channel_read returned %d\n", rc);
                }
            }
        }
        while( rc > 0 );

        do
        {
            char buffer[0x4000];
            rc = libssh2_channel_read_stderr( m_pChannel, buffer, sizeof(buffer) );
            if( rc > 0 )
            {
                bytecount += rc;
//                fprintf(stderr, "Read %d number of bytes.\n", bytecount);
                buffer[rc] = 0; // terminate the string
                strStdError += string( buffer ); //save string to output
            }
            else {
                if( rc != LIBSSH2_ERROR_EAGAIN )
                {
                    /* no need to output this for the EAGAIN case */
                    //fprintf(stderr, "libssh2_channel_read returned %d\n", rc);
                }
            }
        }
        while( rc > 0 );


        /* this is due to blocking that would occur otherwise so we loop on
           this condition */
        if( rc == LIBSSH2_ERROR_EAGAIN )
        {
            WaitSocket(m_sock, m_pSession);
        }
        else
            break;
    }

    if (m_pChannel) {
        libssh2_channel_free(m_pChannel);
        m_pChannel = NULL;
    }
    
    return bRet;
}

bool CSshConnect::SetHostAddr( string strHostAddr )
{
    bool bRet = true;

    m_strHostAddr = strHostAddr;

    return bRet;
}
bool CSshConnect::SetUserPass( string strUserName, string strPassword )
{
    bool bRet = true;

    m_strUserName = strUserName;
    m_strPassword = strPassword;

    return bRet;
}

bool CSshConnect::SetConnectTimeout( unsigned int uiTimeoutMs )
{
    m_uiTimeoutUs = uiTimeoutMs * 1000;
    return true;
}

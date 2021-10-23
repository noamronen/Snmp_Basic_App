//
// Created by noam on 22/10/2021.
#pragma once
#include "Server.h"
Server::Server()
{
    //Initialize the SNMP library
    init_snmp("snmpdemoapp");

    //Initialize a "session" that defines who we're going to talk to
    snmp_sess_init( &session );                   /* set up defaults */
    session.peername = strdup("test.net-snmp.org");

    //set up the authentication parameters for talking to the server (SNMPv3)
    session.version=SNMP_VERSION_3; // sets the version of SNMP
    session.securityName = strdup("Simple_App_User");
    session.securityNameLen = strlen(session.securityName);

    session.securityLevel = SNMP_SEC_LEVEL_AUTHNOPRIV;//sets the security level to authenticated

    //set the authentication method to MD5 which is a safer way to send a password between devices
    session.securityAuthProto = usmHMACMD5AuthProtocol;
    session.securityAuthProtoLen = sizeof(usmHMACMD5AuthProtocol)/sizeof(oid);
    session.securityAuthKeyLen = USM_AUTH_KU_LEN;

    /* set the authentication key to a MD5 hashed version of our
       passphrase "The Net-SNMP Demo Password" (which must be at least 8
       characters long) */
    if (generate_Ku(session.securityAuthProto,
                    session.securityAuthProtoLen,
                    (u_char *) password, strlen(password),
                    session.securityAuthKey,
                    &session.securityAuthKeyLen) != SNMPERR_SUCCESS) {
        cout<<"Error generating Ku from authentication pass phrase."<<endl;
        snmp_log(LOG_ERR,
                 "Error generating Ku from authentication pass phrase. \n");
        exit(1);
    }
}

void Server::open_session()
{
    //open session
    session_ptr = snmp_open(&session);
    if (!session_ptr)
    {
        snmp_sess_perror("ack", &session);
        SOCK_CLEANUP;
        exit(1);
    }
}

void Server::SNMP_GET()
{
    //ceate the PDU for the data for our request.
    //1) We're going to GET the system.sysDescr.0 node.
    send_pdu = snmp_pdu_create(SNMP_MSG_GET);
    anOID_len = MAX_OID_LEN;
    if (!snmp_parse_oid(".1.3.6.1.2.1.1.1.0", anOID, &anOID_len)) {
        snmp_perror(".1.3.6.1.2.1.1.1.0");
        SOCK_CLEANUP;
        exit(1);
    }

    snmp_add_null_var(send_pdu, anOID, anOID_len); //making space for the response
    status = snmp_synch_response(session_ptr, send_pdu, &recv_pdu); //sending out the request
}

void Server::SNMP_RESPONSE()
{
    int count = 1;
    //process response
    if (status == STAT_SUCCESS && recv_pdu->errstat == SNMP_ERR_NOERROR)
    {
        //SUCCESS: Print the result variables
        for(vars = recv_pdu->variables; vars; vars = vars->next_variable)
            print_variable(vars->name, vars->name_length, vars);

        // manipulate the information ourselves
        for(vars = recv_pdu->variables; vars; vars = vars->next_variable)
        {
            if (vars->type == ASN_OCTET_STR)
            {
                char *sp = new char[1 + vars->val_len];
                memcpy(sp, vars->val.string, vars->val_len);
                sp[vars->val_len] = '\0';
                cout<<"value"<<count++<<"is a string: "<<sp<<endl;
                free(sp);
            }
            else
                cout<<"value"<<count++<<"is a not string: "<<endl;
        }
    } else
    {
        /*
         * FAILURE: print what went wrong!
         */

        if (status == STAT_SUCCESS)
            fprintf(stderr, "Error in packet\nReason: %s\n",
                    snmp_errstring(recv_pdu->errstat));
        else if (status == STAT_TIMEOUT)
            fprintf(stderr, "Timeout: No response from %s.\n",
                    session.peername);
        else
            snmp_sess_perror("snmpdemoapp", session_ptr);

    }

}

void Server::SNMP_CLEANUP()
{
    if (recv_pdu)
        snmp_free_pdu(recv_pdu);
    snmp_close(session_ptr);

}
//


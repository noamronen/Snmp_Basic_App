//
// Created by noam on 22/10/2021.
//
#include <net-snmp/net-snmp-config.h>
#include <net-snmp/net-snmp-includes.h>
#include <string.h>
#include <string>
#include<iostream>
#include <net-snmp/session_api.h>
#ifndef SNMP_SIMPLEAPPLICATION_SERVER_H
#pragma once
#define SNMP_SIMPLEAPPLICATION_SERVER_H
using namespace std;
class Server
{
private:
    struct snmp_session session,*session_ptr; //session struct holds information about who we are trying to talk to
    struct snmp_pdu *send_pdu,*recv_pdu; //pdu struct holds the information we want to send / recieve
    oid anOID[MAX_OID_LEN]; // holds the location of the data we need
    struct variable_list *vars; //holds the data we want to use via snmp
    int status;
    const char *password="1896E2F456J8";
    size_t anOID_len;

public:
    Server();
    void open_session();
    void SNMP_GET();
    void SNMP_RESPONSE();
    void SNMP_CLEANUP();


};

#endif //SNMP_SIMPLEAPPLICATION_SERVER_H

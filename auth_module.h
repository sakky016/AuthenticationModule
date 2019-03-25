#ifndef _AUTH_MODULE_H_
#define _AUTH_MODULE_H_
#include <fstream>
#include<iostream>
#include<list>
#include<unordered_map>
#include<stdio.h>
#include<string>
#include<time.h>
#include<vector>

using namespace std;

//-------------------------------------------------------------------------------------------------------------
// Globals
//-------------------------------------------------------------------------------------------------------------
const string USERS_DATA_FILENAME = "users.db";
const int PASSWORD_HISTORY_MAX = 3;

//-------------------------------------------------------------------------------------------------------------
// Structs
//-------------------------------------------------------------------------------------------------------------
typedef struct userData_tag
{
    string name;
    string password;
    unsigned passwordHash;
    long long lastPasswordChangeTimestamp;
    list<string> prevPasswords;
}userData_t;


//-------------------------------------------------------------------------------------------------------------
// Auth Module class
//-------------------------------------------------------------------------------------------------------------
class AuthModule
{
private:
    string                                  m_usersDataFile;
    bool                                    m_isUsersDataLoaded;
    fstream                                 m_fileStream;
    unordered_map<string, userData_t>       m_usersDataMap;              // Map of name and user data
    int                                     m_numPrevPasswordRecord;

public:
    AuthModule();
    ~AuthModule();
    bool UpdateUsersDataFile();
    bool LoadUsersDataFile();
    bool GetUserData(const string & userName, userData_t & userData);
    bool AddNewUser(const string & userName, const string & password);
    bool UpdateUserPassword(const string & userName, const string & password);
    bool Login(const string & userName, const string & password);
    bool Register(const string & userName, const string & password);
    void ShowUsersDetails();
};

#endif

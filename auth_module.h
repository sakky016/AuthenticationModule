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
const string NO_PASSWORD_IDENTIFIER = "~^~";
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

typedef struct authPolicy_tag
{
    bool useStrongPasswords;                  // If true, password will be checked for length and special character requirements
    unsigned passwordHistoryMax;              // Maximum number of passwords which needs to be validated as per history requirement
    unsigned passwordLenMin;                  // Minimum password length
    unsigned passwordLenMax;                  // Maximum length of password
    int passwordExpiryDays;                   // Days after which the current password will expire. 
}authPolicy_t;

//-------------------------------------------------------------------------------------------------------------
// Auth Module class
//-------------------------------------------------------------------------------------------------------------
class AuthModule
{
private:
    string                                  m_usersDataFile;
    authPolicy_t                            m_authPolicy;
    bool                                    m_isUsersDataLoaded;
    fstream                                 m_fileStream;
    unordered_map<string, userData_t*>      m_usersDataMap;              // Map of name and user data

public:
    AuthModule(authPolicy_t authPolicy);
    ~AuthModule();
    void Initialize();
    bool UpdateUsersDataFile();
    bool LoadUsersDataFile();
    userData_t* GetUserData(const string & userName);
    bool AddNewUser(const string & userName, const string & password);
    bool UpdateUserPassword(const string & userName, const string & password);
    bool Login(const string & userName, const string & password);
    bool Register(const string & userName, const string & password);
    void ShowUsersDetails();
    bool ValidatePassword(const string & userName, const string & password);
    bool IsPasswordValidAsPerHistory(const string & userName, const string & password);
    size_t GetRegisteredUsers() { return m_usersDataMap.size(); }
    double DaysFromTimestamp(long long ts);
    bool HandlePasswordExpiry(userData_t *userData);
};

#endif

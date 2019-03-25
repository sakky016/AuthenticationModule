#include "auth_module.h"

//-------------------------------------------------------------------------------------------------------------
// @name                : AuthModule
//
// @description         : Constructor
//-------------------------------------------------------------------------------------------------------------
AuthModule::AuthModule()
{
    m_usersDataFile = USERS_DATA_FILENAME;
    m_isUsersDataLoaded = false;
    m_numPrevPasswordRecord = PASSWORD_HISTORY_MAX;
}

//-------------------------------------------------------------------------------------------------------------
// @name                : AuthModule
//
// @description         : Destructor
//-------------------------------------------------------------------------------------------------------------
AuthModule::~AuthModule()
{

}

//-------------------------------------------------------------------------------------------------------------
// @name                : UpdateUsersDataFile
//
// @description         : 
//
// @returns             :
//-------------------------------------------------------------------------------------------------------------
bool AuthModule::UpdateUsersDataFile()
{
    m_fileStream.open(m_usersDataFile, ios::out | ios::binary);
    if (!m_fileStream)
    {
        printf("File [ %s ] NOT found!\n", m_usersDataFile.c_str());
        return false;
    }

    for (auto it = m_usersDataMap.begin(); it != m_usersDataMap.end(); it++)
    {
        userData_t userData = it->second;
        //m_fileStream.write((char*)&userData, sizeof(userData));
    }

    m_fileStream.close();
    return true;
}

//-------------------------------------------------------------------------------------------------------------
// @name                : LoadUsersDataFile
//
// @description         : 
//
// @returns             :
//-------------------------------------------------------------------------------------------------------------
bool AuthModule::LoadUsersDataFile()
{
    m_fileStream.open(m_usersDataFile, ios::in | ios::binary);
    if (!m_fileStream)
    {
        printf("File [ %s ] NOT found!\n", m_usersDataFile.c_str());
        return false;
    }



    m_isUsersDataLoaded = true;
    m_fileStream.close();
    return true;
}

//-------------------------------------------------------------------------------------------------------------
// @name                : GetUserData
//
// @description         : 
//
// @returns             : true if userName was found, false otherwise
//-------------------------------------------------------------------------------------------------------------
bool AuthModule::GetUserData(const string & userName, userData_t & userData)
{
    auto it = m_usersDataMap.find(userName);
    if (it != m_usersDataMap.end())
    {
        userData = it->second;
        return true;
    }

    return false;
}

//-------------------------------------------------------------------------------------------------------------
// @name                : AddNewUser
//
// @description         : 
//
// @returns             :
//-------------------------------------------------------------------------------------------------------------
bool AuthModule::AddNewUser(const string & userName, const string & password)
{
    userData_t userData;
    bool retval = false;
    if (!GetUserData(userName, userData))
    {
        // User not already present, add entry.
        userData.lastPasswordChangeTimestamp = time(&userData.lastPasswordChangeTimestamp);
        userData.name = userName;
        userData.password = password;

        m_usersDataMap[userName] = userData;
        printf("User [%s] added\n", userData.name.c_str());
        retval = true;
    }
    else 
    {
        printf("User [%s] already exists\n", userName.c_str());
    }

    return retval;
}

//-------------------------------------------------------------------------------------------------------------
// @name                : UpdateUserPassword
//
// @description         : 
//
// @returns             :
//-------------------------------------------------------------------------------------------------------------
bool AuthModule::UpdateUserPassword(const string & userName, const string & password)
{
    userData_t userData;
    auto it = m_usersDataMap.find(userName);
    if (!GetUserData(userName, userData))
    {
        return false;
    }

    // Store in previous passwords history
    if (userData.prevPasswords.size() == PASSWORD_HISTORY_MAX)
    {
        userData.prevPasswords.pop_front();
    }

    userData.prevPasswords.push_back(userData.password);

    // Update password
    userData.password = password;
    userData.lastPasswordChangeTimestamp = time(&userData.lastPasswordChangeTimestamp);
    m_usersDataMap[userName] = userData;
    printf("Password updated for [%s]\n", userData.name.c_str());

    return true;
}

//-------------------------------------------------------------------------------------------------------------
// @name                : Login
//
// @description         : 
//
// @returns             :
//-------------------------------------------------------------------------------------------------------------
bool AuthModule::Login(const string & userName, const string & password)
{
    userData_t userData;
    if (GetUserData(userName, userData))
    {
        if (userData.password == password)
        {
            printf("User [%s] logged in\n", userName.c_str());
            return true;
        }
    }

    printf("Invalid Username/Password\n");
    return false;
}

//-------------------------------------------------------------------------------------------------------------
// @name                : Register
//
// @description         : 
//
// @returns             :
//-------------------------------------------------------------------------------------------------------------
bool AuthModule::Register(const string & userName, const string & password)
{
    return AddNewUser(userName, password);
}

//-------------------------------------------------------------------------------------------------------------
// @name                : ShowUsersDetails
//
// @description         : 
//
// @returns             :
//-------------------------------------------------------------------------------------------------------------
void AuthModule::ShowUsersDetails()
{
    printf("+-------------------------------------------------------------------------+\n");
    printf("|                     Registered Users' Details                           |\n");
    printf("+-------------------------------------------------------------------------+\n");
    if (1)
    {
        int index = 1;
        printf("** Users registered: %u\n", m_usersDataMap.size());
        for (auto it = m_usersDataMap.begin(); it != m_usersDataMap.end(); it++)
        {
            userData_t userData = it->second;
            printf("User #%3d\n", index);
            printf("Username                     : %s\n", userData.name.c_str());
            printf("Password                     : %s\n", userData.password.c_str());
            printf("Previous passwords           : ");
            for (auto it2 = userData.prevPasswords.begin(); it2 != userData.prevPasswords.end(); it2++)
            {
                printf("%s ", (*it2).c_str());
            }
            printf("\n");

            printf("\n");

            index++;
        }
    }
}
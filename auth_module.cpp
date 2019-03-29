#include "auth_module.h"

//-------------------------------------------------------------------------------------------------------------
// @name                : AuthModule
//
// @description         : Constructor
//-------------------------------------------------------------------------------------------------------------
AuthModule::AuthModule(authPolicy_t authPolicy)
{
    m_authPolicy = authPolicy;
    m_usersDataFile = USERS_DATA_FILENAME;
    m_isUsersDataLoaded = false;
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
    m_fileStream.open(m_usersDataFile, ios::out);
    if (!m_fileStream)
    {
        printf("File [ %s ] NOT found!\n", m_usersDataFile.c_str());
        return false;
    }

    // Write auth policy to file. This is required to make sure
    // that the policy change does not cause inconsistency in the 
    // users DB file.
    m_fileStream << m_authPolicy.passwordHistoryMax << endl;
    m_fileStream << m_authPolicy.passwordLenMax << endl;
    m_fileStream << m_authPolicy.passwordLenMin << endl;
    m_fileStream << m_authPolicy.useStrongPasswords << endl;

    // Write down the number of users
    m_fileStream << m_usersDataMap.size() << endl;

    // Write the actual user details
    for (auto it = m_usersDataMap.begin(); it != m_usersDataMap.end(); it++)
    {
        userData_t *userData = it->second;
        m_fileStream << userData->lastPasswordChangeTimestamp << endl;
        m_fileStream << userData->name << endl;
        m_fileStream << userData->password << endl;
        m_fileStream << userData->passwordHash << endl;

        // Previous passwords record
        auto pwdIt = userData->prevPasswords.begin();
        for (unsigned i = 0; i < m_authPolicy.passwordHistoryMax - 1; i++)
        {
            if (pwdIt != userData->prevPasswords.end())
            {
                m_fileStream << *pwdIt << " ";
                pwdIt++;
            }
            else
            {
                m_fileStream << NO_PASSWORD_IDENTIFIER <<" ";
            }
            
        }
        m_fileStream << endl;

    }

    // Close the file
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

    authPolicy_t fileAuthPolicy;
    m_fileStream >> fileAuthPolicy.passwordHistoryMax;
    m_fileStream >> fileAuthPolicy.passwordLenMax;
    m_fileStream >> fileAuthPolicy.passwordLenMin;
    m_fileStream >> fileAuthPolicy.useStrongPasswords;

    bool isAuthPolicyConsistent = (m_authPolicy.passwordHistoryMax == fileAuthPolicy.passwordHistoryMax &&
                                   m_authPolicy.passwordLenMax == fileAuthPolicy.passwordLenMax &&
                                   m_authPolicy.passwordLenMin == fileAuthPolicy.passwordLenMin &&
                                   m_authPolicy.useStrongPasswords == fileAuthPolicy.useStrongPasswords);

    if (isAuthPolicyConsistent)
    {
        size_t totalRegisteredUsers = 0;
        m_fileStream >> totalRegisteredUsers;

        for (size_t i = 0; i < totalRegisteredUsers; i++)
        {
            userData_t *userData = new userData_t;
            memset(userData, 0, sizeof(userData));

            m_fileStream >> userData->lastPasswordChangeTimestamp;
            m_fileStream >> userData->name;
            m_fileStream >> userData->password;
            m_fileStream >> userData->passwordHash;

            for (unsigned i = 0; i < m_authPolicy.passwordHistoryMax - 1; i++)
            {
                string pwd;
                m_fileStream >> pwd;
                userData->prevPasswords.push_back(pwd);
            }

            m_usersDataMap[userData->name] = userData;
            printf("User [%s] read from file\n", userData->name.c_str());
        }
    }
    else
    {
        printf("ERROR: Inconsistency in auth policy\n");
    }

    m_isUsersDataLoaded = true;
    
    // Close the file
    m_fileStream.close();
    return true;
}

//-------------------------------------------------------------------------------------------------------------
// @name                : GetUserData
//
// @description         : 
//
// @returns             : user's data
//-------------------------------------------------------------------------------------------------------------
userData_t* AuthModule::GetUserData(const string & userName)
{
    userData_t *userData = nullptr;
    auto it = m_usersDataMap.find(userName);
    if (it != m_usersDataMap.end())
    {
        userData = it->second;
    }

    return userData;
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
    userData_t *userData = nullptr;
    bool retval = false;
    hash<string> str_hash;

    userData = GetUserData(userName);
    if (userData == nullptr)
    {
        // User not already present, add entry.
        userData = new userData_t;
        memset(userData, 0, sizeof(userData));

        userData->lastPasswordChangeTimestamp = time(&userData->lastPasswordChangeTimestamp);
        userData->name = userName;
        userData->password = password;
        userData->passwordHash = str_hash(password);

        m_usersDataMap[userName] = userData;
        printf("User [%s] registered\n", userData->name.c_str());
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
    userData_t *userData = GetUserData(userName);
    if (userData == nullptr)
    {
        return false;
    }

    if (ValidatePassword(userName, password) && IsPasswordValidAsPerHistory(userName, password))
    {
        // Store in previous passwords history
        if (userData->prevPasswords.size() == m_authPolicy.passwordHistoryMax - 1 /* -1 because current password is already included*/)
        {
            userData->prevPasswords.pop_front();
        }

        userData->prevPasswords.push_back(userData->password);

        // Update password
        userData->password = password;
        userData->lastPasswordChangeTimestamp = time(&userData->lastPasswordChangeTimestamp);
        m_usersDataMap[userName] = userData;
        printf("Password updated for [%s]\n", userData->name.c_str());
        return true;
    }

    return false;
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
    userData_t *userData = GetUserData(userName);
    if (userData)
    {
        if (userData->password == password)
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
    bool userRegistered = false;
    if (ValidatePassword(userName, password))
    {
        userRegistered = AddNewUser(userName, password);
    }
    
    return userRegistered;
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
        printf("** Users registered: %u\n\n", m_usersDataMap.size());
        for (auto it = m_usersDataMap.begin(); it != m_usersDataMap.end(); it++)
        {
            userData_t *userData = it->second;
            printf("User #%3d\n", index);
            printf("Username                     : %s\n", userData->name.c_str());
            printf("Password                     : %s\n", userData->password.c_str());
            printf("Previous passwords           : ");
            if (userData->prevPasswords.size())
            {
                for (auto it2 = userData->prevPasswords.begin(); it2 != userData->prevPasswords.end(); it2++)
                {
                    if ((*it2) != NO_PASSWORD_IDENTIFIER)
                    {
                        printf("%s ", (*it2).c_str());
                    }
                }
                printf("\n");
            }
            else
            {
                printf("<None>");
            }

            printf("\n");

            index++;
        }
    }
}

//-------------------------------------------------------------------------------------------------------------
// @name                : ValidatePassword
//
// @description         : 
//
// @returns             :
//-------------------------------------------------------------------------------------------------------------
bool AuthModule::ValidatePassword(const string & userName, const string & password)
{
    if (m_authPolicy.useStrongPasswords)
    {
        if (password.length() > m_authPolicy.passwordLenMax ||
            password.length() < m_authPolicy.passwordLenMin)
        {
            printf("Password for [%s] does not meet length criteria\n", userName.c_str());
            return false;
        }

        // TODO: special chars, numerics etc. requirement
    }

    return true;
}

//-------------------------------------------------------------------------------------------------------------
// @name                : IsPasswordValidAsPerHistory
//
// @description         : 
//
// @returns             :
//-------------------------------------------------------------------------------------------------------------
bool AuthModule::IsPasswordValidAsPerHistory(const string & userName, const string & password)
{
    if (m_authPolicy.passwordHistoryMax > 0)
    {
        userData_t *userData = GetUserData(userName);
        if (userData)
        {
            // If current password is same as password being set, don't allow it
            if (userData->password == password)
            {
                printf("Current and new password cannot be the same\n");
                return false;
            }

            for (auto it = userData->prevPasswords.begin(); it != userData->prevPasswords.end(); it++)
            {
                if (*it == password)
                {
                    printf("Password for [%s] does not meet history requirement\n", userName.c_str());
                    return false;
                }
            }
        }
        else
        {
            // Not a valid user/password
            return false;
        }
    }

    return true;
}
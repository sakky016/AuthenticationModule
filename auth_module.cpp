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
    // Free memory of users' data map
    for (auto it = m_usersDataMap.begin(); it != m_usersDataMap.end(); it++)
    {
        printf("Freeing data for [%s]\n", it->first.c_str());
        delete it->second;
    }
}

//-------------------------------------------------------------------------------------------------------------
// @name                : Initialize
//
// @description         : Load the database with existing records.
//
// @returns             : Nothing
//-------------------------------------------------------------------------------------------------------------
void AuthModule::Initialize()
{
    bool retval = LoadUsersDataFile();
    if (retval)
    {
        printf("** Found %ld registered users\n", GetRegisteredUsers());
    }
    else
    {
        printf("** No records found in %s!\n", m_usersDataFile.c_str());
    }
}

//-------------------------------------------------------------------------------------------------------------
// @name                : UpdateUsersDataFile
//
// @description         : This function writes the updated user records in the users database file. Besides
//                        users' informaiton it also writes down the details of Authentication Policy.
//                        This is required to make sure that the policy change does not cause inconsistency in the 
//                        users DB file. This function is called at the end by AddNewUser() and 
//                        UpdateUserPassword() functions to reflect the changes in the file.
//                         
//
// @returns             : True if users database file was updated successfully.
//                        False otherwise.
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
    m_fileStream << m_authPolicy.passwordExpiryDays << endl;

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
// @description         : This function is called by the Initialize() function. It must be called after the
//                        construction of AuthModule. This is responsible for fetching records already registered
//                        in the users database file. If this is not called, existing users' record will be
//                        discarded.
//
// @returns             : True if data from users database file were read successfully and no
//                        ambiguity was found. 
//                        False otherwise.
//-------------------------------------------------------------------------------------------------------------
bool AuthModule::LoadUsersDataFile()
{
    m_fileStream.open(m_usersDataFile, ios::in | ios::binary);
    if (!m_fileStream)
    {
        printf("File [ %s ] NOT found!\n", m_usersDataFile.c_str());
        return false;
    }

    // Read authentication policy details
    authPolicy_t fileAuthPolicy;
    m_fileStream >> fileAuthPolicy.passwordHistoryMax;
    m_fileStream >> fileAuthPolicy.passwordLenMax;
    m_fileStream >> fileAuthPolicy.passwordLenMin;
    m_fileStream >> fileAuthPolicy.useStrongPasswords;
    m_fileStream >> fileAuthPolicy.passwordExpiryDays;

    // Validate it against the policy being used by this module.
    bool isAuthPolicyConsistent = (m_authPolicy.passwordHistoryMax == fileAuthPolicy.passwordHistoryMax &&
                                   m_authPolicy.passwordLenMax == fileAuthPolicy.passwordLenMax &&
                                   m_authPolicy.passwordLenMin == fileAuthPolicy.passwordLenMin &&
                                   m_authPolicy.useStrongPasswords == fileAuthPolicy.useStrongPasswords &&
                                   m_authPolicy.passwordExpiryDays == fileAuthPolicy.passwordExpiryDays);

    // Proceed only if both are same.
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
// @description         : Checks in the map for a given username. 
//
// @param userName      : Username that needs to be checked.
//
// @returns             : user's data for the provided userName.
//                        NULL if userName is not present in records.
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
// @description         : Add new user details to record. If user is registered, this
//                        information is updated in the users database as well.
//
// @param userName      : Username to add
// @param password      : Password that is to be used
//
// @returns             : true if user was added successfully.
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

    // Update the file only if the user was registered successfully.
    if (retval == true)
    {
        bool fileUpdated = UpdateUsersDataFile();
        if (!fileUpdated)
            printf("Failed to update Users database!\n");
    }

    return retval;
}

//-------------------------------------------------------------------------------------------------------------
// @name                : UpdateUserPassword
//
// @description         : This is used to update password for an already existing user. Validations are done
//                        for existence of the user, validity of password as per auth policy.
//
// @returns             :
//-------------------------------------------------------------------------------------------------------------
bool AuthModule::UpdateUserPassword(const string & userName, const string & password)
{
    userData_t *userData = GetUserData(userName);
    bool retval = false;

    if (userData == nullptr)
    {
        printf("User [%s] not found!\n", userName.c_str());
        return retval;
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
        retval = true;
    }

    // Update the file only if the user was registered successfully.
    if (retval == true)
    {
        bool fileUpdated = UpdateUsersDataFile();
        if (!fileUpdated)
            printf("Failed to update Users database!\n");
    }

    return retval;
}

//-------------------------------------------------------------------------------------------------------------
// @name                : Login
//
// @description         : This function helps to check if provided userName and password match as per records.
//                        On successfull login, if auth policy requires password expiry validation it will also
//                        enforce updation of password if current password has expired.
// 
// @param userName      : Username
// @param password      : password
//
// @returns             : True if Username and password matches
//                        False otherwise.
//-------------------------------------------------------------------------------------------------------------
bool AuthModule::Login(const string & userName, const string & password)
{
    userData_t *userData = GetUserData(userName);
    if (userData)
    {
        if (userData->password == password)
        {
            printf("User [%s] logged in\n", userName.c_str());
            return HandlePasswordExpiry(userData);
        }
    }

    printf("Invalid Username/Password\n");
    return false;
}

//-------------------------------------------------------------------------------------------------------------
// @name                : Register
//
// @description         : Lets add new user to database subject to validity of username and password.
//
// @param userName      : Username
// @param password      : password
//
// @returns             : True if user is registered successfully,
//                        False otherwise.
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
// @description         : Display details of registered users. This is only for debug purpose.
//
// @returns             : Nothing
//-------------------------------------------------------------------------------------------------------------
void AuthModule::ShowUsersDetails()
{
    printf("+-------------------------------------------------------------------------+\n");
    printf("|                     Registered Users' Details                           |\n");
    printf("+-------------------------------------------------------------------------+\n");
    if (1)
    {
        int index = 1;
        for (auto it = m_usersDataMap.begin(); it != m_usersDataMap.end(); it++)
        {
            userData_t *userData = it->second;
            printf("User #%3d\n", index);
            printf("Username                     : %s\n", userData->name.c_str());
            printf("Password                     : %s\n", userData->password.c_str());
            printf("Password last updated        : %.2lf day(s) ago\n", DaysFromTimestamp(time(0) - userData->lastPasswordChangeTimestamp));
            printf("Previous passwords           : ");
            if (userData->prevPasswords.size())
            {
                for (auto it2 = userData->prevPasswords.begin(); it2 != userData->prevPasswords.end(); it2++)
                {
                    if ((*it2) != NO_PASSWORD_IDENTIFIER)
                    {
                        printf("%s ", (*it2).c_str());
                    }
                    else
                    {
                        printf("- ");
                    }
                }
                printf("\n");
            }
            else
            {
                printf("- ");
            }

            printf("\n");

            index++;
        }
        printf("\n** Users registered: %u\n", m_usersDataMap.size());
    }
}

//-------------------------------------------------------------------------------------------------------------
// @name                : ValidatePassword
//
// @description         : Do validation of password as per the specified Authentication Policy
//
// @returns             : True if password meets the criteria.
//                        False otherwise.
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
// @description         : If a non-zero value is specified for passwordHistoryMax of Auth Policy, then
//                        this function checks if user's password is valid as per history of previous
//                        passwords.
//
// @returns             : True if valid. False otherwise.
//-------------------------------------------------------------------------------------------------------------
bool AuthModule::IsPasswordValidAsPerHistory(const string & userName, const string & password)
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

        // Check previous passwords history
        if (m_authPolicy.passwordHistoryMax > 0)
        {
            for (auto it = userData->prevPasswords.begin(); it != userData->prevPasswords.end(); it++)
            {
                if (*it == password)
                {
                    printf("Password for [%s] does not meet history requirement\n", userName.c_str());
                    return false;
                }
            }
        }
    }
    else
    {
        // Not a valid user/password
        printf("Invalid username provided for password history check!\n");
        return false;
    }

    // All validations passed, this password is valis as per history requirement
    return true;
}

//-------------------------------------------------------------------------------------------------------------
// @name                : HandlePasswordExpiry
//
// @description         : It checks if the given user's password has expired. If yes, then he is prompted
//                        to update the password.
//
// @returns             : True if password updated.
//-------------------------------------------------------------------------------------------------------------
bool AuthModule::HandlePasswordExpiry(userData_t *userData)
{
    if (m_authPolicy.passwordExpiryDays > 0)
    {
        time_t currentTs = time(&currentTs);
        double days = DaysFromTimestamp(currentTs - userData->lastPasswordChangeTimestamp);
        if (days >= m_authPolicy.passwordExpiryDays)
        {
            printf("Password has expired. Please update!\n");
            bool passwordUpdated = false;
            string newPassword;
            string pwd1;
            string pwd2;

            do
            {
                printf("\n** Password Update\n");
                printf("New password     : ");
                cin >> pwd1;
                printf("Confirm password : ");
                cin >> pwd2;
                if (pwd1 == pwd2)
                {
                    if (UpdateUserPassword(userData->name, pwd2))
                    {
                        newPassword = pwd2;
                        passwordUpdated = true;
                    }
                }
            } while (!passwordUpdated);
        }
    }

    return true;
}

//-------------------------------------------------------------------------------------------------------------
// @name                : DaysFromTimestamp
//
// @description         : Get no. of days as per provided timestamp value (seconds)
//
// @returns             : No. of days
//-------------------------------------------------------------------------------------------------------------
double AuthModule::DaysFromTimestamp(long long ts)
{
    double days = (double)ts / (60 * 60 * 24);
    return days;
}
#include "auth_module.h"

//-------------------------------------------------------------------------------------------------------------
// Globals
//-------------------------------------------------------------------------------------------------------------
const int MAX_ATTEMPTS = 3;

//-------------------------------------------------------------------------------------------------------------
// @name                : DoLogin
//
// @description         : Login prompt.
//
// @returns             : true on success
//-------------------------------------------------------------------------------------------------------------
bool DoLogin(AuthModule & auth)
{
    string user;
    string pwd;
    printf("\n** Login existing user\n");
    printf("Username: ");
    cin >> user;
    printf("Password: ");
    cin >> pwd;
    bool retval = auth.Login(user, pwd);

    return retval;
}

//-------------------------------------------------------------------------------------------------------------
// @name                : DoRegistration
//
// @description         : Registration prompt
//
// @returns             : true on success
//-------------------------------------------------------------------------------------------------------------
bool DoRegistration(AuthModule & auth)
{
    string user;
    string pwd1;
    string pwd2;
    printf("\n** New user registration\n");
    printf("Select a username: ");
    cin >> user;
    userData_t *userData = auth.GetUserData(user);
    if (userData != nullptr)
    {
        printf("User already exists!\n");
        return false;
    }

    printf("Choose password  : ");
    cin >> pwd1;
    printf("Confirm password : ");
    cin >> pwd2;
    if (pwd1 == pwd2)
    {
        bool retval = auth.Register(user, pwd2);
        if (retval)
        {
            printf("Registered successfully\n");
            return true;
        }
    }
    else
    {
        printf("Passwords do not match\n");
    }

    return false;
}


bool UpdatePassword(AuthModule & auth)
{
    bool passwordUpdated = false;
    string userName;
    string currentPwd;
    string pwd1;
    string pwd2;


    printf("\n** Password Update\n");
    printf("Username         : ");
    cin >> userName;
    printf("Current password : ");
    cin >> currentPwd;
    if (auth.Login(userName, currentPwd))
    {
        printf("New password     : ");
        cin >> pwd1;
        printf("Confirm password : ");
        cin >> pwd2;
        return auth.UpdateUserPassword(userName, pwd2);
    }

    return false;
}

//-------------------------------------------------------------------------------------------------------------
// M A I N 
//-------------------------------------------------------------------------------------------------------------
int main()
{
#if 0
    string s1("");
    string s2(" ");
    hash<string> str_hash;
    printf("Hash of [%20s]: %u\n", s1.c_str(), str_hash(s1));
    printf("Hash of [%20s]: %u\n", s2.c_str(), str_hash(s2));
#endif
{

    // Creating an Authentication policy
    authPolicy_t authPolicy;
    authPolicy.passwordHistoryMax = 3;
    authPolicy.useStrongPasswords = true;
    authPolicy.passwordLenMax = 255;
    authPolicy.passwordLenMin = 6;
    authPolicy.passwordExpiryDays = 30;

    // Creating Authentication Module
    AuthModule auth(authPolicy);
    auth.Initialize();

    // Main menu
    bool done = false;
    string choice;
    do
    {
        printf("\n");
        printf("+--------------------------------------+\n");
        printf("|              M E N U                 |\n");
        printf("+--------------------------------------+\n");
        printf("1> Login\n");
        printf("2> Register\n");
        printf("3> Password Update\n");
        printf("4> Show registered users\n");
        printf("0> Quit\n");
        printf(">> Choice: ");
        cin >> choice;
        if (choice == "1")
        {
            // Login
            int attempts = 0;
            bool loginDone = false;
            do
            {
                loginDone = DoLogin(auth);
                attempts++;
                if (!loginDone && attempts == MAX_ATTEMPTS)
                {
                    printf("** Exceeded maximum attempts\n");
                    break;
                }
            } while (!loginDone);
        }
        else if (choice == "2")
        {
            // New user registration
            int attempts = 0;
            bool registrationDone = false;
            do
            {
                registrationDone = DoRegistration(auth);
                attempts++;
                if (!registrationDone && attempts == MAX_ATTEMPTS)
                {
                    printf("** Exceeded maximum attempts\n");
                    break;
                }
            } while (!registrationDone);
        }
        else if (choice == "3")
        {
            // Password update
            int attempts = 0;
            bool pwdUpdated = false;
            do
            {
                pwdUpdated = UpdatePassword(auth);
                attempts++;
                if (!pwdUpdated && attempts == MAX_ATTEMPTS)
                {
                    printf("** Exceeded maximum attempts\n");
                    break;
                }
            } while (!pwdUpdated);

        }
        else if (choice == "4")
        {
            // This is only for debug purpose
            auth.ShowUsersDetails();
        }
        else if (choice == "0")
        {
            printf("** Terminating...\n");
            break;
        }
        else
        {
            printf("** Invalid choice. Try again\n\n");
        }

    } while (!done);

}// End of scope for Auth Module

    getchar();
    getchar();
    return 0;
}
#include "auth_module.h"

int main()
{
#if 0
    string s1("");
    string s2(" ");
    hash<string> str_hash;
    printf("Hash of [%20s]: %u\n", s1.c_str(), str_hash(s1));
    printf("Hash of [%20s]: %u\n", s2.c_str(), str_hash(s2));
#endif

    // Auth Module policy
    authPolicy_t authPolicy;
    authPolicy.passwordHistoryMax = 3;
    authPolicy.useStrongPasswords = true;
    authPolicy.passwordLenMax = 255;
    authPolicy.passwordLenMin = 6;

    AuthModule auth(authPolicy);
    bool retval = false;

#if 0
    string user = "john";
    string pwd = "safePassword1";

    retval = auth.Login(user, pwd);
    retval = auth.Register(user, pwd);
    retval = auth.Login(user, pwd);

    retval = auth.UpdateUserPassword(user, "safePassword2");
    if (!retval)
        printf("Password update failed for %s\n", user.c_str());

    //retval = auth.UpdateUserPassword(user, "safePassword3");
    //if (!retval)
    //    printf("Password update failed for %s\n", user.c_str());

    //retval = auth.UpdateUserPassword(user, "safePassword3");
    //if (!retval)
    //    printf("Password update failed for %s\n", user.c_str());

    user = "rupert";
    pwd = "safePassword1";

    retval = auth.Login(user, pwd);
    retval = auth.Register(user, pwd);
    retval = auth.Login(user, pwd);

    retval = auth.UpdateUserPassword(user, "safePassword2");
    if (!retval)
        printf("Password update failed for %s\n", user.c_str());

    retval = auth.UpdateUserPassword(user, "safePassword3");
    if (!retval)
        printf("Password update failed for %s\n", user.c_str());

    retval = auth.UpdateUserPassword(user, "safePassword3");
    if (!retval)
        printf("Password update failed for %s\n", user.c_str());

    retval = auth.Login(user, pwd);
    retval = auth.Register(user, pwd);
    retval = auth.Login(user, pwd);

    retval = auth.UpdateUserPassword(user, "safePassword2");
    if (!retval)
        printf("Password update failed for %s\n", user.c_str());

    retval = auth.UpdateUserPassword(user, "safePassword3");
    if (!retval)
        printf("Password update failed for %s\n", user.c_str());

    retval = auth.UpdateUserPassword(user, "safePassword3");
    if (!retval)
        printf("Password update failed for %s\n", user.c_str());

    retval = auth.UpdateUserPassword(user, "safePassword4");
    if (!retval)
        printf("Password update failed for %s\n", user.c_str());



    auth.ShowUsersDetails();

    retval = auth.UpdateUsersDataFile();
    if (!retval)
        printf("Auth data update failed!\n");
    else
        printf("Auth data file updated\n");
#endif

    retval = auth.LoadUsersDataFile();
    auth.ShowUsersDetails();

    getchar();
    return 0;
}
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

    AuthModule auth;
    bool retval = false;
    string user = "john";
    string pwd = "pwd";

    auth.Register(user, pwd);

    pwd = "abcd";
    auth.Login(user, pwd);

    auth.Register("harry", "harry_pwd");
    auth.UpdateUserPassword("john", "abcd");
    auth.UpdateUserPassword("john", "abcde");
    auth.UpdateUserPassword("john", "abcdef");
    auth.UpdateUserPassword("john", "abcdefg");


    auth.ShowUsersDetails();
    getchar();
    return 0;
}
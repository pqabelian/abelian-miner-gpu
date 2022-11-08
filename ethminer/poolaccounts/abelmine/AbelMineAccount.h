
#ifndef ABELMINER_ABELMINEACCOUNT_H
#define ABELMINER_ABELMINEACCOUNT_H


#include <string>


namespace poolaccounts
{
namespace abelmine
{

/**
 * pool account mechanism: "abelmine".
 * Each time we could register one abelmine account for one address (in "abelmine.address") and the (user, password) is written to "abelmine.account".
 * In next start of abelminer, the command line should use the user (or (user, password) if necessary) in "abelmine.account".
 */

//  RegisteringAccountAbelMine is used in command line to trigger the poolAccounts module to register account fo "abelmine" mechanism.
//  The recommended name for (pool-account-mechanism XXYYZZ) "RegisteringAccountXXYYZZ", as "RegisteringAccount" is used to trigger the poolAccounts module.
const std::string registeringAccountAbelMine = "RegisteringAccountAbelMine";

//  abelMineAccountFile is the file to which the generated (user, password) for pool-account-mechanism abelmine will be writen.
const std::string abelMineAccountFileExtension = ".abelmine.account";
const std::string abelMineAccountFile = "abelmine.account";

//  abelMineAddressFile is the file from which an address to be registered for pool-account-mechanism abelmine can be loaded.
const std::string abelMineAddressFile = "abelmine.address";


class AbelMineAccount
{
public:
    std::string m_user;
    std::string m_password;
    std::string m_address;

    AbelMineAccount();
    bool prepareRegisterAddress(std::string poolHost="", std::string workingDir = "");
    bool registerAccount(std::string workingDir = "");
    bool isValidAddress(std::string address);
};

}   // namesapce abelmine
}   // namespace poolaccounts

#endif  // ABELMINER_ABELMINEACCOUNT_H

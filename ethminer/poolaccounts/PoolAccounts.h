//
// Created by liu on 22-11-2.
//

/**
 * The wallet address in Abelian is too long to be contained in command line.
 * PoolAccounts module enables a user to register his wallet address to a pool
 * and then later could use a shorter account in command line to login the pool.
 * As different pools may use different register mechanism, abelminer deploys an adapter for each mechanism.
 * For example,
 * abelmine is added on 2022.11.
 */

#ifndef ETHMINER_POOLACCOUNTS_H
#define ETHMINER_POOLACCOUNTS_H

#include <string>
namespace poolaccounts
{
//  registeringAccount is used in command line to trigger the poolAccounts module to register account.
const std::string registeringAccount = "RegisteringAccount";
} // namespace poolaccounts


#endif  // ETHMINER_POOLACCOUNTS_H

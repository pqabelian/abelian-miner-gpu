# AbelMine Pool-Account-Mechanism


## Register
To register an account for an address on a pool which adapts ``abelmine`` pool-account-mechanism, the user needs to:
1. store the address in ``abelmine.address``
2. use the following command
``` shell
./abelminer -U -P stratums://RegisteringAccountAbelMine:password@poolhost:27778
```
where the user needs to specify the ``password`` for that account and specify the ``poolhost`` for the pool, for example the IP address.

**Note:** A cert with name ``poolhost.cert`` must exist in folder ``poolcerts``.


With such a command, abelminer will receive a username and directly begin mining with the pool.


**Note:** The address and username will be written in a file, say, ``poolhost.abelmine.account``. 
Each time this command can register only one abelmine address, 
and if a user wants to register multiple abelmine address, 
he has to run this command multiple times, 
and all the addresses and usernames are stored in account files for corresponding pool host.

## Mine
While the above **register** command registers and then mine, 
a user may stop **abelminer** and restart it later with a registered address for some reason. 
For such a case, the user needs to use the username that has been registered.
For example, 
``` shell
./abelminer -U -P stratums://username:password@poolhost:27778
```
**Note:** The registered username can be found in the account file for the pool, say, ``poolhost.abelmine.account``.

## Multiple Pools
**abelminer** allows a user to specify multiple pools so that once a connected pool disconnects, **abelminer** can switch to next one.
For this, the user could use the register command or mine command as below, where two pools are specified
``` shell
./abelminer -U -P stratums://RegisteringAccountAbelMine:password1@poolhost1:27778 -P stratums://RegisteringAccountAbelMine:password2@poolhost2:27778
```
``` shell
./abelminer -U -P stratums://username1:password1@poolhost1:27778 -P stratums://username2:password2@poolhost2:27778
```
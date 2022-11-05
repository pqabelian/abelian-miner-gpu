
#include "AbelMineAccount.h"

#include "utils/stringutils.h"
#include "utils/SHA256.h"

#include <unistd.h>
#include <fstream>
#include <iostream>

namespace poolaccounts
{
namespace abelmine
{

AbelMineAccount::AbelMineAccount()
{
    m_user = "";
    m_password = "";
    m_address = "";
}


bool AbelMineAccount::prepareRegisterAddress(std::string poolHost, std::string workingDir)
{
    if (!workingDir.empty())
    {
        int ret = chdir(workingDir.c_str());
        if (-1 == ret)
        {
            std::cerr << "unable to change to directory " + workingDir << std::endl;
            return false;
        }
    }

    //  read address
    std::ifstream inFileAddress;
    inFileAddress.open(abelMineAddressFile, std::ios::in);
    if (!inFileAddress.is_open())
    {
        std::cerr << "Unable to read file " + abelMineAddressFile << std::endl;
        return false;
    }
    getline(inFileAddress, m_address);
    inFileAddress.close();

    if (!isValidAddress(m_address))
    {
        std::cerr << "The address is invalid" << std::endl;
        return false;
    }


    // write address to account file
    std::string accountFile = poolHost + abelMineAccountFileExtension;
    std::ofstream ofs;
    ofs.open(accountFile,std::ios::app);
    if(!ofs.is_open()) {
        std::cerr << "Unable to open file " + accountFile << std::endl;
        return false;
    }
    ofs << "address=" << m_address << std::endl;
    ofs.close();

    std::cout << "Address has been written to account file " << accountFile << " successfully." << std::endl;


    // todo: At this moment, generating user at the client side. Later, it will be generated by pool side.    begin
    uint8_t* data = decodeHexString(m_address);
    if(data == nullptr)
    {
        std::cerr<<"Fail to decode address" << std::endl;
        return false;
    }

    SHA256 sha;
    uint8_t * doubleH = sha.doubleHash256(data, m_address.length()/2);
    m_user = SHA256::toString(doubleH);

    // write to file
    //std::ofstream ofs;
    ofs.open(accountFile,std::ios::app);
    if(!ofs.is_open()) {
        std::cerr << "Unable to open file " + accountFile << std::endl;
        return false;
    }
    ofs << "user=" << m_user << std::endl;
    ofs.close();

    std::cout << "User name has been written to account file " << accountFile << " successfully." << std::endl;

    // todo: At this moment, generating user at the client side. Later, it will be generated by pool side.    end



    return true;
}


bool AbelMineAccount::registerAccount(std::string workingDir)
{
    if (!workingDir.empty())
    {
        int ret = chdir(workingDir.c_str());
        if (-1 == ret)
        {
            std::cerr << "unable to change to directory " + workingDir << std::endl;
            return false;
        }
    }

    //  check whether the account file exits
    std::ifstream fAccount(abelMineAccountFile);
    if (fAccount.good())
    {
        std::string currPath = getcwd(nullptr, 0);

        std::cerr << "The account file for abelmine " << abelMineAccountFile << " exits in "
                  << currPath << ". Unable to register again." << std::endl;
        std::cerr << "If you want to register another, backup the address and account files, then remove the account file and try again."
                  << std::endl;

        return false;
    }


    std::cout << "Generating abelmine account to " << abelMineAccountFile
              << " using address in file " << abelMineAddressFile << std::endl;

    std::ifstream fAddress(abelMineAddressFile);
    if (!fAddress.good())
    {
        std::string currPath = getcwd(nullptr, 0);
        std::cerr << abelMineAddressFile << " not found in " + currPath << std::endl;
        return false;
    }

    // read address
    std::ifstream inFileAddress;
    inFileAddress.open(abelMineAddressFile, std::ios::in);
    if (!inFileAddress.is_open())
    {
        std::cerr << "Unable to read file " + abelMineAddressFile << std::endl;
        return false;
    }
    getline(inFileAddress, m_address);
    inFileAddress.close();

    if (!isValidAddress(m_address))
    {
        std::cerr << "The address is invalid" << std::endl;
        return false;
    }

    // generate account
    std::cout << "Generating account..." << std::endl;
    uint8_t* data = decodeHexString(m_address);
    if(data == nullptr)
    {
        std::cerr<<"Fail to decode address" << std::endl;
        return false;
    }

    SHA256 sha;
    uint8_t * doubleH = sha.doubleHash256(data, m_address.length()/2);
    m_user = SHA256::toString(doubleH);

    // write to file
    std::ofstream ofs;
    ofs.open(abelMineAccountFile,std::ios::out);
    if(!ofs.is_open()) {
        std::cerr << "Unable to open file " + abelMineAccountFile << std::endl;
        return false;
    }
    ofs << m_user << std::endl;

    std::cout << "Set password (for future access): ";
    std::cin >> m_password;
    ofs << m_password << std::endl;
    ofs.close();

    std::cout << "Generate account successfully." << std::endl;

    return true;
}


bool AbelMineAccount::isValidAddress(std::string address)
{
    int addressLen = address.length() / 2;
    if (addressLen < 33)
    {
        return false;
    }
    uint8_t* addressBytes = decodeHexString(address);

    // Check verification hash
    uint8_t* verifyBytes = new uint8_t[addressLen - 32];
    for (int i = 0; i < addressLen - 32; i++)
    {
        verifyBytes[i] = addressBytes[i];
    }
    uint8_t* targetBytes = new uint8_t[32];
    for (int i = 0; i < 32; i++)
    {
        targetBytes[i] = addressBytes[addressLen - 32 + i];
    }

    SHA256 sha;
    uint8_t* realBytes = sha.doubleHash256(verifyBytes, addressLen - 32);

    for (int i = 0; i < 32; i++)
    {
        if (targetBytes[i] != realBytes[i])
        {
            delete[] verifyBytes;
            delete[] targetBytes;
            return false;
        }
    }

    delete[] verifyBytes;
    delete[] targetBytes;
    return true;
}


}   //  namespace abelmine
}   //  namespace poolaccounts
//
// Created by liu on 22-11-2.
//

#include "stringutils.h"
#include <cstring>
#include <string>


namespace poolaccounts
{
namespace abelmine
{


uint8_t* decodeHexString(std::string str) {

    if(str.empty())
        return nullptr;

    size_t slength = str.length();
    if((slength % 2) != 0) // must be even
        return nullptr;

    size_t dlength = slength / 2;

    uint8_t* data = new uint8_t[dlength];
    memset(data, 0, dlength);

    size_t index = 0;
    while (index < slength) {
        char c = str[index];
        int value = 0;
        if(c >= '0' && c <= '9')
            value = (c - '0');
        else if (c >= 'A' && c <= 'F')
            value = (10 + (c - 'A'));
        else if (c >= 'a' && c <= 'f')
            value = (10 + (c - 'a'));
        else {
            delete []data;
            return nullptr;
        }

        data[(index/2)] += value << (((index + 1) % 2) * 4);

        index++;
    }

    return data;
}

}   // namespace abelmine
}   // namespace poolaccounts


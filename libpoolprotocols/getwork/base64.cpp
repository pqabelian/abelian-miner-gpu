//
// Created by osy on 22-9-18.
//

#include "base64.h"

bool Base64Encode(const string& input, string* output) {
    typedef boost::archive::iterators::base64_from_binary<boost::archive::iterators::transform_width<string::const_iterator, 6, 8> > Base64EncodeIterator;
    stringstream result;
    copy(Base64EncodeIterator(input.begin()) , Base64EncodeIterator(input.end()), ostream_iterator<char>(result));
    size_t equal_count = (3 - input.length() % 3) % 3;
    for (size_t i = 0; i < equal_count; i++) {
        result.put('=');
    }
    *output = result.str();
    return output->empty() == false;
}

bool Base64Decode(const string& input, string* output)
{
    typedef boost::archive::iterators::transform_width<
        boost::archive::iterators::binary_from_base64<string::const_iterator>, 8, 6>
        Base64DecodeIterator;
    stringstream result;
    try
    {
        copy(Base64DecodeIterator(input.begin()), Base64DecodeIterator(input.end()),
            ostream_iterator<char>(result));
    }
    catch (...)
    {
        return false;
    }
    *output = result.str();
    return output->empty() == false;
}
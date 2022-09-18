//
// Created by osy on 22-9-18.
//

#ifndef ETHMINER_BASE64_H
#define ETHMINER_BASE64_H
#include <boost/archive/iterators/base64_from_binary.hpp>
#include <boost/archive/iterators/binary_from_base64.hpp>
#include <boost/archive/iterators/transform_width.hpp>
#include <iostream>
#include <string>
#include <sstream>

using namespace std;
bool Base64Encode(const string& input, string* output);
bool Base64Decode(const string& input, string* output);
#endif  // ETHMINER_BASE64_H

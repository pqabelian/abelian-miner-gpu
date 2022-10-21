set(SOURCES
	PoolURI.cpp PoolURI.h
	PoolClient.h
	PoolManager.h PoolManager.cpp
	testing/SimulateClient.h testing/SimulateClient.cpp
	stratum/EthStratumClient.h stratum/EthStratumClient.cpp stratum/AbelStratumClient.cpp stratum/AbelStratumClient.h
	getwork/EthGetworkClient.h getwork/EthGetworkClient.cpp getwork/AbelGetworkClient.h getwork/AbelGetworkClient.cpp
        getwork/base64.cpp getwork/base64.h )

hunter_add_package(OpenSSL)
find_package(OpenSSL REQUIRED)

add_library(poolprotocols ${SOURCES})
target_link_libraries(poolprotocols PRIVATE devcore ethminer-buildinfo abelethash::ethash Boost::system jsoncpp_static OpenSSL::SSL OpenSSL::Crypto)
target_include_directories(poolprotocols PRIVATE ..)

/**
 * @file   ldar_crypto.cpp
 * @author Liu Min <minwhut@icloud.com>
 * @date   Mon May 30 18:59:06 2016
 * 
 * @brief  
 * 
 * 
 */

#include "ldar_crypto.h"
#include <openssl/aes.h>
#include <openssl/evp.h>


AESCrypter::AESCrypter(const std::string& key, const std::string& iv): key_(key), iv_(iv) {
  Init();
}


AESCrypter::AESCrypter(const char* key, const char* iv): key_(key), iv_(iv) {
  Init();
}

AESCrypter::~AESCrypter() {
  EVP_CIPHER_CTX_cleanup(&ctx_);
}

void AESCrypter::Init() {
  EVP_CIPHER_CTX_init(&ctx_);
  cryptoAlgorithm_ = EVP_aes_128_cbc();
}

int AESCrypter::BlockSize() const
{
  return EVP_CIPHER_CTX_block_size(&ctx_);
}


void AESCrypter::Setup(int dir)
{
  dir_ = dir;
  if (0 == dir) {
    EVP_EncryptInit_ex(&ctx_, cryptoAlgorithm_, 0, 0, 0);
    EVP_CIPHER_CTX_set_key_length(&ctx_, key_.size());
    EVP_EncryptInit_ex(&ctx_, 0, 0,
                       (const unsigned char*)(key_.data()),
                       (const unsigned char*)(iv_.data()));
  } else {
    EVP_DecryptInit_ex(&ctx_, cryptoAlgorithm_, 0, 0, 0);
    EVP_CIPHER_CTX_set_key_length(&ctx_, key_.size());
    EVP_DecryptInit_ex(&ctx_, 0, 0,
                       (const unsigned char*)(key_.data()),
                       (const unsigned char*)(iv_.data()));
  }

  EVP_CIPHER_CTX_set_padding(&ctx_, 1);
}

bool AESCrypter::Update(const std::string &in, std::string& out)
{
  if ( 0 == in.size() )
    return true;

  out.resize(in.size()+BlockSize());
  int resultLength;
  if (0 == dir_) {
    if (0 == EVP_EncryptUpdate(&ctx_,
                               (unsigned char*)out.data(),
                               &resultLength,
                               (unsigned char*)in.data(),
                               in.size())) {
      return false;
    }
  } else {
    if (0 == EVP_DecryptUpdate(&ctx_,
                               (unsigned char*)out.data(),
                               &resultLength,
                               (unsigned char*)in.data(),
                               in.size())) {
      return false;
    }
  }
  out.resize(resultLength);
  return true;
}

bool AESCrypter::Final(std::string &out)
{
  out.resize(BlockSize());
  int resultLength;
  if (0 == dir_) {
    if (0 == EVP_EncryptFinal_ex(&ctx_,
                                 (unsigned char*)out.data(),
                                 &resultLength)) {
      return false;
    }
  } else {
    if (0 == EVP_DecryptFinal_ex(&ctx_,
                                 (unsigned char*)out.data(),
                                 &resultLength)) {
      return false;
    }
  }
  out.resize(resultLength);
  return true;
}

bool AESCrypter::Encrypt(const std::string& input, std::string& output) {
  Setup(0);
  std::string u, f;
  if (!Update(input, u))
    return false;
  if (!Final(f))
    return false;
  output = u + f;
  return true;
}


bool AESCrypter::Decrypt(const std::string& input, std::string& output) {
  Setup(1);
  std::string u, f;
  if (!Update(input, u))
    return false;
  if (!Final(f))
    return false;
  output = u + f;
  return true;
}


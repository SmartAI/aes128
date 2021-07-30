/**
 * @file   ldar_crypto.h
 * @author Liu Min <minwhut@icloud.com>
 * @date   Mon May 30 16:50:55 2016
 * 
 * @brief  ldar crypto module, only support aes128
 * 
 * @note using openssl Evp API
 */
#ifndef _LDAR_CRYPTO_H_
#define _LDAR_CRYPTO_H_

#include <string>
#include <openssl/evp.h>


class AESCrypter {
 public:
  AESCrypter(const std::string& key, const std::string& iv);
  AESCrypter(const char* key, const char* iv);
  ~AESCrypter();

  bool Encrypt(const std::string& input, std::string& output);
  bool Decrypt(const std::string& input, std::string& output);
  
private:
  int BlockSize() const;
  void Init() ;
  void Setup(int dir);
  bool Update(const std::string &in, std::string& out);
  bool Final(std::string &out);
  int dir_;
  std::string key_;
  std::string iv_;
  EVP_CIPHER_CTX *ctx_;
  const EVP_CIPHER *cryptoAlgorithm_;
};


#endif /* _LDAR_CRYPTO_H_ */

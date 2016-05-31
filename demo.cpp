#include "ldar_crypto.h"
#include <iostream>

//using namespace LDAR;

int main(int argc, char *argv[]) {
  std::string key("6d272c9858b53daaa9fdd54a1ec6a5a7");
  std::string iv("08d0ed4a1a28840fbf6a63189de6c9cd");
  AESCrypter ldar_aes(key, iv);
  if (argc < 2) {
      std::cout << "need a string to be encrypted" << std::endl;
      return -1;
  }

  std::string input(argv[1]);
  std::string output;
  std::string tmp;
  
  if (!ldar_aes.Encrypt(input, output)) {
    std::cout << "encrypt error " << std::endl;
    return -1;
  }

  if (!ldar_aes.Decrypt(output, tmp)) {
    std::cout << "decrypt error ";
    return -1;
  }
  
  std::cout << output << std::endl;
  std::cout << tmp << std:: endl;
  return 0;
}


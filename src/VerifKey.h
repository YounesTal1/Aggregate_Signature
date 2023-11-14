#ifndef _VerifKey_h
#define _VerifKey_h  
  

#include <pbc/pbc.h>
#include "Param.h"
#include "SignKey.h"
  
  
class VerifKey {
public:
  VerifKey(Param pr, SignKey sk);

  void Verify(element_t signature, element_t message);
  void Aggregate(element_t aggsig, std::vector<element_t>& signature, std::vector<element_t> &message);
  void DPP(element_t result, int l, std::vector<element_t> &signatures, std::vector<element_t> &messages);
  std::vector<element_t> CalculateCoeff(std::vector<element_t>& messages);
  std::vector<element_t> CalculateCoeffOmit(int index, std::vector<element_t>& messages);
  void AggVerify(element_t signature, std::vector<element_t>& messages);
  void LocalOpen(element_t aux1, element_t aux2, int index, std::vector<element_t>& messages);
  void LocalAggVerify(element_t signature, element_t message, element_t aux1, element_t aux2);

private:
  std::vector<element_t> vk; 
  Param pr;
  element_t vklocal;

};
  
  
#endif  


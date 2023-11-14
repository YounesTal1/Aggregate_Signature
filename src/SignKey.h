#ifndef _SignKey_h
#define _SignKey_h  
  

#include <pbc/pbc.h>

#include "Param.h"
#include <vector>
  
class SignKey {
public:
    SignKey(Param pr);
    element_t& getAlpha();
    void Sign(element_t signature, element_t message);
    void SeqAggSign(element_t aggsig_new, element_t message, std::vector<element_t>& messages, element_t aggsig_old);

private:
    element_t alpha;
    Param pr;
};
  
  
#endif  


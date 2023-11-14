#ifndef _Param_h
#define _Param_h  
  
#include <pbc/pbc.h>
  
  
class Param {
public:

    Param();
    Param(const char *pstr);

    pairing_t& getPairing();
    element_t& getGenerator();

private:
    pairing_t pairing;
    element_t g; // Generator G1
};  
  
#endif  


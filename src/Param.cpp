#include "Param.h"


int B = 80;
Param::Param(){}


Param::Param(const char *pstr)
{
	pairing_init_set_str(this->pairing, pstr);
	element_init_G1(this->g, this->pairing);
	element_random(this->g);

}

pairing_t& Param::getPairing()
{
	return this->pairing;
}

element_t& Param::getGenerator()
{ 
	return this->g; 
}


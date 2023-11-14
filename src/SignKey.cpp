#include <cassert>
#include "SignKey.h"
#include "VerifKey.h"
#include "Global.h"
#include <pbc/pbc_field.h>
#include <iostream>
#include <vector>



SignKey::SignKey(Param pr)
{

   this->pr = pr;
   element_init_Zr(this->alpha, this->pr.getPairing());
   element_random(this->alpha);

}

element_t& SignKey::getAlpha()
{
	return this->alpha; 
}


void SignKey::Sign(element_t signature, element_t message)
{

	element_t tmp;
	element_init_Zr(tmp, this->pr.getPairing());
	element_add(tmp, this->alpha, message);
	element_invert(tmp, tmp);
	element_pow_zn(signature, this->pr.getGenerator(), tmp);
	element_clear(tmp);
}



void SignKey::SeqAggSign(element_t aggsig_new, element_t message, std::vector<element_t> &messages, element_t aggsig_old)
{
	element_t tmp;
        element_init_Zr(tmp, this->pr.getPairing());
        element_add(tmp, this->alpha, message);
        element_invert(tmp, tmp);
        element_pow_zn(aggsig_new, aggsig_old, tmp);
	element_clear(tmp);

}

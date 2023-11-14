#include "VerifKey.h"
#include "SignKey.h"
#include "Global.h"
#include "Param.h"
#include <pbc/pbc_field.h>
#include <iostream>
#include <cassert>


VerifKey::VerifKey(Param pr, SignKey sk) : pr(pr), vk(B) {


    element_init_G1(vk[0], pr.getPairing());
    element_init_G1(vklocal, pr.getPairing());
    element_pow_zn(vk[0], pr.getGenerator(), sk.getAlpha());
    element_set(vklocal, vk[0]);


    for (int i = 1; i < B; i++)
    {
        element_init_G1(vk[i], pr.getPairing());
        element_pow_zn(vk[i], vk[i-1], sk.getAlpha());
    }
}


void VerifKey::Verify(element_t signature, element_t message)
{



	element_t v1, v2, tmp;
      	element_init_GT(v1, this->pr.getPairing());
	pairing_apply(v1, this->pr.getGenerator(), this->pr.getGenerator(), this->pr.getPairing());


      	element_init_G1(tmp, this->pr.getPairing());
      	element_init_GT(v2, this->pr.getPairing());

	element_pow_zn(tmp, this->pr.getGenerator(), message);
	element_mul(tmp, tmp, this->vk[0]);
	pairing_apply(v2, signature, tmp, this->pr.getPairing());



	bool b = !element_cmp(v1, v2);
	assert(b == 1);

	element_clear(v1);
	element_clear(v2);
	element_clear(tmp);
}

//DPP taken from "Cécile Delerablée, Pascal Paillier, and David Pointcheval. Fully collusion secure dynamic broadcast encryption with constant-size ciphertexts or decryption keys".
//
//Note that this algorithm requires that the messages it is operating over are pairwise distinct, while there is no check in the code to guarantee this. This is not likely to happen as the messages are generated at random from Zr

void VerifKey::DPP(element_t result, int l, std::vector<element_t> &signatures, std::vector<element_t> &messages)
{
	element_t tmp, tmp2;
	element_init_Zr(tmp, this->pr.getPairing());
	element_init_G1(tmp2, this->pr.getPairing());
	std::vector<element_t> Powers(l);
	for (int i = 0; i < l; i++) 
	{
          element_init_G1(Powers[i], this->pr.getPairing());
          element_set(Powers[i], signatures[i]);
        }


	for (int i = 0; i < l - 1; i++)
	{
		for(int j = i + 1; j < l ; j++)
		{
			if ( i != j )
			{
				element_sub(tmp, messages[j], messages[i]);
				element_invert(tmp, tmp);
				element_sub(tmp2, Powers[i], Powers[j]);
				element_pow_zn(Powers[j], tmp2, tmp); 
			}
		}
	}
	element_set(result, Powers[l-1]);

	element_clear(tmp);
	element_clear(tmp2);
	for (int j = 0; j < l; j++) 
	{                                                                                                         
               element_clear(Powers[j]);                                                                                                         
        }


}

void VerifKey::Aggregate(element_t aggsig, std::vector<element_t> &signatures, std::vector<element_t> &messages) {
	int l = signatures.size();

	for(int i = 0; i < l; i++)
	{
		Verify(signatures[i], messages[i]);
	}

	DPP(aggsig, l, signatures, messages);
}

std::vector<element_t> VerifKey::CalculateCoeffOmit(int index, std::vector<element_t>& messages)
{

    int l = messages.size();
    std::vector<element_t> coeffs(l);
    element_t tmp;

    for (int i = 0; i < l; i++)
    {
        element_init_Zr(coeffs[i], this->pr.getPairing());
        element_set0(coeffs[i]);
    }


    element_set1(coeffs[0]);
    element_init_Zr(tmp, this->pr.getPairing());


    for (int i = 0; i < l; i++)
    {
	   if(index != i)
	   {
		std::vector<element_t> newCoeffs(l);

		for (int j = 0; j < l; j++)
		{
		    element_init_Zr(newCoeffs[j], this->pr.getPairing());
		    element_set0(newCoeffs[j]);
		}

		for (int j = 0; j < l - 1; j++)
		{
			    element_add(newCoeffs[j + 1], newCoeffs[j + 1], coeffs[j]);
			    element_mul(tmp, messages[i], coeffs[j]);
			    element_add(newCoeffs[j], newCoeffs[j], tmp);
		}

		for (int j = 0; j < l; j++) 
		{
		    element_clear(coeffs[j]);
		}

		coeffs = std::move(newCoeffs);
	   }
    }
    return coeffs;


}


std::vector<element_t> VerifKey::CalculateCoeff(std::vector<element_t>& messages)
{

    int l = messages.size();
    std::vector<element_t> coeffs(l + 1);
    element_t tmp;

    for (int i = 0; i < l+1; i++)
    {
        element_init_Zr(coeffs[i], this->pr.getPairing());
        element_set0(coeffs[i]);
    }

    element_set1(coeffs[0]);

    element_init_Zr(tmp, this->pr.getPairing());


    for (auto& mi : messages)
    {
        std::vector<element_t> newCoeffs(coeffs.size() + 1);

        for (auto& coeff : newCoeffs) {
            element_init_Zr(coeff, this->pr.getPairing());
            element_set0(coeff);
        }

        for (int j = 0; j < l+1; j++) {
            element_add(newCoeffs[j + 1], newCoeffs[j + 1], coeffs[j]);
            element_mul(tmp, mi, coeffs[j]);
            element_add(newCoeffs[j], newCoeffs[j], tmp);
        }

        for (int j = 0; j < l+1; j++)
	{
            element_clear(coeffs[j]);
        }

        coeffs = std::move(newCoeffs);
    }
    return coeffs;


}

void VerifKey::AggVerify(element_t signature, std::vector<element_t>& messages) {


    int l = messages.size();
    assert (l <= B);
    std::vector<element_t> coeffs(l + 1);
    coeffs = CalculateCoeff(messages);

    element_t prod, tmp;

    element_init_G1(prod, this->pr.getPairing());
    element_init_G1(tmp, this->pr.getPairing());
    element_set(prod, this->pr.getGenerator());
    element_pow_zn(prod, prod, coeffs[0]);


    for (int i = 0; i < l; i++) 
    {
    	element_pow_zn(tmp, this->vk[i], coeffs[i+1]);
    	element_mul(prod, prod, tmp); 
    }

    element_t v1, v2;
  
          
    element_init_GT(v1, this->pr.getPairing());
    pairing_apply(v1, this->pr.getGenerator(), this->pr.getGenerator(), this->pr.getPairing());
    element_init_GT(v2, this->pr.getPairing());
    pairing_apply(v2, signature, prod, this->pr.getPairing());

    bool b = !element_cmp(v1, v2);
    assert(b == 1);

    element_clear(v1);
    element_clear(v2);
    element_clear(prod);
    element_clear(tmp);
    for (int j = 0; j < l+1; j++)                                                                                                                   
    {                                                                                                                                             
          element_clear(coeffs[j]);                                                                                                              
    }

}



void VerifKey::LocalOpen(element_t aux1, element_t aux2, int index, std::vector<element_t>& messages)
{

    int l = messages.size();
    std::vector<element_t> coeffs(l);                                                                                               

    coeffs = CalculateCoeffOmit(index, messages);


      element_t prod, tmp;
  
      element_init_G1(prod, this->pr.getPairing()); 
      element_init_G1(tmp, this->pr.getPairing());
      element_set(prod, this->pr.getGenerator());
      element_pow_zn(prod, prod, coeffs[0]);
  
    for (int i = 0; i < l - 1; i++)
    {
          element_pow_zn(tmp, this->vk[i], coeffs[i+1]);
          element_mul(prod, prod, tmp);
    }

    element_set(aux1, prod);

    element_set1(prod);
  
    for (int i = 0; i < l; i++)
    {
          element_pow_zn(tmp, this->vk[i], coeffs[i]);
          element_mul(prod, prod, tmp);  
    }
    element_set(aux2, prod);


    element_clear(prod);
    element_clear(tmp);
    for (int j = 0; j < l; j++)                                                                                                                   
    {                                                                                                                                             
                 element_clear(coeffs[j]);                                                                                                              
    }
}


void VerifKey::LocalAggVerify(element_t signature, element_t message, element_t aux1, element_t aux2)
{
      element_t v1, v2, tmp;
      bool b1, b2;

      element_init_GT(v1, this->pr.getPairing());

      pairing_apply(v1, this->pr.getGenerator(), this->pr.getGenerator(), this->pr.getPairing());
      
      element_init_GT(v2, this->pr.getPairing());
      element_init_G1(tmp, this->pr.getPairing());
      element_pow_zn(tmp, aux1, message);
      element_mul(tmp, tmp, aux2);
      pairing_apply(v2, signature, tmp, this->pr.getPairing());
      b1 = !element_cmp(v1, v2);

      pairing_apply(v1, this->vklocal, aux1, this->pr.getPairing());
      pairing_apply(v2, this->pr.getGenerator(), aux2, this->pr.getPairing());
      b2 = !element_cmp(v1, v2);
      assert(b1*b2 == 1);


      element_clear(v1);
      element_clear(v2);
      element_clear(tmp);


}


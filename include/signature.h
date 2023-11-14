#include <cassert>
#include "Param.h"
#include "SignKey.h"
#include "VerifKey.h"
#include "Global.h"

#include <iostream>
  
using namespace std;

void test_sign(Param pr, element_t message)
{

	SignKey sk(pr);

	VerifKey vk(pr, sk);
	element_t signature;
	element_init_G1(signature, pr.getPairing());

	sk.Sign(signature, message); 
	vk.Verify(signature, message);

}

void test_aggsign(Param pr, std::vector<element_t>& messages)
{
	int l = messages.size();
	SignKey sk(pr);
	VerifKey vk(pr, sk);

	element_t aggsig;
        element_init_G1(aggsig, pr.getPairing());
	std::vector<element_t> signatures(l);


	for(int i = 0; i < l ; i++)
	{
		element_init_G1(signatures[i], pr.getPairing());
		sk.Sign(signatures[i], messages[i]); 
	}


	vk.Aggregate(aggsig, signatures, messages);
	vk.AggVerify(aggsig, messages);

}

void test_aggloc(Param pr, std::vector<element_t>& messages)
{
	int l = messages.size();
	SignKey sk(pr);
	VerifKey vk(pr, sk);

	element_t aggsig;
        element_init_G1(aggsig, pr.getPairing());
	std::vector<element_t> signatures(l);


	for(int i = 0; i < l ; i++)
	{
		element_init_G1(signatures[i], pr.getPairing());
		sk.Sign(signatures[i], messages[i]); 
	}


	vk.Aggregate(aggsig, signatures, messages);
	element_t aux1, aux2;
        element_init_G1(aux1, pr.getPairing());
        element_init_G1(aux2, pr.getPairing());
	int index ;

	for (int i = 0; i < l; i++)
	{
		index = i;
		vk.LocalOpen(aux1, aux2, index, messages);
		vk.LocalAggVerify(aggsig, messages[index], aux1, aux2);
		vk.AggVerify(aggsig, messages);

	}

}


void test_aggseq(Param pr, std::vector<element_t>& messages)
{
	int l = messages.size();
	SignKey sk(pr);
	VerifKey vk(pr, sk);

	element_t aggsig;
        element_init_G1(aggsig, pr.getPairing());
	std::vector<element_t> signatures(l);


	for(int i = 0; i < l ; i++)
	{
		element_init_G1(signatures[i], pr.getPairing());
		sk.Sign(signatures[i], messages[i]); 
	}


	vk.Aggregate(aggsig, signatures, messages);

	element_t aggsig_new, message;                                                                                                              
        element_init_G1(aggsig_new, pr.getPairing());                                                                                                  
        element_init_Zr(message, pr.getPairing());                                                                                                  
	element_random(message);


	sk.SeqAggSign(aggsig_new, message, messages, aggsig);
	std::vector<element_t> messages_new(l+1);
	for(int i = 0; i < l; i++)
	{
		element_init_Zr(messages_new[i], pr.getPairing());
		element_set(messages_new[i], messages[i]);
	}
	element_init_Zr(messages_new[l], pr.getPairing());
	element_set(messages_new[l], message);
	vk.AggVerify(aggsig_new, messages_new);

}

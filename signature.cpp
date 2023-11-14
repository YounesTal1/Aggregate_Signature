#include "signature.h"
#include <string.h>
#include <iostream>

//using namespace std;

int main(int argc, char* argv[]) 
{

	FILE *param = fopen("a.param", "r");
        char buff[4096];
        fread(buff, 1, 4096, param);
	printf("System setup Key\n");
	cout << "B = " << B << endl;

	Param pr(buff);



///////////////////////////////////////////////////////////////////////////
//Tests:
///////////////////////////////////////////////////////////////////////////

	int nb = 50;
	assert(nb <= B);
	element_t message;

	element_init_Zr(message, pr.getPairing());
	

///////////////////////////////////////////////////////////////////////////
//Tests1:
///////////////////////////////////////////////////////////////////////////



	cout<< "First test: Sign and Verify over "<< nb << " random messages" << endl;
	for(int i = 0; i < nb; i++)
	{
		element_random(message);
		test_sign(pr, message);
	}

	cout<< "End test with no errors" << endl;
	

///////////////////////////////////////////////////////////////////////////
//Tests2:
///////////////////////////////////////////////////////////////////////////



	cout<< "Second test: Aggregate and AggVerify over " << nb << " random messages" << endl;
	std::vector<element_t> messages(nb);
	for(int i = 0; i < nb; i++)
          {                        
		element_init_Zr(messages[i], pr.getPairing());
                element_random(message);
		element_set(messages[i], message);
          }

	test_aggsign(pr, messages);



	cout<< "End test with no errors" << endl;



///////////////////////////////////////////////////////////////////////////
//Tests3:
///////////////////////////////////////////////////////////////////////////


  
	cout<< "Third test: LocalOpen and LocalAggVerify over " << nb << " random messages" << endl;
	test_aggloc(pr, messages);

	cout<< "End test with no errors" << endl;
	

///////////////////////////////////////////////////////////////////////////
//Tests4:
///////////////////////////////////////////////////////////////////////////


	cout<< "Fourth test: SeqAggSign and SeqAggVerify over " << nb << " random messages" << endl;	
	test_aggseq(pr, messages);

	cout<< "End test with no errors" << endl;

}


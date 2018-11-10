/*
 * tree_impl.h
 *
 *  Created on: Jul 6, 2018
 *      Author: suiguangye
 */

#ifndef TREE_IMPL_H_
#define TREE_IMPL_H_

#include "tree.h"

#include "scalar_low_impl.h"
/* functions for geTree */





void printtreeGe(const secp256k1_ge *r,  int size)
{
	 printf("size = %d \n",  size);
	int i = 0;
for ( i = 0;i< size; i++)
{
	   unsigned char tmp[64];

    secp256k1_ge_to_char(tmp,  r+i);
    printtreeChar(tmp, 64);
}


printf("end \n" );
}



void printtreeChar(const unsigned char *r,int size)
{
	 printf("size = %d \n",  size);
	int i = 0;
 for ( i = 0;i< size; i++)
	   printf(" %d",r[i]);


 printf(" \n" );
}




void printtreeScalar(const secp256k1_scalar *r,int size)
{
	 printf("size = %d \n",  size);
	int i = 0;
  for ( i = 0;i< size; i++)
  { unsigned char message_char[32];

  secp256k1_scalar_get_b32(message_char, r+i);

  printtreeChar(message_char, 32);

  }


  printf(" \n" );
}





















#endif /* TREE_IMPL_H_ */

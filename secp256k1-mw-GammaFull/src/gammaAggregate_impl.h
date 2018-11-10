

#ifndef GAMMAAGGREGATE_IMPL_H_
#define GAMMAAGGREGATE_IMPL_H_

/*#include "secp256k1.c"*/

#include "field.h"
#include "group.h"
#include "ecmult.h"
#include "ecmult_gen.h"
#include "gammaAggregate.h"
#include "scalar.h"
#include "scalar_impl.h"







static int secp256k1_gamma_sig_verify(const secp256k1_ecmult_context *ctx, const secp256k1_scalar *sigd, const secp256k1_scalar *sigz,
		const secp256k1_ge *pubkey, const secp256k1_scalar *message) {
	unsigned char message_char[32];
	secp256k1_sha256 hasher;
	unsigned char output_hash[32];
    secp256k1_scalar e, dn,zn;
    unsigned char pub_char[64];

    secp256k1_gej pubkeyj;
    secp256k1_gej pr;

    secp256k1_gej A;
    secp256k1_ge Ae;

    secp256k1_scalar hasha;

    int overflow = 0;



    secp256k1_ge_to_char(pub_char, pubkey);
    secp256k1_scalar_get_b32(message_char, message);

    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, pub_char, sizeof(pub_char));
    secp256k1_sha256_write(&hasher, message_char, sizeof(message_char));
    secp256k1_sha256_finalize(&hasher,output_hash);


    secp256k1_scalar_set_b32(&e, output_hash, &overflow);

    VERIFY_CHECK(overflow == 0);

    secp256k1_gej_set_ge(&pubkeyj, pubkey);
    secp256k1_scalar_inverse_var(&dn, sigd);  /* dn = sigd^(-1) */
    secp256k1_scalar_mul(&e, &e, &dn);
    secp256k1_scalar_mul(&zn, sigz, &dn);
    secp256k1_ecmult(ctx, &A, &pubkeyj, &e, &zn);    /* A = pubkeyj*e + zn*G  */


    secp256k1_ge_set_gej(&Ae, &A);
    secp256k1_ge_to_char(pub_char, &Ae);

    /* printf("hasha =  " );
     printChar(pub_char, sizeof(pub_char));*/

    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, pub_char, sizeof(pub_char));
    secp256k1_sha256_finalize(&hasher,output_hash);



    secp256k1_scalar_set_b32(&hasha, output_hash, &overflow);

    VERIFY_CHECK(overflow == 0);

    /* printf("random run \n"); */

    if(secp256k1_scalar_eq(&hasha, sigd) == 1)
    {
    	return 1;
    }
    return 0;



}



static int secp256k1_gamma_sig_verify_forAGG(const secp256k1_ecmult_context *ctx,
		const secp256k1_scalar *sigd, const secp256k1_scalar *sigz,
		const secp256k1_ge *pubkey, const secp256k1_scalar *message,  secp256k1_ge *Ae) {
	unsigned char message_char[32];
	secp256k1_sha256 hasher;
	unsigned char output_hash[32];
    secp256k1_scalar e, dn,zn;
    unsigned char pub_char[64];

    secp256k1_gej pubkeyj;
    secp256k1_gej pr;

    secp256k1_gej A;
    /*secp256k1_ge Ae;*/

    secp256k1_scalar hasha;

    int overflow = 0;



    secp256k1_ge_to_char(pub_char, pubkey);
    secp256k1_scalar_get_b32(message_char, message);

    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, pub_char, sizeof(pub_char));
    secp256k1_sha256_write(&hasher, message_char, sizeof(message_char));
    secp256k1_sha256_finalize(&hasher,output_hash);


    secp256k1_scalar_set_b32(&e, output_hash, &overflow);

    VERIFY_CHECK(overflow == 0);

    secp256k1_gej_set_ge(&pubkeyj, pubkey);
    secp256k1_scalar_inverse_var(&dn, sigd);  /* dn = sigd^(-1) */
    secp256k1_scalar_mul(&e, &e, &dn);
    secp256k1_scalar_mul(&zn, sigz, &dn);
    secp256k1_ecmult(ctx, &A, &pubkeyj, &e, &zn);    /* A = pubkeyj*e + zn*G  */


    secp256k1_ge_set_gej( Ae, &A);
    secp256k1_ge_to_char(pub_char, Ae);

    /* printf("hasha =  " );
     printChar(pub_char, sizeof(pub_char));*/

    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, pub_char, sizeof(pub_char));
    secp256k1_sha256_finalize(&hasher,output_hash);



    secp256k1_scalar_set_b32(&hasha, output_hash, &overflow);

    VERIFY_CHECK(overflow == 0);

    /* printf("random run \n"); */

    if(secp256k1_scalar_eq(&hasha, sigd) == 1)
    {
    	return 1;
    }
    return 0;



}







static int secp256k1_gamma_sig_sign(const secp256k1_ecmult_gen_context *ctx, secp256k1_scalar *sigd,
		secp256k1_scalar *sigz, const secp256k1_scalar *seckey, const secp256k1_scalar *message, const secp256k1_scalar *nonce, int *recid) {
    unsigned char b[32];
    secp256k1_gej rp;
    secp256k1_ge r;
    secp256k1_scalar n;

    unsigned char message_char[32];
    secp256k1_sha256 hasher;
    unsigned char output_hash[32];

    unsigned char tmp[64];

    secp256k1_gej pubkey;

    int overflow = 0;

    secp256k1_ecmult_gen(ctx, &rp, nonce);      /* A = rp = nonce * P  */
    secp256k1_ge_set_gej(&r, &rp);
    secp256k1_ge_to_char(tmp, &r);

  /*  printf("hasha =  " );
     printChar(tmp, sizeof(tmp)); */

    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, tmp, sizeof(tmp));
    secp256k1_sha256_finalize(&hasher,output_hash);



    secp256k1_scalar_set_b32(sigd, output_hash, &overflow);

    VERIFY_CHECK(overflow == 0);

    if (recid) {
        /* The overflow condition is cryptographically unreachable as hitting it requires finding the discrete log
         * of some P where P.x >= order, and only 1 in about 2^127 points meet this criteria.
         */
        *recid = (overflow ? 2 : 0) | (secp256k1_fe_is_odd(&r.y) ? 1 : 0);
    }


    secp256k1_ecmult_gen(ctx, &pubkey, seckey);
    secp256k1_ge_set_gej(&r, &pubkey);                    /*gej to ge */
    secp256k1_ge_to_char(tmp, &r);
    secp256k1_scalar_get_b32(message_char, message);

    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, tmp, sizeof(tmp));
    secp256k1_sha256_write(&hasher, message_char, sizeof(message_char));
    secp256k1_sha256_finalize(&hasher,output_hash);


    secp256k1_scalar_set_b32(sigz, output_hash, &overflow);
    VERIFY_CHECK(overflow == 0);

    secp256k1_scalar_mul( sigz, sigz, seckey);
    secp256k1_scalar_negate(sigz, sigz);

    secp256k1_scalar_mul(nonce, nonce, sigd);
    secp256k1_scalar_add(sigz, sigz, nonce);


    secp256k1_scalar_clear(&n);
    secp256k1_gej_clear(&rp);
    secp256k1_gej_clear(&pubkey);
    secp256k1_ge_clear(&r);


    /*
    if (secp256k1_scalar_is_zero(sigs)) {
        return 0;
    }
    if (secp256k1_scalar_is_high(sigs)) {
        secp256k1_scalar_negate(sigs, sigs);
        if (recid) {
            *recid ^= 1;
        }
    }*/
    return 1;
}



/*
 *
 *
 *static int secp256k1_gamma_Agg(const secp256k1_ecmult_context *ctx,
		const secp256k1_ge *pubkey, const secp256k1_scalar *message,  const secp256k1_scalar *d,
		const secp256k1_scalar *z, const int size,
		 secp256k1_ge *outpubkey,  secp256k1_scalar *outmessage, secp256k1_ge *A, int *outsize, secp256k1_scalar *sumZ)
  int i;
    int pos1 = 0;
    int pos2 = 0;

    secp256k1_ge  *tempA = (secp256k1_ge*) malloc (size*sizeof(secp256k1_ge));



   secp256k1_scalar_set_int(sumZ, 0);

   tHatTreeNode *tHat = NULL;
   geTreeNode *aHat = NULL;



    for (i = 0; i<size ; i++)
    {
    	int check =  secp256k1_gamma_sig_verify_forAGG( ctx ,  d+i,  z+i, pubkey+i, message+i,tempA+i);
    	 int check1 =  tHatTree_Find ( pubkey+i ,  message+i ,tHat)   ;
    	int check2 =  geTree_Find ( tempA+i ,aHat) ;

    	if ( check == 1   &&
    			( check1 == 0) && (check2 == 0 ) )
    	{
    		tHat = tHatTree_Insertion(pubkey+i, message+i, tHat);
    		aHat = geTree_Insertion(tempA+i, aHat);


    		secp256k1_scalar_add(sumZ, sumZ, z+i);
    	}
    	 else
    	{
    		  printf("i= %d,   check1 =  %d , check2 =  %d \n "
    				  , i,   check1, check2);



    	}
    }



    tHatTree_inorder(tHat, outpubkey ,outmessage,  &pos1);
    geTree_inorder(aHat, A,  &pos2);

    free(tempA);

    releasetHatTreeNode(tHat);
    releasegeTreeNode(aHat);


    if (pos1 != pos2)
    {
    	return 0;
    }
    else
    {
    	*outsize = pos1;
    }

    return 1;

   */



static int secp256k1_gamma_Agg(const secp256k1_ecmult_context *ctx,
		const secp256k1_ge *pubkey, const secp256k1_scalar *message,  const secp256k1_scalar *d,
		const secp256k1_scalar *z, const int size,
		 secp256k1_ge *outpubkey,  secp256k1_scalar *outmessage, secp256k1_ge *A, int *outsize, secp256k1_scalar *sumZ)
{
    int i;
    int pos1 = 0;
    int pos2 = 0;

    secp256k1_ge  *tempA = (secp256k1_ge*) malloc (size*sizeof(secp256k1_ge));



   secp256k1_scalar_set_int(sumZ, 0);

   tHatTreeNode *tHat = NULL;
   geTreeNode *aHat = NULL;

    for (i = 0; i<size ; i++)
    {
    	int check =  secp256k1_gamma_sig_verify_forAGG( ctx ,  d+i,  z+i, pubkey+i, message+i,tempA+i);
    	 int check1 =  tHatTree_Find ( pubkey+i ,  message+i ,tHat)   ;
    	int check2 =  geTree_Find ( tempA+i ,aHat) ;

    	if ( check == 1   &&
    			( check1 == 0) && (check2 == 0 ) )
    	{
    		tHat = tHatTree_Insertion(pubkey+i, message+i, tHat);
    		aHat = geTree_Insertion(tempA+i, aHat);


    		secp256k1_scalar_add(sumZ, sumZ, z+i);
    	}

    }




    tHatTree_inorder(tHat, outpubkey ,outmessage,  &pos1);
    geTree_inorder(aHat, A,  &pos2);

    free(tempA);

    releasetHatTreeNode(tHat);
    releasegeTreeNode(aHat);


    if (pos1 != pos2)
    {
    	return 0;
    }
    else
    {
    	*outsize = pos1;
    }

    return 1;
}

static int secp256k1_gamma_Agg_verify(const secp256k1_context *ctx, const secp256k1_ecmult_context *ctxecmult,
		const secp256k1_ge *pubkey, const secp256k1_scalar *message,
		const secp256k1_ge *A, const int size,  const secp256k1_scalar *sumZ)
{

     if (checkTSet(pubkey, message, size)== 0)
     {
    	 return 0;
     }

     if (checkASet(A, size) == 0)
     {

    	 return 0;
     }

     /*printf("verifySize =  %d ",   size);*/

     int totalSize = 2*size;

     secp256k1_scalar *index =  (secp256k1_scalar*) malloc (totalSize*sizeof(secp256k1_scalar));
     secp256k1_gej  *points = (secp256k1_gej*) malloc (totalSize*sizeof(secp256k1_gej));
     secp256k1_gej  *result = (secp256k1_gej*) malloc ( sizeof(secp256k1_gej));
     secp256k1_ge   *gepoints = (secp256k1_ge *) malloc (totalSize*sizeof(secp256k1_ge ));


     secp256k1_gej_set_infinity(result);

     secp256k1_scratch *scratch = secp256k1_scratch_space_create(ctx, 450000 + 256 * (2 * 1024 + 2));


     int i;
     for (i = 0; i<size ; i++)
        {
    	    secp256k1_sha256 hasher;
    	    unsigned char output_hash[32];
    	    unsigned char message_char[32];
    	    unsigned char tmp[64];

    	    secp256k1_gej_set_ge(points+i, pubkey+i);
    	    secp256k1_gej_set_ge(points+size + i, A+i);

    	    memcpy(gepoints+i, pubkey+i, sizeof(secp256k1_ge));
    	    memcpy(gepoints+size + i, A+i, sizeof(secp256k1_ge));

    	    int overflow = 0;


    	    {  /* d_i = H(A_i) */
    	    secp256k1_ge_to_char(tmp, A+i);
     	    secp256k1_sha256_initialize(&hasher);
    	    secp256k1_sha256_write(&hasher, tmp, sizeof(tmp));
    	    secp256k1_sha256_finalize(&hasher,output_hash);
    	    secp256k1_scalar_set_b32(index + size + i, output_hash, &overflow);

    	    secp256k1_scalar_negate(index + size + i, index+ size +i);

    	    VERIFY_CHECK(overflow == 0);
    	    }

    	    {    /* e_i = H(X_i, m_i) */
    	    secp256k1_ge_to_char(tmp, pubkey+i);
    	    secp256k1_scalar_get_b32(message_char, message+i);
    	    secp256k1_sha256_initialize(&hasher);
    	    secp256k1_sha256_write(&hasher, tmp, sizeof(tmp));
    	    secp256k1_sha256_write(&hasher, message_char, sizeof(message_char));
    	    secp256k1_sha256_finalize(&hasher,output_hash);
    	    secp256k1_scalar_set_b32(index  + i, output_hash, &overflow);
    	    VERIFY_CHECK(overflow == 0);
    	    }
        }




     {       /*compute ecumulate*/

       if (sumZ == NULL || size == 0) {
           return 0;
       }
       int straussFunction = 0;

       int max_points = secp256k1_pippenger_max_points(scratch);
       if (max_points == 0) {
           return 0;
       } else if (max_points > ECMULT_MAX_POINTS_PER_BATCH) {
           max_points = ECMULT_MAX_POINTS_PER_BATCH;
       }
       int  n_batches = (totalSize+max_points-1)/max_points;
       int  n_batch_points = (totalSize+n_batches-1)/n_batches;


       if (n_batch_points >= ECMULT_PIPPENGER_THRESHOLD) {
    	   straussFunction = 0;
       } else {
    	   straussFunction = 1;
           max_points = secp256k1_strauss_max_points(scratch);
           if (max_points == 0) {
               return 0;
           }
           n_batches = (totalSize+max_points-1)/max_points;
           n_batch_points = (totalSize+n_batches-1)/n_batches;
       }




      if (straussFunction == 1)
      {
          for(i = 0; i < n_batches; i++) {
              int nbp = totalSize < n_batch_points ? totalSize : n_batch_points;
              int offset = n_batch_points*i;
              secp256k1_gej tmp;
              if (!secp256k1_ecmult_strauss_batch_agg(ctxecmult, scratch, &tmp, nbp , points+offset, index+offset, i == 0 ? sumZ : NULL  )) {
                  return 0;
              }
              secp256k1_gej_add_var(result, result, &tmp, NULL);
              totalSize -= nbp;
          }
      }else
      {
          for(i = 0; i < n_batches; i++) {
              int nbp = 0;

              if (totalSize < n_batch_points)
              {
            	  nbp = totalSize;
              }else
              {
            	  nbp = n_batch_points;
              }


              int offset = n_batch_points*i;

              secp256k1_gej tmp;
               secp256k1_ecmult_pippenger_batch_agg(ctxecmult, scratch,  &tmp, nbp , gepoints+offset, index+offset, i == 0 ? sumZ : NULL  );

              secp256k1_gej_add_var(result, result, &tmp, NULL);
              totalSize -= nbp;
          }
      }

       /*printf( "%d, %d, %d",max_points, n_batches, n_batch_points );*/

       /*secp256k1_ecmult_strauss_wnaf(ctxecmult, &state, result, totalSize , points, index, sumZ);
       secp256k1_scratch_deallocate_frame(scratch);  */

     }

       int re = secp256k1_gej_is_infinity(result);

       free(result);
       free(index);
       free(points);
       free(gepoints);

       secp256k1_scratch_destroy(scratch);

      return (re);

}





 int secp256k1_ecmult_pippenger_batch_agg(const secp256k1_ecmult_context *ctx , secp256k1_scratch *scratch,  secp256k1_gej *r, const int n_points, const secp256k1_ge  *oldpoints, const secp256k1_scalar *oldscalars, const secp256k1_scalar *inp_g_sc)
 {


	    /* Use 2(n+1) with the endomorphism, n+1 without, when calculating batch
	     * sizes. The reason for +1 is that we add the G scalar to the list of
	     * other scalars. */

	#ifdef USE_ENDOMORPHISM
	    size_t entries = 2*n_points + 2;
	    /*printf( "entries =  %d  " , entries );*/
	#else
	    size_t entries = n_points + 1;
	#endif
	    secp256k1_ge *points;
	    secp256k1_scalar *scalars;
	    secp256k1_gej *buckets;
	    struct secp256k1_pippenger_state *state_space;
	    size_t idx = 0;
	    size_t point_idx = 0;
	    int i, j;
	    int bucket_window;

	    (void)ctx;
	    secp256k1_gej_set_infinity(r);
	    if (inp_g_sc == NULL && n_points == 0) {
	        return 1;
	    }

	    bucket_window = secp256k1_pippenger_bucket_window(n_points);
	    if (!secp256k1_scratch_allocate_frame(scratch, secp256k1_pippenger_scratch_size(n_points, bucket_window), PIPPENGER_SCRATCH_OBJECTS)) {
	        return 0;
	    }
	    points = (secp256k1_ge *) secp256k1_scratch_alloc(scratch, entries * sizeof(*points));
	    scalars = (secp256k1_scalar *) secp256k1_scratch_alloc(scratch, entries * sizeof(*scalars));
	    state_space = (struct secp256k1_pippenger_state *) secp256k1_scratch_alloc(scratch, sizeof(*state_space));
	    state_space->ps = (struct secp256k1_pippenger_point_state *) secp256k1_scratch_alloc(scratch, entries * sizeof(*state_space->ps));
	    state_space->wnaf_na = (int *) secp256k1_scratch_alloc(scratch, entries*(WNAF_SIZE(bucket_window+1)) * sizeof(int));
	    buckets = (secp256k1_gej *) secp256k1_scratch_alloc(scratch, (1<<bucket_window) * sizeof(*buckets));

	    if (inp_g_sc != NULL) {
	        scalars[0] = *inp_g_sc;
	        points[0] = secp256k1_ge_const_g;
	        idx++;
	#ifdef USE_ENDOMORPHISM
	        secp256k1_ecmult_endo_split(&scalars[0], &scalars[1], &points[0], &points[1]);
	        idx++;
	#endif
	    }

	    while (point_idx < n_points) {
	        /* use memcpy to replace
	         * 	         *   if (!cb(&scalars[idx], &points[idx], point_idx + cb_offset, cbdata)) {
	            secp256k1_scratch_deallocate_frame(scratch);
	            return 0;
	        }*/

	    	memcpy(scalars+idx, oldscalars+point_idx, sizeof(secp256k1_scalar));
	    	memcpy(points+idx, oldpoints+point_idx, sizeof(secp256k1_ge));

	        idx++;
	#ifdef USE_ENDOMORPHISM
	        secp256k1_ecmult_endo_split(&scalars[idx - 1], &scalars[idx], &points[idx - 1], &points[idx]);
	        idx++;
	#endif
	        point_idx++;
	    }

	    secp256k1_ecmult_pippenger_wnaf(buckets, bucket_window, state_space, r, scalars, points, idx);

	    /* Clear data */
	    for(i = 0; (size_t)i < idx; i++) {
	        secp256k1_scalar_clear(&scalars[i]);
	        state_space->ps[i].skew_na = 0;
	        for(j = 0; j < WNAF_SIZE(bucket_window+1); j++) {
	            state_space->wnaf_na[i * WNAF_SIZE(bucket_window+1) + j] = 0;
	        }
	    }
	    for(i = 0; i < 1<<bucket_window; i++) {
	        secp256k1_gej_clear(&buckets[i]);
	    }
	    secp256k1_scratch_deallocate_frame(scratch);
	    return 1;

 }




 int secp256k1_ecmult_strauss_batch_agg(const secp256k1_ecmult_context *ctxecmult, secp256k1_scratch *scratch,
		  secp256k1_gej *result, int num, const secp256k1_gej *points, const secp256k1_scalar *index, const secp256k1_scalar *sumZ)

 {

	    secp256k1_gej_set_infinity(result);
	    if (sumZ == NULL && num == 0) {
	        return 1;
	    }

     struct secp256k1_strauss_state state;

     if (!secp256k1_scratch_allocate_frame(scratch, secp256k1_strauss_scratch_size(num), STRAUSS_SCRATCH_OBJECTS)) {
         return 0;
     }

     state.prej = (secp256k1_gej*)secp256k1_scratch_alloc(scratch, num * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(secp256k1_gej));
     state.zr = (secp256k1_fe*)secp256k1_scratch_alloc(scratch, num * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(secp256k1_fe));
     #ifdef USE_ENDOMORPHISM
     state.pre_a = (secp256k1_ge*)secp256k1_scratch_alloc(scratch, num * 2 * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(secp256k1_ge));
     state.pre_a_lam = state.pre_a + num * ECMULT_TABLE_SIZE(WINDOW_A);
     #else
     state.pre_a = (secp256k1_ge*)secp256k1_scratch_alloc(scratch, num * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(secp256k1_ge));
     #endif
     state.ps = (struct secp256k1_strauss_point_state*)secp256k1_scratch_alloc(scratch, num * sizeof(struct secp256k1_strauss_point_state));

     secp256k1_ecmult_strauss_wnaf(ctxecmult, &state, result, num , points, index, sumZ);
     secp256k1_scratch_deallocate_frame(scratch);

     return 1;
 }



/* check if every item of set is in the right order and distinct */
int checkTSet(  const secp256k1_ge *pubkey, const secp256k1_scalar *message,  const int size )
{
	int i;
	for (i = 0; i< (size-1) ; i++)
	{
		if (secp256k1_ge_compare2( (pubkey+i), message+i,   (pubkey+i+1), message+i+1) >=0 )
		{
			return 0;
		}
	}
   return 1;

}

int checkASet(  const secp256k1_ge *A,  const int size )
{
	int i;
		for (i = 0; i< (size-1) ; i++)
		{
			if (secp256k1_ge_compare(A+i,    A+i+1 ) >=0 )
			{
				return 0;
			}
		}
		return 1;
}




  void printGe(const secp256k1_ge *r,  int size)
{
	 printf("size = %d \n",  size);
	int i = 0;
  for ( i = 0;i< size; i++)
  {
	   unsigned char tmp[64];

      secp256k1_ge_to_char(tmp,  r+i);
      printChar(tmp, 64);
  }


  printf("end \n" );
}



  void printChar(const unsigned char *r,int size)
{
	 printf("size = %d \n",  size);
	int i = 0;
   for ( i = 0;i< size; i++)
	   printf(" %d",r[i]);


   printf(" \n" );
}


 void printScalar(const secp256k1_scalar *r,int size)
{
	 printf("size = %d \n",  size);
	int i = 0;
   for ( i = 0;i< size; i++)
   { unsigned char message_char[32];

   secp256k1_scalar_get_b32(message_char, r+i);

   printChar(message_char, 32);

   }


   printf(" \n" );
}





 void printGej(const secp256k1_gej *r,  int size)
{
	 printf("size = %d \n",  size);
	int i = 0;

	secp256k1_ge  ge;
   for ( i = 0;i< size; i++)
   {
	   unsigned char tmp[64];

	   secp256k1_ge_set_gej(&ge,r+i);

       secp256k1_ge_to_char(tmp,  &ge);
       printChar(tmp, 64);
   }


   printf("end \n" );
}

 /*tree functions */

 geTreeNode * rotateright(geTreeNode *x)
 {
 	geTreeNode *y;
     y=x->Left;
     x->Left=y->Right;
     y->Right=x;
     x->Height=height(x);
     y->Height=height(y);
     return(y);
 }

 geTreeNode * rotateleft(geTreeNode *x)
 {
 	geTreeNode *y;
     y=x->Right;
     x->Right=y->Left;
     y->Left=x;
     x->Height = height(x);
     y->Height = height(y);

     return(y);
 }

 geTreeNode * RR(geTreeNode *T)
 {
     T=rotateleft(T);
     return(T);
 }

 geTreeNode * LL(geTreeNode *T)
 {
     T=rotateright(T);
     return(T);
 }

 geTreeNode * LR(geTreeNode *T)
 {
     T->Left=rotateleft(T->Left);
     T=rotateright(T);

     return(T);
 }

 geTreeNode * RL(geTreeNode *T)
 {
     T->Right=rotateright(T->Right);
     T=rotateleft(T);
     return(T);
 }


 int BF(geTreeNode *T)
 {
     int lh,rh;
     if(T==NULL)
         return(0);

     if(T->Left== NULL)
         lh=0;
     else
         lh=1+ T->Left->Height;

     if(T->Right==NULL)
         rh=0;
     else
         rh=1+ T->Right->Height;

     return(lh-rh);
 }

 int height(geTreeNode *T)
 {
     int lh,rh;
     if(T==NULL)
         return(0);

     if(T->Left==NULL)
         lh=0;
     else
         lh=1+T->Left->Height;

     if(T->Right==NULL)
         rh=0;
     else
         rh=1+T->Right->Height;

     if(lh>rh)
         return(lh);

     return(rh);
 }


 /* functions for tHatTree */


   tHatTreeNode * tHatrotateright(tHatTreeNode *x)
 {
 	tHatTreeNode *y;
     y=x->Left;
     x->Left=y->Right;
     y->Right=x;
     x->Height=tHatheight(x);
     y->Height=tHatheight(y);
     return(y);
 }

 tHatTreeNode * tHatrotateleft(tHatTreeNode *x)
 {
 	tHatTreeNode *y;
     y=x->Right;
     x->Right=y->Left;
     y->Left=x;
     x->Height = tHatheight(x);
     y->Height = tHatheight(y);

     return(y);
 }

 tHatTreeNode * tHatRR(tHatTreeNode *T)
 {
     T=tHatrotateleft(T);
     return(T);
 }

 tHatTreeNode * tHatLL(tHatTreeNode *T)
 {
     T=tHatrotateright(T);
     return(T);
 }

 tHatTreeNode * tHatLR(tHatTreeNode *T)
 {
     T->Left=tHatrotateleft(T->Left);
     T=tHatrotateright(T);

     return(T);
 }

 tHatTreeNode * tHatRL(tHatTreeNode *T)
 {
     T->Right=tHatrotateright(T->Right);
     T=tHatrotateleft(T);
     return(T);
 }


 int tHatBF(tHatTreeNode *T)
 {
     int lh,rh;
     if(T==NULL)
         return(0);

     if(T->Left==NULL)
         lh=0;
     else
         lh= 1 + (T->Left)-> Height;

     if(T->Right==NULL)
         rh=0;
     else
         rh=1+ T->Right->Height;

     return(lh-rh);
 }

 int tHatheight(tHatTreeNode *T)
 {
     int lh,rh;
     if(T==NULL)
         return(0);

     if(T->Left==NULL)
         lh=0;
     else
         lh=1+T->Left->Height;

     if(T->Right==NULL)
         rh=0;
     else
         rh=1+T->Right->Height;

     if(lh>rh)
         return(lh);

     return(rh);
 }



 /*static functions */






 static int geTree_Find(const secp256k1_ge *X, const  geTreeNode *T)
 {
 	 if( T == NULL ){
 		     return 0;
 		}
 	 else if(secp256k1_ge_compare(X,  T->Data) < 0   )       /*X < T->Data */
 	   {
 		 return geTree_Find( X,  T->Left);
 	   }
 	 else if(secp256k1_ge_compare(X,  T->Data) > 0)
 	 {
 		 return geTree_Find( X,  T->Right);
 	 }

	/* printGe( X, 1);
 	 printGe(T->Data, 1);
 	 int test = secp256k1_ge_compare( X,   T->Data ) ;*/

 	 return 1;
 }

void  releasegeTreeNode( geTreeNode *T)
{
    if (T !=  NULL)
    {
    	releasegeTreeNode(T->Left);
    	releasegeTreeNode(T->Right);

    	free(T);
    }

}

void  releasetHatTreeNode( tHatTreeNode *T)
{
    if (T !=  NULL)
    {
    	releasetHatTreeNode(T->Left);
    	releasetHatTreeNode(T->Right);

    	free(T);
    }

}


/*   */
 static geTreeNode *geTree_Insertion(const secp256k1_ge *X, geTreeNode *T)
 {
 	  if( T == NULL ){
 	        T = (geTreeNode*) malloc(sizeof(geTreeNode));
 	       /* T->Data = (secp256k1_ge*) malloc(sizeof(secp256k1_ge));*/
 	       T->Data = X;
 	        /*   memcpy(T->Data, X , sizeof(secp256k1_ge));*/
 	       /*T->Height = 0;*/
 	        T->Left   = NULL;
 	       T->Right = NULL;
 	    }
 	    else if(secp256k1_ge_compare(X,  T->Data) < 0   )       /*X < T->Data */
 	    {
 	        T->Left = geTree_Insertion(X, T->Left);    /*递归比较并插入，将插入后的左子树更新给T-Left*/
 	        if(BF(T) == 2)
 	            {if(secp256k1_ge_compare(X,  T->Left->Data) < 0 )
 	                 T =  LL(T);  /*左单旋*/
 	            else
 	            	T =  LR(T); /*左-右双旋*/}
 	    }
 	    else if(secp256k1_ge_compare(X,  T->Data) > 0){
 	        T->Right = geTree_Insertion(X, T->Right);  /*递归比较并插入，将插入后的右子树更新给T->Right*/
 	        if(BF(T) == -2)
 	            {if(secp256k1_ge_compare(X,  T->Right->Data) > 0)
 	                T = RR(T);  /*右单旋*/
 	            else
 	                T = RL(T); /*右-左双旋*/}
 	    }

 	    /*else X == T->Data, 无需插入*/
 	    T->Height = height(T);/*树高等于子树高度加一*/

 	    return T;   /*返回插入并调整后的树*/
 }



 static void geTree_inorder(geTreeNode *T, secp256k1_ge *out , int * post)
 {
     if(T != NULL)
     {
     	geTree_inorder(T->Left, out , post);
     	 memcpy(out+(*post), T->Data, sizeof(secp256k1_ge));
     	 (*post)++;
     	 geTree_inorder(T->Right, out , post);
     }
 }

 static tHatTreeNode *tHatTree_Insertion(const secp256k1_ge *X, const  secp256k1_scalar *m, tHatTreeNode *T)
 {
 	  if( T == NULL ){
 	        T = (tHatTreeNode*)malloc(sizeof(tHatTreeNode));
 	        T->Data = X;
 	        T->message = m;

 	       /*  T->Data = (secp256k1_ge*)malloc(sizeof(secp256k1_ge));
 	      T->message = (secp256k1_scalar*)malloc(sizeof(secp256k1_scalar));

 	       memcpy(T->Data, X , sizeof(secp256k1_ge));
 	      memcpy(T->message, m , sizeof(secp256k1_scalar));*/

 	     /*T->Height = 0;*/
 	        T->Left   = NULL;
 	       T->Right = NULL;
 	    }
 	    else if(secp256k1_ge_compare2( X, m,   T->Data , T->message) < 0   )       /*X < T->Data */
 	    {
 	        T->Left = tHatTree_Insertion(X, m, T->Left);    /*递归比较并插入，将插入后的左子树更新给T-Left*/
 	        if(tHatBF(T) == 2)
 	            {if(secp256k1_ge_compare2( X,  m,  T->Left->Data , T->Left->message) < 0 )
 	                 T =  tHatLL(T);  /*左单旋*/
 	            else
 	            	T =  tHatLR(T); /*左-右双旋*/}
 	    }
 	    else if(secp256k1_ge_compare2(X, m, T->Data, T->message) > 0){
 	        T->Right = tHatTree_Insertion(X, m, T->Right);  /*递归比较并插入，将插入后的右子树更新给T->Right*/
 	        if(tHatBF(T) == -2)
 	            {if(secp256k1_ge_compare2( X,  m,  T->Right->Data , T->Right->message ) > 0)
 	                T = tHatRR(T);  /*右单旋*/
 	            else
 	                T = tHatRL(T); /*右-左双旋*/}
 	    }

 	    /*else X == T->Data, 无需插入*/
 	    T->Height = tHatheight(T);/*树高等于子树高度加一*/

 	    return T;   /*返回插入并调整后的树*/

 }

 static void tHatTree_inorder(tHatTreeNode *T, secp256k1_ge *out ,secp256k1_scalar *m, int *post)
 {
     if(T != NULL)
     {
     	tHatTree_inorder(T->Left, out ,m, post);
     	  memcpy ( out  + ( *post ) , T->Data,  sizeof(secp256k1_ge)  );      /*(out  + ( *post )) = T->Data;  (m  + ( *post )) = T->message;*/
     	  memcpy ( m + ( *post ) , T->message,  sizeof(secp256k1_scalar)  );

     	(*post) ++;
     	tHatTree_inorder(T->Right, out ,m, post);
     }
 }
 static   int tHatTree_Find(const secp256k1_ge  *X,    const secp256k1_scalar  *m,   const  tHatTreeNode *T)
 {
 	 if( T == NULL ){
 		     return 0;
 		}
 	 else if(secp256k1_ge_compare2( X,  m,  T->Data , T->message) < 0   )       /*X < T->Data */
 	   {
 		 return tHatTree_Find(  X,   m,  T->Left);
 	   }
 	 else if(secp256k1_ge_compare2( X,  m,  T->Data , T->message) > 0)
 	 {
 		 return tHatTree_Find(  X,   m,   T->Right);
 	 }

 	 printGe( X, 1);
 	 printGe(T->Data, 1);
 	 int test = secp256k1_ge_compare2( X,  m,  T->Data , T->message) ;

 	 return 1;
 }


   int secp256k1_ge_compare(const secp256k1_ge  *ge1, const secp256k1_ge  *ge2) {

     if ( ge1->infinity == 1 &&  ge2->infinity == 1 )
     	return 0;
     if ( ge1->infinity == 1 &&  ge2->infinity == 0)
         return -1;
     if ( ge1->infinity == 0 &&  ge2->infinity == 1)
         return 1;

     int r = secp256k1_fe_cmp_var(&(ge1->x), &(ge2->x));

     if ( r != 0 )
     {
     	return r;
     }else
     {
        return secp256k1_fe_cmp_var(&(ge1->y), &(ge2->y));
     }
 }


   int secp256k1_ge_compare2(const secp256k1_ge *ge1, const secp256k1_scalar *m1,
		   const secp256k1_ge *ge2, const secp256k1_scalar *m2) {


     int r = secp256k1_ge_compare( ge1,  ge2);

     if ( r != 0 )
     {
     	return r;
     }else
     {
     return secp256k1_scalar_cmp(m1, m2);
     }
 }



   int secp256k1_scalar_cmp(  const secp256k1_scalar *m1,    const secp256k1_scalar *m2)
   {
 	  unsigned char message_char1[32];
 	  unsigned char message_char2[32];

 	 secp256k1_scalar_get_b32(message_char1, m1);
 	 secp256k1_scalar_get_b32(message_char2, m2);



 	 return (stringCompare(message_char1, message_char1, 32));



   }






   int stringCompare(const unsigned char *ch1,  const unsigned char *ch2,  const int size)
 {

 	int i = 0;
    for ( i = 0;i< size; i++)
    {
    	if(*(ch1+i) != *(ch2+i))
    	{
    		return ( (*(ch1+i) > *(ch2+i)) ? 1:-1    );
    	}

    }

    return 0;

 }










































#endif /* GAMMAAGGREGATE_IMPL_H_ */

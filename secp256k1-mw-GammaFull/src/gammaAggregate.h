
#ifndef GAMMAAGGREGATE_H_
#define GAMMAAGGREGATE_H_



#include "group.h"
#include "ecmult.h"
#include "scalar.h"



static int secp256k1_gamma_sig_verify(const secp256k1_ecmult_context *ctx, const secp256k1_scalar* r,
		const secp256k1_scalar* s, const secp256k1_ge *pubkey, const secp256k1_scalar *message);



static int secp256k1_gamma_sig_sign(const secp256k1_ecmult_gen_context *ctx, secp256k1_scalar* r,
		secp256k1_scalar* s, const secp256k1_scalar *seckey, const secp256k1_scalar *message, const secp256k1_scalar *nonce, int *recid);

static int secp256k1_gamma_sig_verify_forAGG(const secp256k1_ecmult_context *ctx, const secp256k1_scalar *sigd, const secp256k1_scalar *sigz,
		const secp256k1_ge *pubkey, const secp256k1_scalar *message,  secp256k1_ge *Ae);



static int secp256k1_gamma_Agg(const secp256k1_ecmult_context *ctx,
		const secp256k1_ge *pubkey, const secp256k1_scalar *message,  const secp256k1_scalar *d,
		const secp256k1_scalar *z, const int size,
		 secp256k1_ge *outpubkey,  secp256k1_scalar *outmessage, secp256k1_ge *A, int *outsize, secp256k1_scalar *sumZ);

static int secp256k1_gamma_Agg_verify(const secp256k1_context *ctx,  const secp256k1_ecmult_context *ctxecmult,  const secp256k1_ge *pubkey, const secp256k1_scalar *message,
		const secp256k1_ge *A, const int size,  const secp256k1_scalar *sumZ);












/*tree functions */

typedef struct geTreeNode {
	secp256k1_ge *Data;

	struct geTreeNode *Left;
	struct geTreeNode *Right;
    int Height;
}geTreeNode;




static geTreeNode *geTree_Insertion(const secp256k1_ge *X, geTreeNode *T);
static void geTree_inorder(geTreeNode *T, secp256k1_ge *outpubkey, int *post);
static int geTree_Find(const  secp256k1_ge *X,const geTreeNode *T);


typedef struct tHatTreeNode {
	secp256k1_ge *Data;
	secp256k1_scalar *message;

	struct tHatTreeNode *Left;
	struct tHatTreeNode *Right;
    int Height;
}tHatTreeNode;


static tHatTreeNode *tHatTree_Insertion(const secp256k1_ge *X,const  secp256k1_scalar *m, tHatTreeNode *T);
static void tHatTree_inorder(tHatTreeNode *T, secp256k1_ge *out ,secp256k1_scalar *m, int *post);
static int tHatTree_Find(const secp256k1_ge  *X,const  secp256k1_scalar  *m, const tHatTreeNode *T);
























#endif /* GAMMAAGGREGATE_H_ */



















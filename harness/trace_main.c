#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sig.h>
#include "api.h"
#include <verification.h>
int protocols_verify_trace(signature_t *sig, const public_key_t *pk, const unsigned char *m, size_t l);
static int hx(const char*h,unsigned char*o,size_t n){for(size_t i=0;i<n;i++){unsigned x;if(sscanf(h+2*i,"%2x",&x)!=1)return -1;o[i]=x;}return 0;}
int main(int argc,char**argv){
  // argv: pk_hex msg_hex sig_hex
  if(argc<4){fprintf(stderr,"usage: trace pk msg sig\n");return 2;}
  size_t pkl=strlen(argv[1])/2, ml=strlen(argv[2])/2, sl=strlen(argv[3])/2;
  unsigned char *pkb=malloc(pkl),*mb=malloc(ml?ml:1),*sb=malloc(sl);
  hx(argv[1],pkb,pkl);hx(argv[2],mb,ml);hx(argv[3],sb,sl);
  public_key_t pk; signature_t sig;
  extern int SQISIGN_NAMESPACE(public_key_from_bytes)(public_key_t*,const unsigned char*);
  extern void SQISIGN_NAMESPACE(signature_from_bytes)(signature_t*,const unsigned char*);
  public_key_from_bytes(&pk,pkb);
  signature_from_bytes(&sig,sb);
  int r=protocols_verify_trace(&sig,&pk,mb,ml);
  printf("TRACE result %d\n",r);
  return 0;
}

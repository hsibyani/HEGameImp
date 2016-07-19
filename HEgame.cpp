#include "FHE.h"
#include "EncryptedArray.h"
#include <NTL/lzz_pXFactoring.h>
#include <fstream>
#include <sstream>
#include <sys/time.h>

int positionize_me(vector<long> &v, long &nslots)
{
    int x = 0;
    int y = 0;
    for(int i=0; i<nslots; i++){
        if(v[i]==1){
            x=i%3;
            y=i/3;
            break;
        }
    }
    
    cout << "Your Position is: (" << x << "," << y << ")." << endl;
    return 0;
}

int move_up(vector<long> &v, long &nslots)
{
    for(int i=0; i<nslots; i++){
        if(v[i]==1){
            v[i]=0;
            v[i+3]=1;
            break;
        }
    }
    return 0;
}

int move_down(vector<long> &v, long &nslots)
{
    for(int i=0; i<nslots; i++){
        if(v[i]==1){
            v[i]=0;
            v[i-3]=1;
            break;
        }
    }
    return 0;
}

int move_right(vector<long> &v, long &nslots)
{
    for(int i=0; i<nslots; i++){
        if(v[i]==1){
            v[i]=0;
            v[i+1]=1;
        }
    }
    return 0;
}

int move_left(vector<long> &v, long &nslots)
{
    for(int i=0; i<nslots; i++){
        if(v[i]==1){
            v[i]=0;
            v[i-1]=1;
        }
    }
    return 0;
}

int prep(vector<long> &v, Ctxt &ct, const FHEPubKey &publickey, EncryptedArray &ea)
{
    ea.encrypt(ct, publickey, v);
    return 0;
}

Ctxt send_and_recieve(Ctxt &ct_position, Ctxt &ct_floor)
{
    Ctxt ct_result = ct_floor;
    ct_result *= ct_position;
    return ct_result;
}

vector<long> decipher(Ctxt &ct_result, FHESecKey &secretkey, EncryptedArray &ea)
{
    vector<long> res;
    ea.decrypt(ct_result, secretkey, res);
    return res;
}

int winning_check(vector<long> &v, long &nslots)
{
    for(int i=0; i<nslots; i++){
        if(v[i]==1){
            cout << "You have found the gem in position: (" << i%3 << "," << i/3 << ")." << endl;
            break;
        }
    }
    return 0;
}

int main(int argc, char **argv)
{
    /* On our trusted system we generate a new key
     * (or read one in) and encrypt the secret data set.
     */

    long m=0, p=2, r=1; // Native plaintext space
                        // Computations will be 'modulo p'
    long L=8;          // Levels
    long c=3;           // Columns in key switching matrix
    long w=64;          // Hamming weight of secret key
    long d=0;
    long security = 128;
    ZZX G;
    m = FindM(security,L,c,p, d, 0, 0);

    FHEcontext context(m, p, r);
    // initialize context
    buildModChain(context, L, c);
    // modify the context, adding primes to the modulus chain
    FHESecKey secretKey(context);
    // construct a secret key structure
    const FHEPubKey& publicKey = secretKey;
    // an "upcast": FHESecKey is a subclass of FHEPubKey

    //if(0 == d)
    G = context.alMod.getFactorsOverZZ()[0];

   secretKey.GenSecKey(w);
   // actually generate a secret key with Hamming weight w

   addSome1DMatrices(secretKey);
   cout << "Generated key" << endl;

   EncryptedArray ea(context, G);
   // constuct an Encrypted array object ea that is
   // associated with the given context and the polynomial G

   long nslots = ea.size();
   cout << "nslots: " << nslots << endl;

   vector<long> vMult3;
   Ctxt ctMult3(publicKey);
   for(int i = 0 ; i < nslots; i++) {
        vMult3.push_back(0);
   }
   int fruit_slot=8;
   vMult3[fruit_slot]=1;
   ea.encrypt(ctMult3, publicKey, vMult3);

   vector<long> v3;
   Ctxt ct3(publicKey);
   for(int i=0;i<nslots; i++){
	   v3.push_back(0);
   }
   v3[5]=1;
//   ea.encrypt(ct3, publicKey, v3);

   // On the public (untrusted) system we
   // can now perform our computation
   
   //Calculate 3x+7
   //Ctxt ctEq = ct3;
   //ctEq += ctMult3;

 //   vector<long> res;

    cout << "All computations are modulo " << std::pow(p,r) << "." << endl;
    

    vector<long> res;
    Ctxt ctEq=ct3;
    positionize_me(v3, nslots);
    prep(v3, ct3, publicKey, ea);
    ctEq=send_and_recieve(ctMult3, ct3);
    res=decipher(ctEq, secretKey, ea);
    winning_check(res, nslots);

    move_up(v3, nslots);
    positionize_me(v3, nslots);
    prep(v3, ct3, publicKey, ea);
    ctEq=send_and_recieve(ctMult3, ct3);
    res=decipher(ctEq, secretKey, ea);
    winning_check(res, nslots);

    return 0;
}


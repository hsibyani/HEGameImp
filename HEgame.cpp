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
    for(int i=0; i<nslots; i++)
    {
        if(v[i]==1)
        {
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
    for(int i=0; i<nslots; i++)
    {
        if(v[i]==1)
        {
            v[i]=0;
            v[i+3]=1;
            break;
        }
    }
    return 0;
}

int move_down(vector<long> &v, long &nslots)
{
    for(int i=0; i<nslots; i++)
    {
        if(v[i]==1)
        {
            v[i]=0;
            v[i-3]=1;
            break;
        }
    }
    return 0;
}

int move_right(vector<long> &v, long &nslots)
{
    for(int i=0; i<nslots; i++)
    {
        if(v[i]==1)
        {
            v[i]=0;
            v[i+1]=1;
            break;
        }
    }
    return 0;
}

int move_left(vector<long> &v, long &nslots)
{
    for(int i=0; i<nslots; i++)
    {
        if(v[i]==1)
        {
            v[i]=0;
            v[i-1]=1;
            break;
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

int decipher(Ctxt &ct_result, FHESecKey &secretkey, EncryptedArray &ea, vector<long> &res)
{
    ea.decrypt(ct_result, secretkey, res);
    return 0;
}

int winning_check(vector<long> &v, long &nslots)
{
    for(int i=0; i<nslots; i++)
    {
        if(v[i]==1)
        {
            cout << "You have found the gem in position: (" << i%3 << "," << i/3 << ")." << endl;
            break;
        }
    }
    return 0;
}

int initialize_game_board(vector<long> &game_board, long &nslots, int &size, int &fruit_x_position, int &fruit_y_position)
{
    for(int i=0; i<nslots; i++)
    {
        game_board.push_back(0);
    }
    game_board[fruit_y_position*size+fruit_x_position]=1;
    return 0;
}

int initialize_player_position(vector<long> &player_position, long &nslots, int &size, int &player_x_position, int &player_y_position)
{
    for(int i=0; i<nslots; i++)
    {
        player_position.push_back(0);
    }
    player_position[player_y_position*size+player_x_position]=1;
    return 0;
}

int move_wrapper(vector<long> &player_position, long &nslots, Ctxt &ctEq, const FHEPubKey &publicKey, EncryptedArray &ea, Ctxt &encrypted_game_board, FHESecKey &secretkey, vector<long> &res)
{
    prep(player_position, ctEq, publicKey, ea);
    ctEq=send_and_recieve(encrypted_game_board, ctEq);
    decipher(ctEq, secretkey, ea, res);
    winning_check(res, nslots);
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

    int size = 3;
    int fruit_x_position = 2;
    int fruit_y_position = 2;

    vector<long> game_board;
    initialize_game_board(game_board, nslots, size, fruit_x_position, fruit_y_position);

    Ctxt encrypted_game_board(publicKey);
    ea.encrypt(encrypted_game_board, publicKey, game_board);


    vector<long> player_position;

    int player_x_position = 2;
    int player_y_position = 1;

    initialize_player_position(player_position, nslots, size, player_x_position, player_y_position);

    cout << "All computations are modulo " << std::pow(p,r) << "." << endl;

    vector<long> res;

    Ctxt ctEq(publicKey);

    while(true)
    {
        cout << "Write something" << endl;
        char tmp;
        cin >> tmp;
        cout << "You have entered: " << tmp  << endl;

        if(tmp=='u')
        {
            move_up(player_position, nslots);
            positionize_me(player_position, nslots);
            move_wrapper(player_position, nslots, ctEq, publicKey, ea, encrypted_game_board, secretKey, res);
        }
        if(tmp=='d')
        {
            move_down(player_position, nslots);
            positionize_me(player_position, nslots);
            move_wrapper(player_position, nslots, ctEq, publicKey, ea, encrypted_game_board, secretKey, res);
        }
        if(tmp=='r')
        {
            move_right(player_position, nslots);
            positionize_me(player_position, nslots);
            move_wrapper(player_position, nslots, ctEq, publicKey, ea, encrypted_game_board, secretKey, res);
        }
        if(tmp=='l')
        {
            move_left(player_position, nslots);
            positionize_me(player_position, nslots);
            move_wrapper(player_position, nslots, ctEq, publicKey, ea, encrypted_game_board, secretKey, res);
        }
    }
    return 0;
}

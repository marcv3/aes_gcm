#include "stdafx.h"
#include <stdio.h>

#include <iostream>
using std::cout;
using std::cerr;

#include <string>
using std::string;

#include "cryptopp/hex.h"
using CryptoPP::HexEncoder;
using CryptoPP::HexDecoder;

#include "cryptopp/cryptlib.h"
using CryptoPP::BufferedTransformation;
using CryptoPP::AuthenticatedSymmetricCipher;

#include "cryptopp/filters.h"
using CryptoPP::StringSink;
using CryptoPP::StringSource;
using CryptoPP::AuthenticatedEncryptionFilter;
using CryptoPP::AuthenticatedDecryptionFilter;

#include "cryptopp/aes.h"
using CryptoPP::AES;

#include "cryptopp/gcm.h"
using CryptoPP::GCM;
using CryptoPP::GCM_TablesOption;

#include "assert.h"

int main(int argc, char* argv[])
{
    //KEY 0000000000000000000000000000000000000000000000000000000000000000
    //IV  000000000000000000000000
    //HDR 00000000000000000000000000000000
    //PTX 00000000000000000000000000000000
    //CTX cea7403d4d606b6e074ec5d3baf39d18
    //TAG ae9b1771dba9cf62b39be017940330b4

    // Test Vector 003
    byte key[32];
    memset( key, 0, sizeof(key) );

    byte test_key[4];
    memset( test_key, 0xf0, sizeof(test_key) );

    byte iv[12];
    memset( iv, 0, sizeof(iv) );

    string adata( 16, (char)0x00 );
    string pdata( 16, (char)0x00 );

    const int TAG_SIZE = 16;

    // Encrypted, with Tag
    string cipher, encoded;

    // Recovered
    string radata, rpdata;

    /*********************************\
    \*********************************/

    try
    {
        printf("\n");
        printf("************************************************************\n");
        printf("********************  ENCRYPTION START  ********************\n");
        printf("\n");

        GCM< AES >::Encryption e;
        e.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );
        // Not required for GCM mode (but required for CCM mode)
        // e.SpecifyDataLengths( adata.size(), pdata.size(), 0 );
        
        printf("key:");
        for(int i=0; i<sizeof(key); i++){
            if(i%10 == 0)
                printf("\n");
            printf(" 0x%02x ", (unsigned)key[i]);
        }
        printf("\n");
        printf("\n");

        printf("iv:");
        for(int i=0; i<sizeof(iv); i++){
            if(i%10 == 0)
                printf("\n");
            printf(" 0x%02x ", (unsigned)iv[i]);
        }
        printf("\n");
        printf("\n");

        AuthenticatedEncryptionFilter ef( e,
            new StringSink( cipher ), false, TAG_SIZE
        ); // AuthenticatedEncryptionFilter


        StringSource( cipher, true,
            new HexEncoder( new StringSink( encoded ), true, 16, " " ) );

        printf("encoded:");
        for(int i=0; i<sizeof(encoded); i++){
            if(i%10 == 0)
                printf("\n");
            printf(" 0x%02x ", encoded[i]);
        }
        printf("\n");
        printf("\n");

        //printf("cipher:");
        //for(int i=0; i<sizeof(cipher); i++){
        //    if(i%10 == 0)
        //        printf("\n");
        //    printf(" 0x%02x ", (unsigned)cipher[i]);
        //}
        //printf("\n");
        //printf("\n");


        // AuthenticatedEncryptionFilter::ChannelPut
        //  defines two channels: "" (empty) and "AAD"
        //   channel "" is encrypted and authenticated
        //   channel "AAD" is authenticated
        ef.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() );
        ef.ChannelMessageEnd("AAD");

        //printf("adata: %x\n", adata);

        // Authenticated data *must* be pushed before
        //  Confidential/Authenticated data. Otherwise
        //  we must catch the BadState exception
        ef.ChannelPut( "", (const byte*)pdata.data(), pdata.size() );
        ef.ChannelMessageEnd("");

        //printf("pdata: %x\n", pdata);

        // Pretty print
        StringSource( cipher, true,
            new HexEncoder( new StringSink( encoded ), true, 16, " " ) );

        printf("encoded:");
        for(int i=0; i<sizeof(encoded); i++){
            if(i%10 == 0)
                printf("\n");
            printf(" 0x%02x ", encoded[i]);
        }
        printf("\n");
        printf("\n");
    }
    catch( CryptoPP::BufferedTransformation::NoChannelSupport& e )
    {
        // The tag must go in to the default channel:
        //  "unknown: this object doesn't support multiple channels"
        cerr << "Caught NoChannelSupport..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    /*********************************\
    \*********************************/

    // Attack the first and last byte
    //if( cipher.size() > 1 )
    //{
    //  cipher[ 0 ] |= 0x0F;
    //  cipher[ cipher.size()-1 ] |= 0x0F;
    //}

    /*********************************\
    \*********************************/

    try
    {
        GCM< AES >::Decryption d;
        d.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );

        // Break the cipher text out into it's
        //  components: Encrypted Data and MAC Value
        string enc = cipher.substr( 0, cipher.length()-TAG_SIZE );
        string mac = cipher.substr( cipher.length()-TAG_SIZE );

        // Sanity checks
        assert( cipher.size() == enc.size() + mac.size() );
        assert( enc.size() == pdata.size() );
        assert( TAG_SIZE == mac.size() );

        // Not recovered - sent via clear channel
        radata = adata;     

        // Object will not throw an exception
        //  during decryption\verification _if_
        //  verification fails.
        //AuthenticatedDecryptionFilter df( d, NULL,
        // AuthenticatedDecryptionFilter::MAC_AT_BEGIN );

        AuthenticatedDecryptionFilter df( d, NULL,
            AuthenticatedDecryptionFilter::MAC_AT_BEGIN |
            AuthenticatedDecryptionFilter::THROW_EXCEPTION, TAG_SIZE );

        // The order of the following calls are important
        df.ChannelPut( "", (const byte*)mac.data(), mac.size() );
        df.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() ); 
        df.ChannelPut( "", (const byte*)enc.data(), enc.size() );               

        // If the object throws, it will most likely occur
        //  during ChannelMessageEnd()
        df.ChannelMessageEnd( "AAD" );
        df.ChannelMessageEnd( "" );

        // If the object does not throw, here's the only
        //  opportunity to check the data's integrity
        bool b = false;
        b = df.GetLastResult();
        assert( true == b );

        // Remove data from channel
        string retrieved;
        size_t n = (size_t)-1;

        // Plain text recovered from enc.data()
        df.SetRetrievalChannel( "" );
        n = (size_t)df.MaxRetrievable();
        retrieved.resize( n );

        if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        rpdata = retrieved;
        assert( rpdata == pdata );

        // Hmmm... No way to get the calculated MAC
        //  mac out of the Decryptor/Verifier. At
        //  least it is purported to be good.
        //df.SetRetrievalChannel( "AAD" );
        //n = (size_t)df.MaxRetrievable();
        //retrieved.resize( n );

        //if( n > 0 ) { df.Get( (byte*)retrieved.data(), n ); }
        //assert( retrieved == mac );

        // All is well - work with data
        cout << "Decrypted and Verified data. Ready for use." << endl;
        cout << endl;

        cout << "adata length: " << adata.size() << endl;
        cout << "pdata length: " << pdata.size() << endl;
        cout << endl;

        //cout << "adata: " << adata << endl;
        //cout << "pdata: " << pdata << endl;
        //cout << endl;

        cout << "cipher text: " << endl << " " << encoded << endl;
        cout << endl;

        cout << "recovered adata length: " << radata.size() << endl;
        cout << "recovered pdata length: " << rpdata.size() << endl;
        cout << endl;

        //cout << "recovered adata: " << radata << endl;
        //cout << "recovered pdata: " << rpdata << endl;
        //cout << endl;
    }
    catch( CryptoPP::InvalidArgument& e )
    {
        cerr << "Caught InvalidArgument..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::AuthenticatedSymmetricCipher::BadState& e )
    {
        // Pushing PDATA before ADATA results in:
        //  "GMC/AES: Update was called before State_IVSet"
        cerr << "Caught BadState..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }
    catch( CryptoPP::HashVerificationFilter::HashVerificationFailed& e )
    {
        cerr << "Caught HashVerificationFailed..." << endl;
        cerr << e.what() << endl;
        cerr << endl;
    }

    /*********************************\
    \*********************************/

    return 0;
}

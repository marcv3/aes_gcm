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
    // For test case 14, remove all adata calls
    //
    //KEY 0000000000000000000000000000000000000000000000000000000000000000
    //IV  000000000000000000000000
    //HDR 00000000000000000000000000000000
    //PTX 00000000000000000000000000000000
    //CTX cea7403d4d606b6e074ec5d3baf39d18
    //TAG ae9b1771dba9cf62b39be017940330b4

    byte key_startState[32] = {0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 
                               0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
                               0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c, 
                               0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08};

    byte iv_startState[12] = {0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 
                              0xdb, 0xad, 0xde, 0xca, 0xf8, 0x88};

    string adata = {
                (char)0xfe, (char)0xed, (char)0xfa, (char)0xce, (char)0xde, (char)0xad, 
                (char)0xbe, (char)0xef, (char)0xfe, (char)0xed, (char)0xfa, (char)0xce, 
                (char)0xde, (char)0xad, (char)0xbe, (char)0xef, (char)0xab, (char)0xad, 
                (char)0xda, (char)0xd2
                   };

    string pdata = {
                (char)0xd9, (char)0x31, (char)0x32, (char)0x25, (char)0xf8, (char)0x84, 
                (char)0x06, (char)0xe5, (char)0xa5, (char)0x59, (char)0x09, (char)0xc5, 
                (char)0xaf, (char)0xf5, (char)0x26, (char)0x9a, (char)0x86, (char)0xa7, 
                (char)0xa9, (char)0x53, (char)0x15, (char)0x34, (char)0xf7, (char)0xda, 
                (char)0x2e, (char)0x4c, (char)0x30, (char)0x3d, (char)0x8a, (char)0x31, 
                (char)0x8a, (char)0x72, (char)0x1c, (char)0x3c, (char)0x0c, (char)0x95, 
                (char)0x95, (char)0x68, (char)0x09, (char)0x53, (char)0x2f, (char)0xcf, 
                (char)0x0e, (char)0x24, (char)0x49, (char)0xa6, (char)0xb5, (char)0x25, 
                (char)0xb1, (char)0x6a, (char)0xed, (char)0xf5, (char)0xaa, (char)0x0d, 
                (char)0xe6, (char)0x57, (char)0xba, (char)0x63, (char)0x7b, (char)0x39
                   }; 

/*
test case 16:

K= 
feffe9928665731c6d6a8f9467308308
feffe9928665731c6d6a8f9467308308 
 
IV=
cafebabefacedbaddecaf888

A=
feedfacedeadbeeffeedfacedeadbeef
abaddad2

P=
d9313225f88406e5a55909c5aff5269a
86a7a9531534f7da2e4c303d8a318a72
1c3c0c95956809532fcf0e2449a6b525
b16aedf5aa0de657ba637b39

C=
522dc1f099567d07f47f37a32a84427d
643a8cdcbfe5c0c97598a2bd2555d1aa
8cb08e48590dbb3da7b08b1056828838
c5f61e6393ba7a0abcc9f662

T=
76fc6ece0f4e1768cddf8853bb2d551b
*/



    // Test Vector 003
    byte key[32];
    //memset( key, 0, sizeof(key) );
    memcpy(key, key_startState, sizeof(key));

    byte iv[12];
    //memset( iv, 0, sizeof(iv) );
    memcpy(iv, iv_startState, sizeof(iv));

    //string adata( 16, (char)0x00 );
    //string pdata( 16, (char)0x00 );

    const int TAG_SIZE = 16;

    // Encrypted, with Tag
    string cipher, encoded;

    // Recovered
    string radata, rpdata;

    /*********************************\
    \*********************************/

    try
    {
        GCM< AES >::Encryption e;
        e.SetKeyWithIV( key, sizeof(key), iv, sizeof(iv) );

        AuthenticatedEncryptionFilter ef( e,
            new StringSink( cipher ), false, TAG_SIZE
        ); // AuthenticatedEncryptionFilter

        // AuthenticatedEncryptionFilter::ChannelPut
        //  defines two channels: "" (empty) and "AAD"
        //   channel "" is encrypted and authenticated
        //   channel "AAD" is authenticated
        ef.ChannelPut( "AAD", (const byte*)adata.data(), adata.size() );
        ef.ChannelMessageEnd("AAD");

        // Authenticated data *must* be pushed before
        //  Confidential/Authenticated data. Otherwise
        //  we must catch the BadState exception
        ef.ChannelPut( "", (const byte*)pdata.data(), pdata.size() );
        ef.ChannelMessageEnd("");

        // Pretty print
        StringSource( cipher, true,
            new HexEncoder( new StringSink( encoded ), true, 16, " " ) );
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

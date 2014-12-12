//
//  GMEllipticCurveCrypto+hash.m
//
//  BSD 2-Clause License
//
//  Copyright (c) 2014 Richard Moore.
//
//  All rights reserved.
//
//  Redistribution and use in source and binary forms, with or without modification,
//  are permitted provided that the following conditions are met:
//
//  1. Redistributions of source code must retain the above copyright notice, this
//     list of conditions and the following disclaimer.
//
//  2. Redistributions in binary form must reproduce the above copyright notice,
//     this list of conditions and the following disclaimer in the documentation
//     and/or other materials provided with the distribution.
//
//  THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
//  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
//  WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
//  IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE FOR ANY DIRECT,
//  INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
//  NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR
//  PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
//  WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
//  ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
//  POSSIBILITY OF SUCH DAMAGE.
//


#import "GMEllipticCurveCrypto+hash.h"

#import <CommonCrypto/CommonDigest.h>

NSData *derEncodeSignature(NSData* signature) {
    NSInteger length = [signature length];
    
    if (length % 2) {
        return nil;
    }

    int keySize = length / 2;

    const unsigned char *data = [signature bytes];

    // Construct the DER encoded structure    
    unsigned char bytes[2 * keySize + 8];

    bytes[0] = 0x30;                  // type tag - sequence
    // bytes[1] will be filled in later
    bytes[2] = 0x02;                  // type tag - integer

    int index = 3;

    // Ensure the r value is encoded as positive
    if (data[0] >= 0x80) {
        bytes[index++] = 1 + keySize;       // length
        bytes[index++] = 0x00;
    } else {
        bytes[index++] = keySize;           // length
    }

    // encode the r value
    [signature getBytes:&bytes[index] range:NSMakeRange(0, keySize)];
    index += keySize;

    bytes[index++] = 0x02;            // type tag - integer

    // Ensure the s value is encoded as positive
    if (data[keySize] >= 0x80) {
        bytes[index++] = 1 + keySize; // length
        bytes[index++] = 0x00;
    } else {        
        bytes[index++] = keySize;     // length
    }

    // encode the s value
    [signature getBytes:&bytes[index] range:NSMakeRange(keySize, keySize)];
    index += keySize;

    // now we know the final size
    bytes[1] = index - 2; 
    NSLog(@"Index: %d", index);

    return [NSData dataWithBytes:bytes length:index];
}

@implementation GMEllipticCurveCrypto (hash)

- (BOOL)hashSHA256AndVerifySignature:(NSData *)signature forData:(NSData *)data {
    int bytes = self.bits / 8;
    
    if (bytes > CC_SHA256_DIGEST_LENGTH) {
      NSLog(@"ERROR: SHA256 hash is too short for curve");
      return NO;
    }

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256([data bytes], (int)[data length], hash);
    return [self verifySignature:signature forHash:[NSData dataWithBytes:hash length:bytes]];
}


- (NSData*)hashSHA256AndSignData:(NSData *)data {
    int bytes = self.bits / 8;

    if (bytes > CC_SHA256_DIGEST_LENGTH) {
      NSLog(@"ERROR: SHA256 hash is too short for curve");
      return nil;
    }

    unsigned char hash[CC_SHA256_DIGEST_LENGTH];
    CC_SHA256([data bytes], (int)[data length], hash);
    return [self signatureForHash:[NSData dataWithBytes:hash length:bytes]];
}


- (BOOL)hashSHA384AndVerifySignature:(NSData *)signature forData:(NSData *)data {
    int bytes = self.bits / 8;

    unsigned char hash[CC_SHA384_DIGEST_LENGTH];
    CC_SHA384([data bytes], (int)[data length], hash);
    return [self verifySignature:signature forHash:[NSData dataWithBytes:hash length:bytes]];
}


- (NSData*)hashSHA384AndSignData:(NSData *)data {
    int bytes = self.bits / 8;

    unsigned char hash[CC_SHA384_DIGEST_LENGTH];
    CC_SHA384([data bytes], (int)[data length], hash);
    return [self signatureForHash:[NSData dataWithBytes:hash length:bytes]];
}

- (NSData*)encodedSignatureForHash: (NSData*)hash {
    NSData *signature = [self signatureForHash:hash];
    return derEncodeSignature(signature);    
}

- (NSData*)hashSHA256AndSignDataEncoded: (NSData*)data {
    NSData *signature = [self hashSHA256AndSignData:data];
    return derEncodeSignature(signature);    
}

- (NSData*)hashSHA384AndSignDataEncoded: (NSData*)data {
    NSData *signature = [self hashSHA384AndSignData:data];
    return derEncodeSignature(signature);    
}

@end

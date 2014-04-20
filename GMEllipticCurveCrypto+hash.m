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

@end

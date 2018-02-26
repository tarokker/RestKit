// AF_PropertyListRequestOperation_RestKit.m
//
// Copyright (c) 2011 Gowalla (http://gowalla.com/)
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#import "AF_PropertyListRequestOperation_RestKit.h"

static dispatch_queue_t af_property_list_request_operation_processing_queue_restkit() {
    static dispatch_queue_t af_af_property_list_request_operation_processing_queue_restkit;
    static dispatch_once_t onceToken;
    dispatch_once(&onceToken, ^{
        af_af_property_list_request_operation_processing_queue_restkit = dispatch_queue_create("com.alamofire.restkit.networking.property-list-request.processing", DISPATCH_QUEUE_CONCURRENT);
    });

    return af_af_property_list_request_operation_processing_queue_restkit;
}

@interface AF_PropertyListRequestOperation_RestKit ()
@property (readwrite, nonatomic) id responsePropertyList;
@property (readwrite, nonatomic, assign) NSPropertyListFormat propertyListFormat;
@property (readwrite, nonatomic) NSError *propertyListError;
@end

@implementation AF_PropertyListRequestOperation_RestKit
@synthesize responsePropertyList = _responsePropertyList;
@synthesize propertyListReadOptions = _propertyListReadOptions;
@synthesize propertyListFormat = _propertyListFormat;
@synthesize propertyListError = _propertyListError;

+ (instancetype)propertyListRequestOperationWithRequest:(NSURLRequest *)request
												success:(void (^)(NSURLRequest *request, NSHTTPURLResponse *response, id propertyList))success
												failure:(void (^)(NSURLRequest *request, NSHTTPURLResponse *response, NSError *error, id propertyList))failure
{
    AF_PropertyListRequestOperation_RestKit *requestOperation = [(AF_PropertyListRequestOperation_RestKit *)[self alloc] initWithRequest:request];
    [requestOperation setCompletionBlockWithSuccess:^(AF_HTTPRequestOperation_RestKit *operation, id responseObject) {
        if (success) {
            success(operation.request, operation.response, responseObject);
        }
    } failure:^(AF_HTTPRequestOperation_RestKit *operation, NSError *error) {
        if (failure) {
            failure(operation.request, operation.response, error, [(AF_PropertyListRequestOperation_RestKit *)operation responsePropertyList]);
        }
    }];

    return requestOperation;
}

- (id)initWithRequest:(NSURLRequest *)urlRequest {
    self = [super initWithRequest:urlRequest];
    if (!self) {
        return nil;
    }

    self.propertyListReadOptions = NSPropertyListImmutable;

    return self;
}


- (id)responsePropertyList {
    if (!_responsePropertyList && [self.responseData length] > 0 && [self isFinished]) {
        NSPropertyListFormat format;
        NSError *error = nil;
        self.responsePropertyList = [NSPropertyListSerialization propertyListWithData:self.responseData options:self.propertyListReadOptions format:&format error:&error];
        self.propertyListFormat = format;
        self.propertyListError = error;
    }

    return _responsePropertyList;
}

- (NSError *)error {
    if (_propertyListError) {
        return _propertyListError;
    } else {
        return [super error];
    }
}

#pragma mark - AF_HTTPRequestOperation_RestKit

+ (NSSet *)acceptableContentTypes {
    return [NSSet setWithObjects:@"application/x-plist", nil];
}

+ (BOOL)canProcessRequest:(NSURLRequest *)request {
    return [[[request URL] pathExtension] isEqualToString:@"plist"] || [super canProcessRequest:request];
}

- (void)setCompletionBlockWithSuccess:(void (^)(AF_HTTPRequestOperation_RestKit *operation, id responseObject))success
                              failure:(void (^)(AF_HTTPRequestOperation_RestKit *operation, NSError *error))failure
{
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Warc-retain-cycles"
#pragma clang diagnostic ignored "-Wgnu"
    self.completionBlock = ^ {
        if (self.error) {
            if (failure) {
                dispatch_async(self.failureCallbackQueue ?: dispatch_get_main_queue(), ^{
                    failure(self, self.error);
                });
            }
        } else {
            dispatch_async(af_property_list_request_operation_processing_queue_restkit(), ^(void) {
                id propertyList = self.responsePropertyList;

                if (self.propertyListError) {
                    if (failure) {
                        dispatch_async(self.failureCallbackQueue ?: dispatch_get_main_queue(), ^{
                            failure(self, self.error);
                        });
                    }
                } else {
                    if (success) {
                        dispatch_async(self.successCallbackQueue ?: dispatch_get_main_queue(), ^{
                            success(self, propertyList);
                        });
                    }
                }
            });
        }
    };
#pragma clang diagnostic pop
}

@end

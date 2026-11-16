#import "guest-auth-experiment.h"

int main(int argc, const char *argv[]) {
    @autoreleasepool {
        NSMutableArray<NSString *> *arguments = [NSMutableArray array];
        for (int i = 1; i < argc; i++) {
            NSString *value = [NSString stringWithUTF8String:argv[i]];
            if (!value || value.length > 256) return 64;
            [arguments addObject:value];
        }
        return HengeGuestAuthExperimentRun(arguments);
    }
}

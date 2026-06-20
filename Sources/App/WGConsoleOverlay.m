#import "WGConsoleOverlay.h"

@implementation WGConsoleOverlay {
    UITextView *_textView;
    NSMutableAttributedString *_logContent;
}

- (instancetype)initWithFrame:(CGRect)frame {
    self = [super initWithFrame:frame];
    if (self) {
        self.backgroundColor = [UIColor colorWithWhite:0.0 alpha:0.75];
        self.layer.cornerRadius = 8.0;
        self.clipsToBounds = YES;
        self.userInteractionEnabled = YES;
        _visible = YES;

        _textView = [[UITextView alloc] initWithFrame:self.bounds];
        _textView.autoresizingMask = UIViewAutoresizingFlexibleWidth | UIViewAutoresizingFlexibleHeight;
        _textView.backgroundColor = UIColor.clearColor;
        _textView.editable = NO;
        _textView.selectable = YES;
        _textView.font = [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular];
        _textView.textColor = UIColor.greenColor;
        _textView.indicatorStyle = UIScrollViewIndicatorStyleWhite;
        [self addSubview:_textView];

        _logContent = [[NSMutableAttributedString alloc] init];

        [self appendLog:@"=== WineGlass Translation Engine ===" level:WG_LOG_INFO];
        [self appendLog:@"Phase 1: iOS Shell + Metal" level:WG_LOG_INFO];
        [self appendLog:@"Phase 2: PE Loader" level:WG_LOG_INFO];
        [self appendLog:@"Phase 3: x86-64 Interpreter" level:WG_LOG_INFO];
        [self appendLog:@"Phase 4: Win32 API Layer" level:WG_LOG_INFO];
        [self appendLog:@"Phase 5: D3D -> Metal Bridge" level:WG_LOG_INFO];
        [self appendLog:@"---" level:WG_LOG_DEBUG];
    }
    return self;
}

- (UIColor *)colorForLevel:(WGLogLevel)level {
    switch (level) {
        case WG_LOG_DEBUG: return [UIColor colorWithRed:0.6 green:0.6 blue:0.6 alpha:1.0];
        case WG_LOG_INFO:  return [UIColor colorWithRed:0.3 green:1.0 blue:0.3 alpha:1.0];
        case WG_LOG_WARN:  return [UIColor colorWithRed:1.0 green:0.8 blue:0.2 alpha:1.0];
        case WG_LOG_ERROR: return [UIColor colorWithRed:1.0 green:0.3 blue:0.3 alpha:1.0];
        case WG_LOG_FATAL: return [UIColor colorWithRed:1.0 green:0.0 blue:0.0 alpha:1.0];
    }
    return UIColor.whiteColor;
}

- (void)appendLog:(NSString *)message level:(WGLogLevel)level {
    NSString *line = [NSString stringWithFormat:@"%@\n", message];
    NSDictionary *attrs = @{
        NSForegroundColorAttributeName: [self colorForLevel:level],
        NSFontAttributeName: [UIFont monospacedSystemFontOfSize:10 weight:UIFontWeightRegular]
    };
    NSAttributedString *attrLine = [[NSAttributedString alloc] initWithString:line attributes:attrs];

    [_logContent appendAttributedString:attrLine];

    // Keep last 500 lines
    NSString *plain = _logContent.string;
    NSArray *lines = [plain componentsSeparatedByString:@"\n"];
    if (lines.count > 500) {
        NSRange firstLine = [plain rangeOfString:@"\n"];
        if (firstLine.location != NSNotFound) {
            [_logContent deleteCharactersInRange:NSMakeRange(0, firstLine.location + 1)];
        }
    }

    _textView.attributedText = _logContent;

    // Scroll to bottom
    if (_textView.contentSize.height > _textView.bounds.size.height) {
        CGPoint bottom = CGPointMake(0, _textView.contentSize.height - _textView.bounds.size.height);
        [_textView setContentOffset:bottom animated:NO];
    }
}

- (void)clear {
    _logContent = [[NSMutableAttributedString alloc] init];
    _textView.attributedText = _logContent;
}

- (void)setVisible:(BOOL)visible {
    _visible = visible;
    self.hidden = !visible;
}

@end

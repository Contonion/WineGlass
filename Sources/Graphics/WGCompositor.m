#import "WGCompositor.h"
#import <CoreText/CoreText.h>
#include "wg_win32_windows.h"
#include "wg_log.h"

typedef struct __attribute__((packed)) {
    float x, y;
    float r, g, b, a;
    float u, v; // texture coords (0 if no texture)
} WGVertex;

static NSString *const shaderSource = @""
"#include <metal_stdlib>\n"
"using namespace metal;\n"
"struct Vertex {\n"
"    packed_float2 pos;\n"
"    packed_float4 color;\n"
"    packed_float2 uv;\n"
"};\n"
"struct Fragment { float4 pos [[position]]; float4 color; float2 uv; };\n"
"vertex Fragment vert(const device Vertex *verts [[buffer(0)]], uint vid [[vertex_id]]) {\n"
"    Fragment f;\n"
"    f.pos = float4(float2(verts[vid].pos), 0, 1);\n"
"    f.color = float4(verts[vid].color);\n"
"    f.uv = float2(verts[vid].uv);\n"
"    return f;\n"
"}\n"
"fragment float4 frag(Fragment f [[stage_in]], texture2d<float> tex [[texture(0)]]) {\n"
"    if (f.uv.x > 0.001 || f.uv.y > 0.001) {\n"
"        constexpr sampler s(filter::linear);\n"
"        float4 t = tex.sample(s, f.uv);\n"
"        return float4(t.rgb * f.color.rgb, t.a * f.color.a);\n"
"    }\n"
"    return f.color;\n"
"}\n";

@implementation WGCompositor {
    id<MTLDevice> _device;
    id<MTLRenderPipelineState> _pipeline;
    id<MTLBuffer> _vertexBuffer;
    id<MTLTexture> _textTexture;
    BOOL _ready;
}

- (instancetype)initWithDevice:(id<MTLDevice>)device {
    self = [super init];
    if (self) {
        _device = device;
        [self buildPipeline];
        _vertexBuffer = [device newBufferWithLength:sizeof(WGVertex) * 8192
                                           options:MTLResourceStorageModeShared];
        [self createTextTexture];
    }
    return self;
}

- (void)buildPipeline {
    NSError *error = nil;
    id<MTLLibrary> lib = [_device newLibraryWithSource:shaderSource options:nil error:&error];
    if (!lib) {
        WG_LOGE("Compositor", "Shader compile: %s", error.localizedDescription.UTF8String);
        return;
    }

    MTLRenderPipelineDescriptor *desc = [MTLRenderPipelineDescriptor new];
    desc.vertexFunction = [lib newFunctionWithName:@"vert"];
    desc.fragmentFunction = [lib newFunctionWithName:@"frag"];
    desc.colorAttachments[0].pixelFormat = MTLPixelFormatBGRA8Unorm;
    desc.colorAttachments[0].blendingEnabled = YES;
    desc.colorAttachments[0].sourceRGBBlendFactor = MTLBlendFactorSourceAlpha;
    desc.colorAttachments[0].destinationRGBBlendFactor = MTLBlendFactorOneMinusSourceAlpha;
    desc.colorAttachments[0].sourceAlphaBlendFactor = MTLBlendFactorOne;
    desc.colorAttachments[0].destinationAlphaBlendFactor = MTLBlendFactorOneMinusSourceAlpha;

    _pipeline = [_device newRenderPipelineStateWithDescriptor:desc error:&error];
    if (!_pipeline) {
        WG_LOGE("Compositor", "Pipeline: %s", error.localizedDescription.UTF8String);
        return;
    }
    _ready = YES;
}

- (void)createTextTexture {
    int texW = 1024, texH = 256;

    // Use UIGraphicsImageRenderer for proper iOS context
    UIGraphicsImageRenderer *renderer = [[UIGraphicsImageRenderer alloc]
        initWithSize:CGSizeMake(texW, texH)];

    UIImage *image = [renderer imageWithActions:^(UIGraphicsImageRendererContext *ctx) {
        // Black background
        [[UIColor blackColor] setFill];
        [ctx fillRect:CGRectMake(0, 0, texW, texH)];

        // Render window titles
        WGWindowManager *wm = wg_wm_get();
        int yPos = 10;
        for (int i = 0; i < wm->count && yPos < texH - 30; i++) {
            WGWin32Window *w = &wm->windows[i];
            if (!w->alive || !w->visible || !w->title[0]) continue;
            if (w->parent != 0) continue;

            int len = 0;
            while (len < 255 && w->title[len]) len++;
            NSString *title = [[NSString alloc] initWithCharacters:(const unichar *)w->title length:len];

            NSDictionary *attrs = @{
                NSFontAttributeName: [UIFont boldSystemFontOfSize:20],
                NSForegroundColorAttributeName: [UIColor whiteColor]
            };
            [title drawAtPoint:CGPointMake(10, yPos) withAttributes:attrs];
            yPos += 30;
        }

        // Status line at bottom
        NSString *status = [NSString stringWithFormat:@"WineGlass — Running x86 on iOS"];
        NSDictionary *sAttrs = @{
            NSFontAttributeName: [UIFont systemFontOfSize:14],
            NSForegroundColorAttributeName: [UIColor colorWithWhite:0.7 alpha:1.0]
        };
        [status drawAtPoint:CGPointMake(10, texH - 24) withAttributes:sAttrs];
    }];

    // Convert to Metal texture (use BGRA since that's what UIImage gives us)
    CGImageRef cgImg = image.CGImage;
    MTLTextureDescriptor *td = [MTLTextureDescriptor texture2DDescriptorWithPixelFormat:MTLPixelFormatRGBA8Unorm
                                                                                  width:texW height:texH mipmapped:NO];
    td.usage = MTLTextureUsageShaderRead;
    _textTexture = [_device newTextureWithDescriptor:td];

    // Draw into RGBA pixel buffer
    uint8_t *pixels = calloc(texW * texH * 4, 1);
    CGColorSpaceRef cs = CGColorSpaceCreateDeviceRGB();
    CGContextRef bctx = CGBitmapContextCreate(pixels, texW, texH, 8, texW * 4, cs,
                                              kCGImageAlphaPremultipliedLast);
    CGContextDrawImage(bctx, CGRectMake(0, 0, texW, texH), cgImg);
    CGContextRelease(bctx);
    CGColorSpaceRelease(cs);

    [_textTexture replaceRegion:MTLRegionMake2D(0, 0, texW, texH)
                    mipmapLevel:0
                      withBytes:pixels
                    bytesPerRow:texW * 4];
    free(pixels);
}

static void addQuad(WGVertex *verts, int *count,
                    float x1, float y1, float x2, float y2,
                    float r, float g, float b, float a) {
    int i = *count;
    verts[i++] = (WGVertex){x1, y1, r, g, b, a, 0, 0};
    verts[i++] = (WGVertex){x2, y1, r, g, b, a, 0, 0};
    verts[i++] = (WGVertex){x1, y2, r, g, b, a, 0, 0};
    verts[i++] = (WGVertex){x2, y1, r, g, b, a, 0, 0};
    verts[i++] = (WGVertex){x2, y2, r, g, b, a, 0, 0};
    verts[i++] = (WGVertex){x1, y2, r, g, b, a, 0, 0};
    *count = i;
}

static void addTexturedQuad(WGVertex *verts, int *count,
                            float x1, float y1, float x2, float y2,
                            float u1, float v1, float u2, float v2,
                            float r, float g, float b, float a) {
    int i = *count;
    verts[i++] = (WGVertex){x1, y1, r, g, b, a, u1, v1};
    verts[i++] = (WGVertex){x2, y1, r, g, b, a, u2, v1};
    verts[i++] = (WGVertex){x1, y2, r, g, b, a, u1, v2};
    verts[i++] = (WGVertex){x2, y1, r, g, b, a, u2, v1};
    verts[i++] = (WGVertex){x2, y2, r, g, b, a, u2, v2};
    verts[i++] = (WGVertex){x1, y2, r, g, b, a, u1, v2};
    *count = i;
}

static float toNDCx(float px, float screenW) { return (px / screenW) * 2.0f - 1.0f; }
static float toNDCy(float py, float screenH) { return 1.0f - (py / screenH) * 2.0f; }

- (void)renderWindowsToDrawable:(id<CAMetalDrawable>)drawable
                   commandQueue:(id<MTLCommandQueue>)queue
                     screenSize:(CGSize)size {
    if (!_ready) return;

    // Rebuild text texture each frame (titles may change)
    [self createTextTexture];

    WGWindowManager *wm = wg_wm_get();
    int visCount = wg_wm_visible_count();
    if (visCount == 0) return;

    WGVertex *verts = (WGVertex *)_vertexBuffer.contents;
    int vertCount = 0;
    float sw = size.width;
    float sh = size.height;

    float scale = fminf(sw / 800.0f, sh / 600.0f);
    float offsetX = (sw - 800 * scale) / 2.0f;
    float offsetY = (sh - 600 * scale) / 2.0f;

    int titleIndex = 0;
    for (int i = 0; i < wm->count && vertCount < 7000; i++) {
        WGWin32Window *w = &wm->windows[i];
        if (!w->alive || !w->visible) continue;

        float wx = offsetX + w->x * scale;
        float wy = offsetY + w->y * scale;
        float ww = w->w * scale;
        float wh = w->h * scale;

        float x1 = toNDCx(wx, sw);
        float y1 = toNDCy(wy, sh);
        float x2 = toNDCx(wx + ww, sw);
        float y2 = toNDCy(wy + wh, sh);

        // Window body — light gray like Windows
        addQuad(verts, &vertCount, x1, y1, x2, y2, 0.94f, 0.94f, 0.94f, 0.98f);

        // Title bar for top-level windows
        if (w->parent == 0) {
            float tbh = 32.0f * scale;
            float ty2 = toNDCy(wy + tbh, sh);
            // Windows blue title bar gradient
            addQuad(verts, &vertCount, x1, y1, x2, ty2, 0.0f, 0.47f, 0.84f, 1.0f);

            // Title text (white on blue)
            if (w->title[0]) {
                float textH = 20.0f * scale;
                float textY1 = toNDCy(wy + 6 * scale, sh);
                float textY2 = toNDCy(wy + 6 * scale + textH, sh);
                float textX1 = toNDCx(wx + 10 * scale, sw);
                float textX2 = toNDCx(wx + 300 * scale, sw);
                float tv1 = (float)(titleIndex * 30) / 256.0f;
                float tv2 = tv1 + 25.0f / 256.0f;
                addTexturedQuad(verts, &vertCount, textX1, textY1, textX2, textY2,
                               0.01f, tv1, 0.4f, tv2, 1.0f, 1.0f, 1.0f, 1.0f);
                titleIndex++;
            }

            // Close button (red)
            float cbSize = 20.0f * scale;
            float cbx1 = toNDCx(wx + ww - cbSize - 8 * scale, sw);
            float cbx2 = toNDCx(wx + ww - 8 * scale, sw);
            float cby1 = toNDCy(wy + 6 * scale, sh);
            float cby2 = toNDCy(wy + 6 * scale + cbSize, sh);
            addQuad(verts, &vertCount, cbx1, cby1, cbx2, cby2, 0.9f, 0.2f, 0.2f, 1.0f);
        }

        // Shadow
        float sdw = 4.0f;
        float sx2 = toNDCx(wx + ww + sdw, sw);
        float sy2 = toNDCy(wy + wh + sdw, sh);
        addQuad(verts, &vertCount, x2, y1, sx2, sy2, 0.0f, 0.0f, 0.0f, 0.3f);
        float sdy1 = toNDCy(wy + wh, sh);
        addQuad(verts, &vertCount, x1, sdy1, sx2, sy2, 0.0f, 0.0f, 0.0f, 0.3f);
    }

    if (vertCount == 0) return;

    MTLRenderPassDescriptor *pass = [MTLRenderPassDescriptor new];
    pass.colorAttachments[0].texture = drawable.texture;
    pass.colorAttachments[0].loadAction = MTLLoadActionClear;
    pass.colorAttachments[0].storeAction = MTLStoreActionStore;
    pass.colorAttachments[0].clearColor = MTLClearColorMake(0.12, 0.12, 0.18, 1.0);

    id<MTLCommandBuffer> cmd = [queue commandBuffer];
    id<MTLRenderCommandEncoder> enc = [cmd renderCommandEncoderWithDescriptor:pass];

    [enc setRenderPipelineState:_pipeline];
    [enc setVertexBuffer:_vertexBuffer offset:0 atIndex:0];
    [enc setFragmentTexture:_textTexture atIndex:0];
    [enc drawPrimitives:MTLPrimitiveTypeTriangle vertexStart:0 vertexCount:vertCount];

    [enc endEncoding];
    [cmd presentDrawable:drawable];
    [cmd commit];
}

@end

// wg_dxbc.c — DXBC (Shader Model 4/5) -> MSL translator. See wg_dxbc.h.
//
// Pipeline: parse the DXBC container -> locate the SHDR/SHEX token stream ->
// decode the instruction stream (opcode + operand tokens) -> emit MSL over a
// register model (temps r0..rN, inputs in.vN, outputs out.oN, constant buffers
// cbN[], resources tN, samplers sN). Coverage is a core instruction set; unknown
// opcodes emit a comment so the rest still compiles.
#include "wg_dxbc.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <stdarg.h>

// ---------- little string builder ----------
typedef struct { char *buf; size_t len, cap; } SB;
static void sb_ensure(SB *s, size_t extra) {
    if (s->len + extra + 1 > s->cap) {
        size_t nc = s->cap ? s->cap * 2 : 1024;
        while (nc < s->len + extra + 1) nc *= 2;
        s->buf = (char *)realloc(s->buf, nc); s->cap = nc;
    }
}
static void sb_puts(SB *s, const char *t) { size_t n = strlen(t); sb_ensure(s, n); memcpy(s->buf + s->len, t, n); s->len += n; s->buf[s->len] = 0; }
static void sb_putf(SB *s, const char *fmt, ...) {
    char tmp[512]; va_list ap; va_start(ap, fmt); vsnprintf(tmp, sizeof tmp, fmt, ap); va_end(ap); sb_puts(s, tmp);
}

// ---------- DXBC container ----------
#define FOURCC(a,b,c,d) ((uint32_t)(a)|((uint32_t)(b)<<8)|((uint32_t)(c)<<16)|((uint32_t)(d)<<24))

bool wg_dxbc_is_dxbc(const void *data, uint32_t size) {
    return data && size >= 4 && *(const uint32_t *)data == FOURCC('D','X','B','C');
}

// Find a chunk by FourCC; returns pointer to chunk data + size, or NULL.
static const uint8_t *find_chunk(const uint8_t *base, uint32_t size, uint32_t tag, uint32_t *out_size) {
    if (size < 32) return NULL;
    uint32_t chunk_count = *(const uint32_t *)(base + 28);
    const uint32_t *offsets = (const uint32_t *)(base + 32);
    if (32 + chunk_count * 4u > size) return NULL;
    for (uint32_t i = 0; i < chunk_count; i++) {
        uint32_t off = offsets[i];
        if (off + 8 > size) continue;
        uint32_t ctag = *(const uint32_t *)(base + off);
        uint32_t csize = *(const uint32_t *)(base + off + 4);
        if (ctag == tag) { if (out_size) *out_size = csize; return base + off + 8; }
    }
    return NULL;
}

// ---------- signatures (ISGN/OSGN) ----------
typedef struct { char name[32]; uint32_t index, sysval, reg; uint8_t mask; } SigElem;
static int parse_sig(const uint8_t *chunk, SigElem *out, int maxn) {
    if (!chunk) return 0;
    uint32_t count = *(const uint32_t *)(chunk + 0);
    const uint8_t *elems = chunk + 8;   // count(4)+unknown(4)
    int n = 0;
    for (uint32_t i = 0; i < count && n < maxn; i++) {
        const uint8_t *e = elems + i * 24;   // D3D11_SIGNATURE_PARAMETER: 24 bytes
        uint32_t name_off = *(const uint32_t *)(e + 0);
        SigElem *s = &out[n++];
        const char *nm = (const char *)(chunk + name_off);
        strncpy(s->name, nm, sizeof s->name - 1); s->name[sizeof s->name - 1] = 0;
        s->index  = *(const uint32_t *)(e + 4);
        s->sysval = *(const uint32_t *)(e + 8);   // D3D_NAME_* (1=Position, ...)
        s->reg    = *(const uint32_t *)(e + 16);
        s->mask   = *(const uint8_t  *)(e + 20);
    }
    return n;
}

// ---------- SM4/5 token stream ----------
// Operand register types.
enum { OT_TEMP=0, OT_INPUT=1, OT_OUTPUT=2, OT_INDEXABLE_TEMP=3, OT_IMM32=4, OT_IMM64=5,
       OT_SAMPLER=6, OT_RESOURCE=7, OT_CBUFFER=8, OT_ICB=9, OT_NULL=13 };

typedef struct {
    int type, num_comp, sel_mode;
    uint8_t mask;            // mask mode: bit x=1,y=2,z=4,w=8
    uint8_t sw[4];           // swizzle mode: each 0..3
    int sel1;                // select1 mode
    int index_dim;
    int idx[3];              // immediate index per dimension
    int idx_rel[3];          // relative? (1 = uses a relative reg, stored in rel_str)
    char rel_str[3][48];     // relative index expression
    float imm[4]; int imm_n; // immediate values
    int modifier;            // source modifier: 0 none, 1 neg, 2 abs, 3 -abs
} Operand;

typedef struct {
    const uint32_t *p, *end;
    int ntemps;
    uint32_t in_used, out_used;    // register bitmasks
    int out_pos_reg;               // output register that is SV_Position (-1 none)
    uint32_t cb_used, res_used, samp_used, depth_res;   // depth_res: sampled via sample_compare
    bool is_pixel;
    bool in_siv_pos[8];            // input reg is a system value position?
} Ctx;

static const char *swz = "xyzw";

// mask (bit x=1..) -> ".xyzw" string
static void mask_to_str(uint8_t m, char *out) {
    int k = 0; out[k++] = '.';
    for (int i = 0; i < 4; i++) if (m & (1 << i)) out[k++] = swz[i];
    if (k == 1) { out[0] = 0; } else out[k] = 0;   // empty if no bits
}
static int mask_count(uint8_t m) { int c = 0; for (int i=0;i<4;i++) if (m&(1<<i)) c++; return c; }
static const char *ftype(int n) { return n<=1?"float":n==2?"float2":n==3?"float3":"float4"; }
static const char *itype(int n) { return n<=1?"int":n==2?"int2":n==3?"int3":"int4"; }
static const char *utype(int n) { return n<=1?"uint":n==2?"uint2":n==3?"uint3":"uint4"; }
// Emit "dst<mask> = [saturate(]rhs[)];" — the DXBC instruction saturate modifier.
static void emit_rhs(SB *body, const char *d, const char *dmask, int sat, const char *rhs) {
    if (sat) sb_putf(body, "  %s%s = saturate(%s);\n", d, dmask, rhs);
    else     sb_putf(body, "  %s%s = %s;\n", d, dmask, rhs);
}

// Read one operand token stream into `o`.
static void read_operand(Ctx *c, Operand *o) {
    memset(o, 0, sizeof *o);
    uint32_t tok = *c->p++;
    o->num_comp = tok & 0x3;                    // 0,1,2(=4comp),3
    o->type = (tok >> 12) & 0xff;
    o->index_dim = (tok >> 20) & 0x3;
    o->sel_mode = (tok >> 2) & 0x3;
    if (o->num_comp == 2) {                     // 4-component
        if (o->sel_mode == 0) {                 // mask
            o->mask = (tok >> 4) & 0xf;
        } else if (o->sel_mode == 1) {          // swizzle
            for (int i = 0; i < 4; i++) o->sw[i] = (tok >> (4 + i*2)) & 0x3;
        } else {                                // select1
            o->sel1 = (tok >> 4) & 0x3;
        }
    }
    bool extended = (tok >> 31) & 1;
    while (extended) {
        uint32_t ext = *c->p++;
        if ((ext & 0x3) == 1)   // D3D10_SB_EXTENDED_OPERAND_MODIFIER
            o->modifier = (ext >> 6) & 0xff;  // 1=neg, 2=abs, 3=-abs
        extended = (ext >> 31) & 1;
    }
    // immediate values
    if (o->type == OT_IMM32) {
        o->imm_n = (o->num_comp == 2) ? 4 : 1;
        for (int i = 0; i < o->imm_n; i++) { uint32_t u = *c->p++; memcpy(&o->imm[i], &u, 4); }
        return;
    }
    if (o->type == OT_IMM64) { c->p += (o->num_comp == 2) ? 8 : 2; return; }
    // indices
    for (int d = 0; d < o->index_dim; d++) {
        int rep = (tok >> (22 + d*3)) & 0x7;
        if (rep == 0) { o->idx[d] = (int)*c->p++; }               // immediate32
        else if (rep == 1) { o->idx[d] = (int)*c->p++; c->p++; }  // immediate64 (take low)
        else if (rep == 2) {                                      // relative
            Operand rel; read_operand(c, &rel);
            o->idx_rel[d] = 1;
            snprintf(o->rel_str[d], sizeof o->rel_str[d], "int(r%d.%c)", rel.idx[0], swz[rel.sw[0]]);
        } else if (rep == 3) {                                    // imm32 + relative
            o->idx[d] = (int)*c->p++;
            Operand rel; read_operand(c, &rel);
            o->idx_rel[d] = 1;
            snprintf(o->rel_str[d], sizeof o->rel_str[d], "int(r%d.%c)", rel.idx[0], swz[rel.sw[0]]);
        }
    }
}

// Build the base lvalue/rvalue for an operand (no swizzle applied yet).
static void operand_base(Ctx *c, Operand *o, char *out, size_t osz) {
    switch (o->type) {
        case OT_TEMP:   snprintf(out, osz, "r%d", o->idx[0]); c->ntemps = (o->idx[0]+1 > c->ntemps) ? o->idx[0]+1 : c->ntemps; break;
        case OT_INPUT:  snprintf(out, osz, "in.v%d", o->idx[0]); if (o->idx[0] < 32) c->in_used |= 1u << o->idx[0]; break;
        case OT_OUTPUT:
            snprintf(out, osz, "out.o%d", o->idx[0]);   // both stages use an output struct
            if (o->idx[0] < 32) c->out_used |= 1u << o->idx[0];
            break;
        case OT_CBUFFER: {
            int bank = o->idx[0]; if (bank < 32) c->cb_used |= 1u << bank;
            if (o->idx_rel[1]) snprintf(out, osz, "cb%d[%s]", bank, o->rel_str[1]);
            else snprintf(out, osz, "cb%d[%d]", bank, o->idx[1]);
            break;
        }
        case OT_NULL:   snprintf(out, osz, "float4(0.0)"); break;
        default:        snprintf(out, osz, "float4(0.0)"); break;
    }
}

// Source rvalue restricted to `ncomp` components (aligned to a dst mask that
// covers the first `ncomp` written positions in order).
static void src_str(Ctx *c, Operand *o, int ncomp, const uint8_t *positions, char *out, size_t osz) {
    char expr[200];
    if (o->type == OT_IMM32) {
        if (ncomp <= 1) snprintf(expr, sizeof expr, "float(%g)", o->imm[0]);
        else {
            char t[160]; int k = snprintf(t, sizeof t, "float%d(", ncomp);
            for (int i = 0; i < ncomp; i++) k += snprintf(t+k, sizeof t-k, "%s%g", i?",":"", o->imm[o->imm_n==1?0:positions[i]]);
            snprintf(t+k, sizeof t-k, ")"); snprintf(expr, sizeof expr, "%s", t);
        }
    } else {
        char base[80]; operand_base(c, o, base, sizeof base);
        char sw_s[8]; int k = 0;
        if (o->num_comp == 2 && o->sel_mode == 1) {          // swizzle mode
            sw_s[k++] = '.';
            for (int i = 0; i < ncomp; i++) sw_s[k++] = swz[o->sw[positions[i]]];
        } else if (o->num_comp == 2 && o->sel_mode == 2) {   // select1 -> scalar, replicate
            sw_s[k++] = '.';
            for (int i = 0; i < ncomp; i++) sw_s[k++] = swz[o->sel1];
        } else if (o->num_comp == 1) {                       // 1-component scalar
            sw_s[k++] = '.'; sw_s[k++] = 'x';
        } else {                                             // default identity, take positions
            sw_s[k++] = '.';
            for (int i = 0; i < ncomp; i++) sw_s[k++] = swz[positions[i]];
        }
        sw_s[k] = 0;
        snprintf(expr, sizeof expr, "%s%s", base, sw_s);
    }
    // source modifier: neg / abs / -abs
    if (o->modifier == 1)      snprintf(out, osz, "(-%s)", expr);
    else if (o->modifier == 2) snprintf(out, osz, "abs(%s)", expr);
    else if (o->modifier == 3) snprintf(out, osz, "(-abs(%s))", expr);
    else                       snprintf(out, osz, "%s", expr);
}

// ---------- opcodes ----------
enum { OP_ADD=0, OP_AND=1, OP_BREAK=2, OP_BREAKC=3, OP_CONTINUE=7, OP_DISCARD=13,
       OP_DIV=14, OP_DP2=15, OP_DP3=16, OP_DP4=17, OP_ELSE=18, OP_ENDIF=21, OP_ENDLOOP=22,
       OP_EQ=24, OP_EXP=25, OP_FTOI=27, OP_FTOU=28, OP_FRC=26, OP_GE=29, OP_IADD=30, OP_IF=31,
       OP_ITOF=43, OP_LOG=47, OP_LOOP=48, OP_LT=49, OP_INEG=40, OP_ISHL=41, OP_ISHR=42, OP_IMUL=38,
       OP_MAD=50, OP_MIN=51, OP_MAX=52, OP_MOV=54, OP_MOVC=55, OP_MUL=56, OP_NE=57, OP_NOT=59, OP_OR=60,
       OP_RET=62, OP_ROUND_NE=64, OP_ROUND_NI=65, OP_ROUND_PI=66, OP_ROUND_Z=67,
       OP_RSQ=68, OP_SAMPLE=69, OP_SAMPLE_L=72, OP_SQRT=75, OP_SINCOS=77, OP_USHR=85,
       OP_UTOF=86, OP_XOR=87,
       OP_CASE=6, OP_DEFAULT=10, OP_DERIV_RTX=11, OP_DERIV_RTY=12, OP_ENDSWITCH=23, OP_IEQ=32,
       OP_IGE=33, OP_ILT=34, OP_IMAX=36, OP_IMIN=37, OP_INE=39, OP_LD=45, OP_RESINFO=61,
       OP_SAMPLE_C=70, OP_SAMPLE_C_LZ=71, OP_SAMPLE_B=74, OP_SWITCH=76,
       OP_DCL_RESOURCE=88, OP_DCL_CB=89, OP_DCL_SAMPLER=90, OP_DCL_INPUT=95,
       OP_DCL_INPUT_SIV=97, OP_DCL_INPUT_PS=98, OP_DCL_INPUT_PS_SIV=100,
       OP_DCL_OUTPUT=101, OP_DCL_OUTPUT_SIV=103, OP_DCL_TEMPS=104,
       OP_DCL_GLOBALFLAGS=106 };

char *wg_dxbc_to_msl(const void *dxbc, uint32_t size, char *out_stage) {
    if (!wg_dxbc_is_dxbc(dxbc, size)) return NULL;
    const uint8_t *base = (const uint8_t *)dxbc;
    uint32_t shsz = 0;
    const uint8_t *sh = find_chunk(base, size, FOURCC('S','H','E','X'), &shsz);
    if (!sh) sh = find_chunk(base, size, FOURCC('S','H','D','R'), &shsz);
    if (!sh) return NULL;

    const uint32_t *tok = (const uint32_t *)sh;
    uint32_t ver = tok[0];
    uint32_t prog_type = (ver >> 16) & 0xffff;   // 0=pixel,1=vertex
    uint32_t len = tok[1];                        // total dwords
    Ctx c; memset(&c, 0, sizeof c);
    c.p = tok + 2; c.end = tok + (len ? len : (shsz/4));
    c.is_pixel = (prog_type == 0);
    c.out_pos_reg = -1;

    SB body; memset(&body, 0, sizeof body);

    while (c.p < c.end) {
        uint32_t op_tok = *c.p;
        uint32_t opcode = op_tok & 0x7ff;
        int sat = (op_tok >> 13) & 1;   // D3D10_SB_INSTRUCTION_SATURATE
        uint32_t ilen = (op_tok >> 24) & 0x7f;
        const uint32_t *next = c.p + (ilen ? ilen : 1);
        if (opcode == 53 /*CUSTOMDATA*/ && c.p + 1 < c.end) next = c.p + c.p[1]; // length in 2nd dword
        c.p++;   // consume opcode token; operands follow

        char d[96], dmask[8], s0[128], s1[128], s2[128];
        uint8_t pos[4]; int nc;

        switch (opcode) {
            case OP_DCL_TEMPS: c.ntemps = (int)*c.p; break;
            case OP_DCL_GLOBALFLAGS: break;
            case OP_DCL_CB: { Operand o; read_operand(&c, &o); if (o.idx[0] < 32) c.cb_used |= 1u<<o.idx[0]; break; }
            case OP_DCL_SAMPLER: { Operand o; read_operand(&c, &o); if (o.idx[0] < 32) c.samp_used |= 1u<<o.idx[0]; break; }
            case OP_DCL_RESOURCE: { Operand o; read_operand(&c, &o); if (o.idx[0] < 32) c.res_used |= 1u<<o.idx[0]; break; }
            case OP_DCL_INPUT: case OP_DCL_INPUT_PS: { Operand o; read_operand(&c, &o); if (o.idx[0] < 32) c.in_used |= 1u<<o.idx[0]; break; }
            case OP_DCL_INPUT_SIV: case OP_DCL_INPUT_PS_SIV: { Operand o; read_operand(&c, &o); uint32_t sv=*c.p; if (o.idx[0]<8 && sv==1) c.in_siv_pos[o.idx[0]]=true; if (o.idx[0]<32) c.in_used |= 1u<<o.idx[0]; break; }
            case OP_DCL_OUTPUT: { Operand o; read_operand(&c, &o); if (o.idx[0] < 32) c.out_used |= 1u<<o.idx[0]; break; }
            case OP_DCL_OUTPUT_SIV: { Operand o; read_operand(&c, &o); uint32_t sv=*c.p; if (sv==1) c.out_pos_reg = o.idx[0]; if (o.idx[0]<32) c.out_used |= 1u<<o.idx[0]; break; }

            case OP_MOV: case OP_FRC: case OP_EXP: case OP_LOG: case OP_RSQ:
            case OP_SQRT: case OP_ROUND_NE: case OP_ROUND_NI: case OP_ROUND_PI: case OP_ROUND_Z:
            case OP_DERIV_RTX: case OP_DERIV_RTY: {
                Operand od, oa; read_operand(&c, &od); read_operand(&c, &oa);
                operand_base(&c, &od, d, sizeof d); mask_to_str(od.mask, dmask);
                nc = mask_count(od.mask); int k=0; for (int i=0;i<4;i++) if (od.mask&(1<<i)) pos[k++]=i;
                src_str(&c, &oa, nc, pos, s0, sizeof s0);
                const char *fn = opcode==OP_FRC?"fract":opcode==OP_EXP?"exp2":opcode==OP_LOG?"log2":
                                 opcode==OP_RSQ?"rsqrt":opcode==OP_SQRT?"sqrt":
                                 opcode==OP_ROUND_NE?"rint":opcode==OP_ROUND_NI?"floor":
                                 opcode==OP_ROUND_PI?"ceil":opcode==OP_ROUND_Z?"trunc":
                                 opcode==OP_DERIV_RTX?"dfdx":opcode==OP_DERIV_RTY?"dfdy":NULL;
                { char rhs[200];
                  if (fn) snprintf(rhs, sizeof rhs, "%s(%s)", fn, s0);
                  else    snprintf(rhs, sizeof rhs, "%s", s0);
                  emit_rhs(&body, d, dmask, sat, rhs); }
                break;
            }
            case OP_ADD: case OP_MUL: case OP_DIV: case OP_MIN: case OP_MAX: {
                Operand od, oa, ob; read_operand(&c,&od); read_operand(&c,&oa); read_operand(&c,&ob);
                operand_base(&c,&od,d,sizeof d); mask_to_str(od.mask,dmask);
                nc = mask_count(od.mask); int k=0; for (int i=0;i<4;i++) if (od.mask&(1<<i)) pos[k++]=i;
                src_str(&c,&oa,nc,pos,s0,sizeof s0); src_str(&c,&ob,nc,pos,s1,sizeof s1);
                const char *o2 = opcode==OP_ADD?"+":opcode==OP_MUL?"*":opcode==OP_DIV?"/":NULL;
                { char rhs[240];
                  if (o2) snprintf(rhs,sizeof rhs,"%s %s %s", s0,o2,s1);
                  else    snprintf(rhs,sizeof rhs,"%s(%s, %s)", opcode==OP_MIN?"min":"max", s0,s1);
                  emit_rhs(&body, d, dmask, sat, rhs); }
                break;
            }
            case OP_MAD: case OP_MOVC: {
                Operand od,oa,ob,oc; read_operand(&c,&od); read_operand(&c,&oa); read_operand(&c,&ob); read_operand(&c,&oc);
                operand_base(&c,&od,d,sizeof d); mask_to_str(od.mask,dmask);
                nc = mask_count(od.mask); int k=0; for (int i=0;i<4;i++) if (od.mask&(1<<i)) pos[k++]=i;
                src_str(&c,&oa,nc,pos,s0,sizeof s0); src_str(&c,&ob,nc,pos,s1,sizeof s1); src_str(&c,&oc,nc,pos,s2,sizeof s2);
                { char rhs[280];
                  if (opcode==OP_MAD) snprintf(rhs,sizeof rhs,"fma(%s, %s, %s)", s0,s1,s2);
                  else { char zc[24]; if (nc<=1) snprintf(zc,sizeof zc,"float(0.0)"); else snprintf(zc,sizeof zc,"float%d(0.0)",nc);
                         snprintf(rhs,sizeof rhs,"select(%s, %s, %s != %s)", s2,s1,s0,zc); } // movc: src0?src1:src2
                  emit_rhs(&body, d, dmask, sat, rhs); }
                break;
            }
            case OP_DP2: case OP_DP3: case OP_DP4: {
                Operand od,oa,ob; read_operand(&c,&od); read_operand(&c,&oa); read_operand(&c,&ob);
                operand_base(&c,&od,d,sizeof d); mask_to_str(od.mask,dmask);
                int n = opcode==OP_DP2?2:opcode==OP_DP3?3:4;
                uint8_t allp[4]={0,1,2,3};
                src_str(&c,&oa,n,allp,s0,sizeof s0); src_str(&c,&ob,n,allp,s1,sizeof s1);
                { char rhs[240]; snprintf(rhs,sizeof rhs,"dot(%s, %s)", s0,s1); emit_rhs(&body, d, dmask, sat, rhs); }
                break;
            }
            case OP_SAMPLE: case OP_SAMPLE_L: {
                Operand od,oc,ores,osmp; read_operand(&c,&od); read_operand(&c,&oc); read_operand(&c,&ores); read_operand(&c,&osmp);
                if (opcode==OP_SAMPLE_L) { Operand ol; read_operand(&c,&ol); }
                operand_base(&c,&od,d,sizeof d); mask_to_str(od.mask,dmask);
                uint8_t uv[2]={0,1};
                src_str(&c,&oc,2,uv,s0,sizeof s0);
                sb_putf(&body,"  %s%s = t%d.sample(s%d, %s)%s;\n", d,dmask, ores.idx[0], osmp.idx[0], s0, dmask);
                break;
            }
            case OP_EQ: case OP_GE: case OP_LT: case OP_NE: {
                Operand od,oa,ob; read_operand(&c,&od); read_operand(&c,&oa); read_operand(&c,&ob);
                operand_base(&c,&od,d,sizeof d); mask_to_str(od.mask,dmask);
                nc = mask_count(od.mask); int k=0; for (int i=0;i<4;i++) if (od.mask&(1<<i)) pos[k++]=i;
                src_str(&c,&oa,nc,pos,s0,sizeof s0); src_str(&c,&ob,nc,pos,s1,sizeof s1);
                const char *op2 = opcode==OP_EQ?"==":opcode==OP_GE?">=":opcode==OP_LT?"<":"!=";
                sb_putf(&body,"  %s%s = select(%s(0.0), %s(1.0), %s %s %s);\n", d,dmask,ftype(nc),ftype(nc),s0,op2,s1);
                break;
            }
            case OP_IADD: case OP_ISHL: case OP_ISHR: case OP_USHR: case OP_AND: case OP_OR: case OP_XOR: {
                Operand od,oa,ob; read_operand(&c,&od); read_operand(&c,&oa); read_operand(&c,&ob);
                operand_base(&c,&od,d,sizeof d); mask_to_str(od.mask,dmask);
                nc = mask_count(od.mask); int k=0; for (int i=0;i<4;i++) if (od.mask&(1<<i)) pos[k++]=i;
                src_str(&c,&oa,nc,pos,s0,sizeof s0); src_str(&c,&ob,nc,pos,s1,sizeof s1);
                bool uns = (opcode==OP_USHR||opcode==OP_AND||opcode==OP_OR||opcode==OP_XOR);
                const char *it = uns ? utype(nc) : itype(nc);
                const char *op2 = opcode==OP_IADD?"+":opcode==OP_ISHL?"<<":(opcode==OP_ISHR||opcode==OP_USHR)?">>":opcode==OP_AND?"&":opcode==OP_OR?"|":"^";
                sb_putf(&body,"  %s%s = as_type<%s>(as_type<%s>(%s) %s as_type<%s>(%s));\n", d,dmask,ftype(nc),it,s0,op2,it,s1);
                break;
            }
            case OP_INEG: case OP_NOT: {
                Operand od,oa; read_operand(&c,&od); read_operand(&c,&oa);
                operand_base(&c,&od,d,sizeof d); mask_to_str(od.mask,dmask);
                nc = mask_count(od.mask); int k=0; for (int i=0;i<4;i++) if (od.mask&(1<<i)) pos[k++]=i;
                src_str(&c,&oa,nc,pos,s0,sizeof s0);
                if (opcode==OP_INEG) sb_putf(&body,"  %s%s = as_type<%s>(-as_type<%s>(%s));\n", d,dmask,ftype(nc),itype(nc),s0);
                else                 sb_putf(&body,"  %s%s = as_type<%s>(~as_type<%s>(%s));\n", d,dmask,ftype(nc),utype(nc),s0);
                break;
            }
            case OP_IMUL: { // (dstHi, dstLo, a, b) -> low 32 bits of the int product (hi rarely used)
                Operand ohi,olo,oa,ob; read_operand(&c,&ohi); read_operand(&c,&olo); read_operand(&c,&oa); read_operand(&c,&ob);
                if (olo.type != OT_NULL) {
                    operand_base(&c,&olo,d,sizeof d); mask_to_str(olo.mask,dmask);
                    int m=mask_count(olo.mask),k=0; for(int i=0;i<4;i++) if(olo.mask&(1<<i)) pos[k++]=i;
                    src_str(&c,&oa,m,pos,s0,sizeof s0); src_str(&c,&ob,m,pos,s1,sizeof s1);
                    sb_putf(&body,"  %s%s = as_type<%s>(as_type<%s>(%s) * as_type<%s>(%s));\n", d,dmask,ftype(m),itype(m),s0,itype(m),s1);
                }
                break;
            }
            case OP_FTOI: case OP_FTOU: case OP_ITOF: case OP_UTOF: {
                Operand od,oa; read_operand(&c,&od); read_operand(&c,&oa);
                operand_base(&c,&od,d,sizeof d); mask_to_str(od.mask,dmask);
                nc = mask_count(od.mask); int k=0; for (int i=0;i<4;i++) if (od.mask&(1<<i)) pos[k++]=i;
                src_str(&c,&oa,nc,pos,s0,sizeof s0);
                if (opcode==OP_FTOI)      sb_putf(&body,"  %s%s = as_type<%s>(%s(%s));\n", d,dmask,ftype(nc),itype(nc),s0);
                else if (opcode==OP_FTOU) sb_putf(&body,"  %s%s = as_type<%s>(%s(%s));\n", d,dmask,ftype(nc),utype(nc),s0);
                else if (opcode==OP_ITOF) sb_putf(&body,"  %s%s = %s(as_type<%s>(%s));\n", d,dmask,ftype(nc),itype(nc),s0);
                else                      sb_putf(&body,"  %s%s = %s(as_type<%s>(%s));\n", d,dmask,ftype(nc),utype(nc),s0);
                break;
            }
            case OP_SINCOS: {
                Operand osin,ocos,osrc; read_operand(&c,&osin); read_operand(&c,&ocos); read_operand(&c,&osrc);
                if (osin.type != OT_NULL) {
                    operand_base(&c,&osin,d,sizeof d); mask_to_str(osin.mask,dmask);
                    int m=mask_count(osin.mask),k=0; for(int i=0;i<4;i++) if(osin.mask&(1<<i)) pos[k++]=i;
                    src_str(&c,&osrc,m,pos,s0,sizeof s0); sb_putf(&body,"  %s%s = sin(%s);\n", d,dmask,s0);
                }
                if (ocos.type != OT_NULL) {
                    operand_base(&c,&ocos,d,sizeof d); mask_to_str(ocos.mask,dmask);
                    int m=mask_count(ocos.mask),k=0; for(int i=0;i<4;i++) if(ocos.mask&(1<<i)) pos[k++]=i;
                    src_str(&c,&osrc,m,pos,s1,sizeof s1); sb_putf(&body,"  %s%s = cos(%s);\n", d,dmask,s1);
                }
                break;
            }
            case OP_IMIN: case OP_IMAX: {
                Operand od,oa,ob; read_operand(&c,&od); read_operand(&c,&oa); read_operand(&c,&ob);
                operand_base(&c,&od,d,sizeof d); mask_to_str(od.mask,dmask);
                nc=mask_count(od.mask); int k=0; for(int i=0;i<4;i++) if(od.mask&(1<<i)) pos[k++]=i;
                src_str(&c,&oa,nc,pos,s0,sizeof s0); src_str(&c,&ob,nc,pos,s1,sizeof s1);
                sb_putf(&body,"  %s%s = as_type<%s>(%s(as_type<%s>(%s), as_type<%s>(%s)));\n",
                        d,dmask,ftype(nc), opcode==OP_IMIN?"min":"max", itype(nc),s0,itype(nc),s1);
                break;
            }
            case OP_IEQ: case OP_IGE: case OP_ILT: case OP_INE: {
                Operand od,oa,ob; read_operand(&c,&od); read_operand(&c,&oa); read_operand(&c,&ob);
                operand_base(&c,&od,d,sizeof d); mask_to_str(od.mask,dmask);
                nc=mask_count(od.mask); int k=0; for(int i=0;i<4;i++) if(od.mask&(1<<i)) pos[k++]=i;
                src_str(&c,&oa,nc,pos,s0,sizeof s0); src_str(&c,&ob,nc,pos,s1,sizeof s1);
                const char *o2 = opcode==OP_IEQ?"==":opcode==OP_IGE?">=":opcode==OP_ILT?"<":"!=";
                sb_putf(&body,"  %s%s = select(%s(0.0), %s(1.0), as_type<%s>(%s) %s as_type<%s>(%s));\n",
                        d,dmask,ftype(nc),ftype(nc), itype(nc),s0,o2,itype(nc),s1);
                break;
            }
            case OP_LD: { // texture load (no sampler): t.read(coord.xy, mip)
                Operand od,oaddr,ores; read_operand(&c,&od); read_operand(&c,&oaddr); read_operand(&c,&ores);
                operand_base(&c,&od,d,sizeof d); mask_to_str(od.mask,dmask);
                uint8_t xy[2]={0,1}; src_str(&c,&oaddr,2,xy,s0,sizeof s0);
                uint8_t z1[1]={2}; src_str(&c,&oaddr,1,z1,s1,sizeof s1);
                sb_putf(&body,"  %s%s = t%d.read(uint2(as_type<int2>(%s)), as_type<uint>(%s))%s;\n",
                        d,dmask, ores.idx[0], s0, s1, dmask);
                break;
            }
            case OP_SAMPLE_B: {
                Operand od,oc,ores,osmp,ob; read_operand(&c,&od); read_operand(&c,&oc); read_operand(&c,&ores); read_operand(&c,&osmp); read_operand(&c,&ob);
                operand_base(&c,&od,d,sizeof d); mask_to_str(od.mask,dmask);
                uint8_t uv[2]={0,1}; src_str(&c,&oc,2,uv,s0,sizeof s0);
                uint8_t b1[1]={0}; src_str(&c,&ob,1,b1,s1,sizeof s1);
                sb_putf(&body,"  %s%s = t%d.sample(s%d, %s, bias(%s))%s;\n", d,dmask, ores.idx[0], osmp.idx[0], s0, s1, dmask);
                break;
            }
            case OP_SAMPLE_C: case OP_SAMPLE_C_LZ: {
                Operand od,oc,ores,osmp,oref; read_operand(&c,&od); read_operand(&c,&oc); read_operand(&c,&ores); read_operand(&c,&osmp); read_operand(&c,&oref);
                operand_base(&c,&od,d,sizeof d); mask_to_str(od.mask,dmask);
                if (ores.idx[0] < 16) c.depth_res |= 1u << ores.idx[0];   // needs depth2d
                uint8_t uv[2]={0,1}; src_str(&c,&oc,2,uv,s0,sizeof s0);
                uint8_t r1[1]={0}; src_str(&c,&oref,1,r1,s1,sizeof s1);
                sb_putf(&body,"  %s%s = t%d.sample_compare(s%d, %s, %s);\n", d,dmask, ores.idx[0], osmp.idx[0], s0, s1);
                break;
            }
            case OP_RESINFO: { // GetDimensions
                Operand od,omip,ores; read_operand(&c,&od); read_operand(&c,&omip); read_operand(&c,&ores);
                operand_base(&c,&od,d,sizeof d); mask_to_str(od.mask,dmask);
                sb_putf(&body,"  %s%s = float4(float(t%d.get_width()), float(t%d.get_height()), 0.0, float(t%d.get_num_mip_levels()))%s;\n",
                        d,dmask, ores.idx[0],ores.idx[0],ores.idx[0], dmask);
                break;
            }
            case OP_SWITCH: { Operand o; read_operand(&c,&o); uint8_t p1[1]={0}; src_str(&c,&o,1,p1,s0,sizeof s0);
                sb_putf(&body,"  switch (as_type<int>(%s)) {\n", s0); break; }
            case OP_CASE: { Operand o; read_operand(&c,&o); int cv=0; memcpy(&cv,&o.imm[0],4);
                sb_putf(&body,"  case %d:\n", cv); break; }
            case OP_DEFAULT: sb_puts(&body,"  default:\n"); break;
            case OP_ENDSWITCH: sb_puts(&body,"  }\n"); break;
            case OP_IF: case OP_BREAKC: case OP_DISCARD: {
                Operand o; read_operand(&c,&o);
                uint8_t p1[1]={0}; src_str(&c,&o,1,p1,s0,sizeof s0);
                int nz = (op_tok >> 18) & 1; const char *cmp = nz ? "!=" : "==";
                if (opcode==OP_IF) sb_putf(&body,"  if (%s %s 0.0) {\n", s0, cmp);
                else if (opcode==OP_BREAKC) sb_putf(&body,"  if (%s %s 0.0) break;\n", s0, cmp);
                else sb_putf(&body,"  if (%s %s 0.0) discard_fragment();\n", s0, cmp);
                break;
            }
            case OP_ELSE: sb_puts(&body,"  } else {\n"); break;
            case OP_ENDIF: case OP_ENDLOOP: sb_puts(&body,"  }\n"); break;
            case OP_LOOP: sb_puts(&body,"  while (true) {\n"); break;
            case OP_BREAK: sb_puts(&body,"  break;\n"); break;
            case OP_CONTINUE: sb_puts(&body,"  continue;\n"); break;
            case OP_RET:
                sb_puts(&body, "  return out;\n");
                break;
            default:
                sb_putf(&body, "  // unhandled opcode %u\n", opcode);
                break;
        }
        c.p = next;   // resync to the instruction's declared length
    }

    // ---------- assemble MSL ----------
    SB out; memset(&out, 0, sizeof out);
    sb_puts(&out, "#include <metal_stdlib>\nusing namespace metal;\n");

    bool has_in = (c.in_used != 0);
    // structs (an empty [[stage_in]] struct is invalid, so only when there are inputs)
    if (!c.is_pixel) {
        if (has_in) {
            sb_puts(&out, "struct WGVSIn {\n");
            for (int i = 0; i < 32; i++) if (c.in_used & (1u<<i)) sb_putf(&out, "  float4 v%d [[attribute(%d)]];\n", i, i);
            sb_puts(&out, "};\n");
        }
        sb_puts(&out, "struct WGVSOut {\n");
        for (int i = 0; i < 32; i++) if (c.out_used & (1u<<i)) {
            if (i == c.out_pos_reg) sb_putf(&out, "  float4 o%d [[position]];\n", i);
            else sb_putf(&out, "  float4 o%d [[user(locn%d)]];\n", i, i);
        }
        sb_puts(&out, "};\n");
    } else if (has_in) {
        sb_puts(&out, "struct WGPSIn {\n");
        for (int i = 0; i < 32; i++) if (c.in_used & (1u<<i)) {
            if (c.in_siv_pos[i]) sb_putf(&out, "  float4 v%d [[position]];\n", i);
            else sb_putf(&out, "  float4 v%d [[user(locn%d)]];\n", i, i);
        }
        sb_puts(&out, "};\n");
    }
    if (c.is_pixel) {   // output struct: SV_TargetN -> [[color(N)]]  (supports MRT)
        sb_puts(&out, "struct WGPSOut {\n");
        for (int i = 0; i < 8; i++) if (c.out_used & (1u<<i)) sb_putf(&out, "  float4 o%d [[color(%d)]];\n", i, i);
        sb_puts(&out, "};\n");
    }

    // function signature (comma-managed so it works with or without stage_in)
    sb_puts(&out, c.is_pixel ? "fragment WGPSOut wg_ps_main(" : "vertex WGVSOut wg_vs_main(");
    bool first = true;
    if (has_in) { sb_putf(&out, "%s in [[stage_in]]", c.is_pixel ? "WGPSIn" : "WGVSIn"); first = false; }
    // Constant buffers live at Metal buffer 16+N (0..15 reserved for vertex buffers).
    for (int i = 0; i < 32; i++) if (c.cb_used & (1u<<i)) { sb_putf(&out, "%sconstant float4* cb%d [[buffer(%d)]]", first?"":", ", i, 16+i); first = false; }
    for (int i = 0; i < 16; i++) if (c.res_used & (1u<<i)) {
        const char *tt = (c.depth_res & (1u<<i)) ? "depth2d<float>" : "texture2d<float>";
        sb_putf(&out, "%s%s t%d [[texture(%d)]]", first?"":", ", tt, i, i); first = false;
    }
    for (int i = 0; i < 16; i++) if (c.samp_used & (1u<<i)) { sb_putf(&out, "%ssampler s%d [[sampler(%d)]]", first?"":", ", i, i); first = false; }
    sb_puts(&out, ") {\n");

    // register file + output
    for (int i = 0; i < c.ntemps; i++) sb_putf(&out, "  float4 r%d = float4(0.0);\n", i);
    sb_puts(&out, c.is_pixel ? "  WGPSOut out = {};\n" : "  WGVSOut out = {};\n");

    if (body.buf) sb_puts(&out, body.buf);
    // RET emits the return; add a fallback only if the body has none.
    bool has_ret = body.buf && strstr(body.buf, "return ");
    if (!has_ret) sb_puts(&out, "  return out;\n");
    sb_puts(&out, "}\n");

    free(body.buf);
    if (out_stage) *out_stage = c.is_pixel ? 'f' : 'v';
    return out.buf;
}

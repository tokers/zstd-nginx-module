#include "ngx_http_zstd_common.h"

static /* const */ char kEncoding[] = "zstd";
static const size_t kEncodingLen = 4;

static ngx_int_t check_accept_encoding(ngx_http_request_t* req) {
  ngx_table_elt_t* accept_encoding_entry;
  ngx_str_t* accept_encoding;
  u_char* cursor;
  u_char* end;
  u_char before;
  u_char after;

  accept_encoding_entry = req->headers_in.accept_encoding;
  if (accept_encoding_entry == NULL) return NGX_DECLINED;
  accept_encoding = &accept_encoding_entry->value;

  if (accept_encoding->len < kEncodingLen) return NGX_DECLINED;

  cursor = accept_encoding->data;
  end = cursor + accept_encoding->len;
  while (1) {
    u_char digit;
    /* It would be an idiotic idea to rely on compiler to produce performant
       binary, that is why we just do -1 at every call site. */
    cursor = ngx_strcasestrn(cursor, kEncoding, kEncodingLen - 1);
    if (cursor == NULL) return NGX_DECLINED;
    before = (cursor == accept_encoding->data) ? ' ' : cursor[-1];
    cursor += kEncodingLen;
    after = (cursor >= end) ? ' ' : *cursor;
    if (before != ',' && before != ' ') continue;
    if (after != ',' && after != ' ' && after != ';') continue;

    /* Check for ";q=0[.[0[0[0]]]]" */
    while (*cursor == ' ') cursor++;
    if (*(cursor++) != ';') break;
    while (*cursor == ' ') cursor++;
    if (*(cursor++) != 'q') break;
    while (*cursor == ' ') cursor++;
    if (*(cursor++) != '=') break;
    while (*cursor == ' ') cursor++;
    if (*(cursor++) != '0') break;
    if (*(cursor++) != '.') return NGX_DECLINED; /* ;q=0, */
    digit = *(cursor++);
    if (digit < '0' || digit > '9') return NGX_DECLINED; /* ;q=0., */
    if (digit > '0') break;
    digit = *(cursor++);
    if (digit < '0' || digit > '9') return NGX_DECLINED; /* ;q=0.0, */
    if (digit > '0') break;
    digit = *(cursor++);
    if (digit < '0' || digit > '9') return NGX_DECLINED; /* ;q=0.00, */
    if (digit > '0') break;
    return NGX_DECLINED; /* ;q=0.000 */
  }
  return NGX_OK;
}

ngx_int_t ngx_http_zstd_check_request(ngx_http_request_t* req) {
  if (req != req->main) return NGX_DECLINED;
  if (check_accept_encoding(req) != NGX_OK) return NGX_DECLINED;
  req->gzip_tested = 1;
  req->gzip_ok = 0;
  return NGX_OK;
}

#ifndef _ENDIAN_H_
#define _ENDIAN_H_

#include <endian.h>
#include <stdlib.h>

#if _BYTE_ORDER == _LITTLE_ENDIAN
#define __LITTLE_ENDIAN__ 1
#else
#define __BIG_ENDIAN__ 1
#endif

#endif

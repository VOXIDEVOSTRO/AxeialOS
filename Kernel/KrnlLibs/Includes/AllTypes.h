#pragma once

#define __StandardLIBC__

#ifdef __StandardLIBC__

// #    include <fenv.h>
#    include <float.h>
#    include <iso646.h>
#    include <limits.h>
#    include <stdalign.h>
#    include <stdarg.h>
#    include <stdatomic.h>
#    include <stdbool.h>
#    include <stddef.h>
#    include <stdint.h>
#    include <stdnoreturn.h>

#else

#    include "LocalTypes/__aln__.h"
#    include "LocalTypes/__args__.h"
#    include "LocalTypes/__bool__.h"
#    include "LocalTypes/__def__.h"
#    include "LocalTypes/__fenv__.h"
#    include "LocalTypes/__flt__.h"
#    include "LocalTypes/__i646__.h"
#    include "LocalTypes/__int__.h"
#    include "LocalTypes/__lims__.h"
#    include "LocalTypes/__noret__.h"

#endif
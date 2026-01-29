#include <KrnFont.h>
#include <__AXEKCONF__.h>

#ifdef LOGKRNFONTSC_Debug
#    define LOGKRNFONTSC_PDebug(fmt, ...) PDebug("[KERNEL>>KrnFonts.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGKRNFONTSC_PDebug(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGKRNFONTSC_Logs
#    define LOGKRNFONTSC_PError(fmt, ...) PError("[KERNEL>>KrnFonts.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGKRNFONTSC_PError(fmt, ...)                                                          \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGKRNFONTSC_Logs
#    define LOGKRNFONTSC_PWarn(fmt, ...) PWarn("[KERNEL>>KrnFonts.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGKRNFONTSC_PWarn(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGKRNFONTSC_Logs
#    define LOGKRNFONTSC_PInfo(fmt, ...) PInfo("[KERNEL>>KrnFonts.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGKRNFONTSC_PInfo(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGKRNFONTSC_Logs
#    define LOGKRNFONTSC_PSuccess(fmt, ...) PSuccess("[KERNEL>>KrnFonts.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGKRNFONTSC_PSuccess(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

void
DisplayChar(uint32_t* __FrameBuffer__,
            uint32_t  __FrameBufferW__,
            uint32_t  __PosX__,
            uint32_t  __PosY__,
            char      __Char__,
            uint32_t  __32bitColor__)
{
    /* Retrieve the 16-byte bitmap for this character */
    const uint8_t* Character = KrnlFontMap[(uint8_t)__Char__];

    /* Render each row of the 8x16 character */
    for (int MapRow = 0; MapRow < FontH; MapRow++)
    {
        uint8_t Line = Character[MapRow];

        /* Process each column (bit) in the row */
        for (int Column = 0; Column < FontW; Column++)
        {
            /* Check if bit is set (MSB is leftmost pixel) */

            if (Line & (0x80 >> Column))
            {
                /* Calculate framebuffer offset and set pixel */
                __FrameBuffer__[(__PosY__ + MapRow) * __FrameBufferW__ + (__PosX__ + Column)] =
                    __32bitColor__;
            }
        }
    }
}

void
DisplayString(uint32_t*   __FrameBuffer__,
              uint32_t    __FrameBufferW__,
              uint32_t    __PosX__,
              uint32_t    __PosY__,
              const char* __String__,
              uint32_t    __32bitColor__)
{
    uint32_t PosX = __PosX__;

    /* Render each character in sequence */
    while (*__String__)
    {
        DisplayChar(__FrameBuffer__, __FrameBufferW__, PosX, __PosY__, *__String__, __32bitColor__);
        PosX += FontW; /* Advance to next character position */
        __String__++;  /* Move to next character in string */
    }
}

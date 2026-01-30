// #define LOGMACROC_Debug
// #define LOGMACROC_Logs

#ifdef LOGMACROC_Debug
#    define LOGMACROC_PDebug(fmt, ...) PDebug("[KERNEL>>LOGMACRO.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMACROC_PDebug(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMACROC_Logs
#    define LOGMACROC_PError(fmt, ...) PError("[KERNEL>>LOGMACRO.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMACROC_PError(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMACROC_Logs
#    define LOGMACROC_PWarn(fmt, ...) PWarn("[KERNEL>>LOGMACRO.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMACROC_PWarn(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMACROC_Logs
#    define LOGMACROC_PInfo(fmt, ...) PInfo("[KERNEL>>LOGMACRO.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMACROC_PInfo(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGMACROC_Logs
#    define LOGMACROC_PSuccess(fmt, ...) PSuccess("[KERNEL>>LOGMACRO.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGMACROC_PSuccess(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif
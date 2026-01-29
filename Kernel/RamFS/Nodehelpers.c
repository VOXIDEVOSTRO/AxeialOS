#include <KHeap.h>
#include <RamFs.h>
#include <__AXEKCONF__.h>

#ifdef LOGNODEHELPERSC_Debug
#    define LOGNODEHELPERSC_PDebug(fmt, ...) PDebug("[KERNEL>>Nodehelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGNODEHELPERSC_PDebug(fmt, ...)                                                       \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGNODEHELPERSC_Logs
#    define LOGNODEHELPERSC_PError(fmt, ...) PError("[KERNEL>>Nodehelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGNODEHELPERSC_PError(fmt, ...)                                                       \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGNODEHELPERSC_Logs
#    define LOGNODEHELPERSC_PWarn(fmt, ...) PWarn("[KERNEL>>Nodehelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGNODEHELPERSC_PWarn(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGNODEHELPERSC_Logs
#    define LOGNODEHELPERSC_PInfo(fmt, ...) PInfo("[KERNEL>>Nodehelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGNODEHELPERSC_PInfo(fmt, ...)                                                        \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGNODEHELPERSC_Logs
#    define LOGNODEHELPERSC_PSuccess(fmt, ...)                                                     \
        PSuccess("[KERNEL>>Nodehelpers.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGNODEHELPERSC_PSuccess(fmt, ...)                                                     \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

RamFSNode*
RamFSCreateNode(const char* __Name__, RamFSNodeType __Type__)
{
    RamFSNode* Node = (RamFSNode*)KMalloc(sizeof(RamFSNode));

    if (Probe_IF_Error(Node) || !Node)
    {
        PushError("RamFSCreateNode",
                  LOGNODEHELPERSC_PError,
                  "Failed to allocate memory for RamFS node",
                  Pointer_TO_Error(Node));
        return Error_TO_Pointer(-BadAllocation);
    }

    Node->Next = 0;                                 /**< Next sibling (unused) */
    for (uint32_t I = 0; I < RamFSMaxChildren; I++) /**< Initialize child array */
    {
        Node->Children[I] = 0;
    }
    Node->ChildCount = 0;              /**< No children initially */
    Node->Name       = __Name__;       /**< Node name */
    Node->Type       = __Type__;       /**< File or directory */
    Node->Size       = 0;              /**< Size (0 for directories) */
    Node->Data       = 0;              /**< Data pointer (NULL for directories) */
    Node->Magic      = RamFSNodeMagic; /**< Integrity check */

    return Node;
}

void
RamFSAddChild(RamFSNode* __Parent__, RamFSNode* __Child__, SysErr* __Err__)
{
    if (Probe_IF_Error(__Parent__) || !__Parent__ || Probe_IF_Error(__Child__) || !__Child__)
    {
        SlotError(__Err__, -BadArguments);
        PushError(
            "RamFSAddChild", LOGNODEHELPERSC_PError, "Bad args to RamFSAddChild", -BadArguments);
        return;
    }

    if (__Parent__->ChildCount < RamFSMaxChildren)
    {
        __Parent__->Children[__Parent__->ChildCount++] = __Child__;
    }
}

RamFSNode*
RamFSEnsureRoot(void)
{
    if (!RamFS.Root)
    {
        /* Root name is "/" (literal string, not allocated) */
        RamFS.Root = RamFSCreateNode("/", RamFSNode_Directory);
    }
    return RamFS.Root;
}

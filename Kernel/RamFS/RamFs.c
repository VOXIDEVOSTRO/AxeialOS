#include <KHeap.h>
#include <RamFs.h>
#include <__AXEKCONF__.h>

#ifdef LOGRAMFSC_Debug
#    define LOGRAMFSC_PDebug(fmt, ...) PDebug("[KERNEL>>RamFs.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGRAMFSC_PDebug(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGRAMFSC_Logs
#    define LOGRAMFSC_PError(fmt, ...) PError("[KERNEL>>RamFs.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGRAMFSC_PError(fmt, ...)                                                             \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGRAMFSC_Logs
#    define LOGRAMFSC_PWarn(fmt, ...) PWarn("[KERNEL>>RamFs.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGRAMFSC_PWarn(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGRAMFSC_Logs
#    define LOGRAMFSC_PInfo(fmt, ...) PInfo("[KERNEL>>RamFs.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGRAMFSC_PInfo(fmt, ...)                                                              \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

#ifdef LOGRAMFSC_Logs
#    define LOGRAMFSC_PSuccess(fmt, ...) PSuccess("[KERNEL>>RamFs.c] " fmt, ##__VA_ARGS__)
#else
#    define LOGRAMFSC_PSuccess(fmt, ...)                                                           \
        do                                                                                         \
        {                                                                                          \
        } while (0)
#endif

RamFSContext RamFS = {
    .Root  = 0,         /**< Root directory node */
    .Magic = RamFSMagic /**< Magic number for context validation */
};

RamFSNode*
RamFSAttachPath(RamFSNode*     __Root__,
                const char*    __FullPath__,
                RamFSNodeType  __Type__,
                const uint8_t* __Data__,
                uint32_t       __Size__)
{
    SysErr  err;
    SysErr* Error = &err;

    if (Probe_IF_Error(__Root__) || !__Root__ || Probe_IF_Error(__FullPath__) || !__FullPath__)
    {
        PushError(
            "RamFSAttachPath", LOGRAMFSC_PError, "Bad args to RamFSAttachPath", -BadArguments);
        return Error_TO_Pointer(-BadArguments);
    }

    if (__FullPath__[0] != '/')
    {
        PushError("RamFSAttachPath", LOGRAMFSC_PError, "Path not rooted", -NotRooted);
        return Error_TO_Pointer(-NotRooted);
    }

    const char* PathSegment = __FullPath__;
    PathSegment++; /*Skip leading slash*/

    RamFSNode*  Cur      = __Root__;
    const char* SegStart = PathSegment;

    /*Create/find intermediate directories*/
    while (*PathSegment)
    {
        if (*PathSegment == '/')
        {
            uint32_t SegLen = (uint32_t)(PathSegment - SegStart);
            if (SegLen == 0)
            {
                PathSegment++;
                SegStart = PathSegment;
                continue;
            }

            /*Find existing directory child*/
            RamFSNode* Next = 0;
            for (uint32_t I = 0; I < Cur->ChildCount; I++)
            {
                RamFSNode* C = Cur->Children[I];
                if (Probe_IF_Error(C) || !C || C->Type != RamFSNode_Directory)
                {
                    continue;
                }

                uint32_t K = 0;
                for (; K < SegLen && C->Name[K] && C->Name[K] == SegStart[K]; K++)
                    ;
                if (K == SegLen && C->Name[K] == '\0')
                {
                    Next = C;
                    break;
                }
            }

            /*Create if missing*/
            if (Probe_IF_Error(Next) || !Next)
            {
                char* Name = (char*)KMalloc(SegLen + 1);
                if (Probe_IF_Error(Name) || !Name)
                {
                    PushError("RamFSAttachPath",
                              LOGRAMFSC_PError,
                              "Failed to allocate memory for RamFS node name",
                              Pointer_TO_Error(Name));
                    return Error_TO_Pointer(-BadAllocation);
                }

                for (uint32_t I = 0; I < SegLen; I++)
                {
                    Name[I] = SegStart[I];
                }
                Name[SegLen] = '\0';

                Next = RamFSCreateNode(Name, RamFSNode_Directory);
                if (Probe_IF_Error(Next) || !Next)
                {
                    PushError("RamFSAttachPath",
                              LOGRAMFSC_PError,
                              "Failed to create RamFS node",
                              Pointer_TO_Error(Next));
                    return Error_TO_Pointer(-BadAllocation);
                }

                RamFSAddChild(Cur, Next, Error);
            }

            Cur = Next;
            PathSegment++;
            SegStart = PathSegment;
            continue;
        }
        PathSegment++;
    }

    /*Leaf segment name*/
    uint32_t LeafLen = (uint32_t)(PathSegment - SegStart);
    if (LeafLen == 0)
    {
        return Cur;
    }

    /*Find existing leaf*/
    RamFSNode* Leaf = 0;
    for (uint32_t I = 0; I < Cur->ChildCount; I++)
    {
        RamFSNode* C = Cur->Children[I];
        if (Probe_IF_Error(C) || !C)
        {
            continue;
        }

        uint32_t K = 0;
        for (; K < LeafLen && C->Name[K] && C->Name[K] == SegStart[K]; K++)
            ;
        if (K == LeafLen && C->Name[K] == '\0')
        {
            Leaf = C;
            break;
        }
    }

    /*Create leaf if missing*/
    if (Probe_IF_Error(Leaf) || !Leaf)
    {
        char* Name = (char*)KMalloc(LeafLen + 1);
        if (Probe_IF_Error(Name) || !Name)
        {
            PushError("RamFSAttachPath",
                      LOGRAMFSC_PError,
                      "Failed to allocate memory for RamFS leaf name",
                      Pointer_TO_Error(Name));
            return Error_TO_Pointer(-BadAllocation);
        }

        for (uint32_t I = 0; I < LeafLen; I++)
        {
            Name[I] = SegStart[I];
        }
        Name[LeafLen] = '\0';

        Leaf = RamFSCreateNode(Name, __Type__);
        if (Probe_IF_Error(Leaf) || !Leaf)
        {
            PushError("RamFSAttachPath",
                      LOGRAMFSC_PError,
                      "Failed to create RamFS leaf node",
                      Pointer_TO_Error(Leaf));
            return Error_TO_Pointer(-BadAllocation);
        }

        RamFSAddChild(Cur, Leaf, Error);
    }

    if (__Type__ == RamFSNode_File)
    {
        Leaf->Data = __Data__;
        Leaf->Size = __Size__;
    }

    return Leaf;
}

RamFSNode*
RamFSMount(const void* __Image__, size_t __Length__)
{
    RamFSNode* Root = RamFSEnsureRoot();
    if (Probe_IF_Error(Root) || !Root || Probe_IF_Error(__Image__) || !__Image__ || __Length__ == 0)
    {
        PushError("RamFSMount", LOGRAMFSC_PError, "Bad args to RamFSMount", -BadArguments);
        return Error_TO_Pointer(-BadArguments);
    }

    const uint8_t* Buf = (const uint8_t*)__Image__;
    uint32_t       Off = 0;

    while (Off + 6 <= (uint32_t)__Length__)
    {
        /*Align to 4-byte boundary for header*/
        Off = CpioAlignUp(Off, CpioAlign);
        if (Off + 110 > (uint32_t)__Length__)
        {
            break;
        }

        /*Check magic "070701"*/
        const char* Magic = (const char*)(Buf + Off);
        if (!(Magic[0] == '0' && Magic[1] == '7' && Magic[2] == '0' && Magic[3] == '7' &&
              Magic[4] == '0' && Magic[5] == '1'))
        {
            break; /*bad magic*/
        }

        /*Header field pointers*/
        const char* Mode     = (const char*)(Buf + Off + 14);
        const char* FileSize = (const char*)(Buf + Off + 54);
        const char* NameSize = (const char*)(Buf + Off + 94);

        Off += 110; /*Past header*/

        uint32_t NameLen  = CpioParseHex(NameSize); /*Includes NUL*/
        uint32_t DataLen  = CpioParseHex(FileSize);
        uint32_t ModeBits = CpioParseHex(Mode);

        /*Name string*/
        uint32_t NameOff = Off;
        uint32_t NameEnd = NameOff + NameLen;
        if (NameEnd > (uint32_t)__Length__)
        {
            break;
        }

        const char* NamePtr = (const char*)(Buf + NameOff);

        /*Trailer terminator*/
        if (NameLen >= 11)
        {
            uint32_t Match = 1;
            for (uint32_t I = 0; I < 11; I++)
            {
                if (NamePtr[I] != CpioTrailer[I])
                {
                    Match = 0;
                    break;
                }
            }
            if (Match)
            {
                break;
            }
        }

        /*Advance to data (aligned after name)*/
        Off = CpioAlignUp(NameEnd, CpioAlign);

        /*Determine node type: dir (040000) or file (0100000)*/
        RamFSNodeType NType = RamFSNode_File;
        if ((ModeBits & 0xF000) == 0x4000)
        {
            NType = RamFSNode_Directory;
        }
        else if ((ModeBits & 0xF000) == 0x8000)
        {
            NType = RamFSNode_File;
        }

        /*Data pointer for files*/
        const uint8_t* DataPtr = 0;
        if (NType == RamFSNode_File)
        {
            uint32_t DataOff = Off;
            uint32_t DataEnd = DataOff + DataLen;
            if (DataEnd > (uint32_t)__Length__)
            {
                break;
            }

            DataPtr = Buf + DataOff;

            /*Advance past data to next header (aligned)*/
            Off = CpioAlignUp(DataEnd, CpioAlign);
        }

        /*Build absolute path: cpio names are relative (no leading slash)*/
        uint32_t RawLen = 0;
        while (NamePtr[RawLen] != '\0')
        {
            RawLen++;
        }

        char* FullPath = (char*)KMalloc(RawLen + 2);
        if (Probe_IF_Error(FullPath) || !FullPath)
        {
            PushError("RamFSMount",
                      LOGRAMFSC_PError,
                      "Failed to allocate memory for RamFS full path",
                      Pointer_TO_Error(FullPath));
            return Error_TO_Pointer(-NotCanonical);
        }

        FullPath[0] = '/';
        for (uint32_t I = 0; I < RawLen; I++)
        {
            FullPath[I + 1] = NamePtr[I];
        }
        FullPath[RawLen + 1] = '\0';

        /*Attach into hierarchy*/
        (void)RamFSAttachPath(Root, FullPath, NType, DataPtr, DataLen);
    }

    return RamFS.Root;
}

RamFSNode*
RamFSLookup(RamFSNode* __Root__, const char* __Path__)
{
    if (Probe_IF_Error(__Root__) || !__Root__ || Probe_IF_Error(__Path__) || !__Path__ ||
        __Path__[0] != '/')
    {
        PushError("RamFSLookup", LOGRAMFSC_PError, "Bad args to RamFSLookup", -BadArguments);
        return Error_TO_Pointer(-BadArguments);
    }

    const char* PathSegment = __Path__;
    PathSegment++; /*Skip leading*/

    RamFSNode*  Cur      = __Root__;
    const char* SegStart = PathSegment;

    while (*PathSegment)
    {
        if (*PathSegment == '/')
        {
            uint32_t SegLen = (uint32_t)(PathSegment - SegStart);
            if (SegLen == 0)
            {
                PathSegment++;
                SegStart = PathSegment;
                continue;
            }

            RamFSNode* Next = 0;
            for (uint32_t I = 0; I < Cur->ChildCount; I++)
            {
                RamFSNode* C = Cur->Children[I];
                if (Probe_IF_Error(C) || !C)
                {
                    continue;
                }

                uint32_t K = 0;
                for (; K < SegLen && C->Name[K] && C->Name[K] == SegStart[K]; K++)
                    ;
                if (K == SegLen && C->Name[K] == '\0')
                {
                    Next = C;
                    break;
                }
            }

            if (Probe_IF_Error(Next) || !Next)
            {
                PushError("RamFSLookup",
                          LOGRAMFSC_PError,
                          "No such path segment",
                          Pointer_TO_Error(Next));
                return Error_TO_Pointer(-Dangling);
            }

            Cur = Next;
            PathSegment++;
            SegStart = PathSegment;
            continue;
        }
        PathSegment++;
    }

    /*Leaf segment*/
    uint32_t LeafLen = (uint32_t)(PathSegment - SegStart);
    if (LeafLen == 0)
    {
        return Cur;
    }

    for (uint32_t I = 0; I < Cur->ChildCount; I++)
    {
        RamFSNode* C = Cur->Children[I];
        if (Probe_IF_Error(C) || !C)
        {
            continue;
        }

        uint32_t K = 0;
        for (; K < LeafLen && C->Name[K] && C->Name[K] == SegStart[K]; K++)
            ;
        if (K == LeafLen && C->Name[K] == '\0')
        {
            return C;
        }
    }

    PushError("RamFSLookup", LOGRAMFSC_PError, "No such file or directory", -NoSuch);
    return Error_TO_Pointer(-NoSuch);
}
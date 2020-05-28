/** @file
 * lpc-dec - LPC decoder from a Saleae Logic analyzer capture.
 */

/*
 * Copyright (C) 2020 Alexander Eichner <alexander.eichner@campus.tu-berlin.de>
 *
 * This program is free software: you can redistribute it and/or modify  
 * it under the terms of the GNU General Public License as published by  
 * the Free Software Foundation, version 3.
 *
 * This program is distributed in the hope that it will be useful, but 
 * WITHOUT ANY WARRANTY; without even the implied warranty of 
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU 
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License 
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */


/*********************************************************************************************************************************
*   Header Files                                                                                                                 *
*********************************************************************************************************************************/

#include <getopt.h>
#include <inttypes.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <errno.h>


/*********************************************************************************************************************************
*   Defined Constants And Macros                                                                                                 *
*********************************************************************************************************************************/

/** @name Supported LAD[3:0] values for the START condition.
 * @{ */
/** Start of a target cycle. */
#define LPC_DEC_START_TARGET_CYCLE              0x0
/** Reserved value. */
#define LPC_DEC_START_RSVD                      0x1
/** Grant for busmaster 0. */
#define LPC_DEC_START_BUSMASTER_GRANT_0         0x2
/** Grant for busmaster 1. */
#define LPC_DEC_START_BUSMASTER_GRANT_1         0x3
/** Stop/Abort. */
#define LPC_DEC_START_ABORT                     0xf
/** @} */

/** @name Cycle type and direction.
 * @{ */
/** I/O transfer. */
#define LPC_DEC_CYC_TYPE_IO                     0x0
/** Memory transfer. */
#define LPC_DEC_CYC_TYPE_MEM                    0x1
/** DMA transfer. */
#define LPC_DEC_CYC_TYPE_DMA                    0x2
/** RESERVED transfer (illegal). */
#define LPC_DEC_CYC_TYPE_RSVD                   0x3
/** Extracts the cycle type from the given LAD value. */
#define LPC_DEC_CYC_TYPE_GET(a_Lad)             (((a_Lad) & 0xc) >> 2)

/** Cycle read direction. */
#define LPC_DEC_CYC_DIR_READ                    0
/** Cycle write direction. */
#define LPC_DEC_CYC_DIR_WRITE                   1
/** Checks whether the given LAD value contains a read cycle (must be write otherwise). */
#define LPC_DEC_CYC_DIR_IS_READ(a_Lad)          (((a_Lad) & 0x2) == LPC_DEC_CYC_DIR_READ)
/** @} */

/*********************************************************************************************************************************
*   Structures and Typedefs                                                                                                      *
*********************************************************************************************************************************/


/**
 * File buffered reader.
 */
typedef struct LPCDECFILEBUFREAD
{
    /** The file handle. */
    FILE                        *pFile;
    /** Current amount of data in the buffer. */
    size_t                      cbData;
    /** Where to read next from the buffer. */
    uint32_t                    offBuf;
    /** Error flag. */
    uint8_t                     fError;
    /** Eos flag. */
    uint8_t                     fEos;
    /** Buffered data. */
    uint8_t                     abBuf[64 * 1024];
} LPCDECFILEBUFREAD;
/** Pointer to a file buffered reader. */
typedef LPCDECFILEBUFREAD *PLPCDECFILEBUFREAD;
/** Pointer to a const file buffered reader. */
typedef const LPCDECFILEBUFREAD *PCLPCDECFILEBUFREAD;


/**
 * Current LPC decoder state.
 */
typedef enum LPCDECSTATE
{
    /** Invalid state, do not use. */
    LPCDECSTATE_INVALID = 0,
    /** Waiting for LFRAME# to be asserted. */
    LPCDECSTATE_LFRAME_WAIT_ASSERTED,
    /** Currently in a start condition. */
    LPCDECSTATE_START,
    /** Address phase, number of cycles depends on the type. */
    LPCDECSTATE_ADDR,
    /** Data phase, number of cycles depends on the type. */
    LPCDECSTATE_DATA,
    /** Turn Around phase. */
    LPCDECSTATE_TAR,
    /** SYNC phase. */
    LPCDECSTATE_SYNC,
    /** 32bit hack. */
    LPCDECSTATE_32BIT_HACK = 0x7fffffff
} LPCDECSTATE;


/**
 * LPC decoder state.
 */
typedef struct LPCDEC
{
    /** Bit number for the LCLK signal. */
    uint8_t                     u8BitLClk;
    /** Bit number for the LFRAME# signal. */
    uint8_t                     u8BitLFrame;
    /** Bit number for the LAD[0] signal. */
    uint8_t                     u8BitLad0;
    /** Bit number for the LAD[1] signal. */
    uint8_t                     u8BitLad1;
    /** Bit number for the LAD[2] signal. */
    uint8_t                     u8BitLad2;
    /** Bit number for the LAD[3] signal. */
    uint8_t                     u8BitLad3;
    /** The next state to write into. */
    uint32_t                    idxState;
    /** LPC decoder states we've gone through. */
    LPCDECSTATE                 aenmState[9]; /* Host memory firmware reads/writes go through the most states + one for the inital LFRAME assert wait state. */
    /** Sequence number when the cycle started. */
    uint64_t                    uSeqNoCycle;
    /** Last clock value seen. */
    uint8_t                     fClkLast;
    /** Last seen value on LAD[3:0] when LFRAME# was asserted. */
    uint8_t                     bStartLast;
    /** Current cycle type. */
    uint8_t                     bTyp;
    /** Flag whether we are currently in a write cycle. */
    uint8_t                     fWrite;
    /** Number of address cycles left. */
    uint8_t                     cAddrCycles;
    /** Number of data cycles. */
    uint8_t                     cDataCycles;
    /** Current data cycle. */
    uint8_t                     iDataCycle;
    /** Number of TAR cycles left. */
    uint8_t                     cTarCycles;
    /** The address being constructed. */
    uint32_t                    u32Addr;
    /** The data being consturcted during the data phase. */
    uint8_t                     bData;
} LPCDEC;
/** Pointer to a LPC decoder state. */
typedef LPCDEC *PLPCDEC;
/** Pointer to a const LPC decoder state. */
typedef const LPCDEC *PCLPCDEC;


/*********************************************************************************************************************************
*   Global Variables                                                                                                             *
*********************************************************************************************************************************/

/** Flag whether verbose mode is enabled. */
static uint8_t g_fVerbose = 0;

/**
 * Available options for lpc-dec.
 */
static struct option g_aOptions[] =
{
    {"input",   required_argument, 0, 'i'},
    {"verbose", no_argument,       0, 'v'},

    {"help",    no_argument,       0, 'H'},
    {0, 0, 0, 0}
};


/*********************************************************************************************************************************
*   Internal Functions                                                                                                           *
*********************************************************************************************************************************/


/**
 * Creates a new buffered file reader from the given filename.
 *
 * @returns Status code.
 * @param   ppBufFile               Where to store the pointer to the buffered file reader on success.
 * @param   pszFilename             The file to load.
 */
static int lpcDecFileBufReaderCreate(PLPCDECFILEBUFREAD *ppBufFile, const char *pszFilename)
{
    int rc = 0;
    FILE *pFile = fopen(pszFilename, "rb");
    if (pFile)
    {
        PLPCDECFILEBUFREAD pBufFile = (PLPCDECFILEBUFREAD)calloc(1, sizeof(*pBufFile));
        if (pBufFile)
        {
            pBufFile->pFile  = pFile;
            pBufFile->cbData = 0;
            pBufFile->offBuf = 0;
            pBufFile->fError = 0;
            pBufFile->fEos   = 0;

            /* Read in the first chunk. */
            size_t cbRead = fread(&pBufFile->abBuf[0], 1, sizeof(pBufFile->abBuf), pFile);
            if (cbRead)
            {
                pBufFile->cbData = cbRead;
                *ppBufFile = pBufFile;
                return 0;
            }
            else
                rc = -1;
        }
        else
            rc = -1;

        fclose(pFile);
    }
    else
        rc = errno;

    return rc;
}


/**
 * Closes the given buffered file reader.
 *
 * @returns nothing.
 * @param   pBufFile                The buffered file reader to close.
 */
static void lpcDecFileBufReaderClose(PLPCDECFILEBUFREAD pBufFile)
{
    fclose(pBufFile->pFile);
    free(pBufFile);
}


/**
 * Returns whether the given buffered file reader has run into an error.
 *
 * @returns Flag whether the has run into an error.
 * @param   pBufFile                The buffered file reader to check.
 */
static inline uint8_t lpcDecFileBufReaderHasError(PCLPCDECFILEBUFREAD pBufFile)
{
    return pBufFile->fError;
}


/**
 * Returns whether the given buffered file reader has reached EOS.
 *
 * @returns Flag whether the has reached EOS.
 * @param   pBufFile                The buffered file reader to check.
 */
static inline uint8_t lpcDecFileBufReaderHasEos(PCLPCDECFILEBUFREAD pBufFile)
{
    return pBufFile->fEos;
}


/**
 * Ensures that there is enough data to read.
 *
 * @returns Status code.
 * @param   pBufFile                The buffered file reader.
 * @param   cbData                  Amount of bytes which should be available.
 */
static int lpcDecFileBufReaderEnsureData(PLPCDECFILEBUFREAD pBufFile, size_t cbData)
{
    if (pBufFile->offBuf + cbData <= pBufFile->cbData)
        return 0;

    /* Move all the remaining data to the front and fill up the free space. */
    size_t cbRem = pBufFile->cbData - pBufFile->offBuf;
    memmove(&pBufFile->abBuf[0], &pBufFile->abBuf[pBufFile->offBuf], cbRem);

    /* Try reading in more data. */
    size_t cbRead = fread(&pBufFile->abBuf[cbRem], 1, sizeof(pBufFile->abBuf) - cbRem, pBufFile->pFile);
    pBufFile->cbData = cbRead + cbRem;
    pBufFile->offBuf = 0;
    if (!cbRead)
        pBufFile->fEos = 1;

    return 0;
}


/**
 * Returns the next byte from the given buffered file reader.
 *
 * @returns Next byte value (0xff on error and error condition needs to get checked using lpcDecFileBufReaderHasError()).
 * @param   pBufFile                The buffered file reader.
 */
static uint8_t lpcDecFileBufReaderGetU8(PLPCDECFILEBUFREAD pBufFile)
{
    /* Ensure that there is no error and there is least one byte to read. */
    if (   lpcDecFileBufReaderHasError(pBufFile)
        || lpcDecFileBufReaderEnsureData(pBufFile, sizeof(uint8_t)))
        return UINT8_MAX;

    return pBufFile->abBuf[pBufFile->offBuf++];
}


/**
 * Returns the next 64bit unsigned integer from the given buffered file reader.
 *
 * @returns Next byte value (0xff on error and error condition needs to get checked using lpcDecFileBufReaderHasError()).
 * @param   pBufFile                The buffered file reader.
 */
static uint64_t lpcDecFileBufReaderGetU64(PLPCDECFILEBUFREAD pBufFile)
{
    /* Ensure that there is no error and there is least one byte to read. */
    if (   lpcDecFileBufReaderHasError(pBufFile)
        || lpcDecFileBufReaderEnsureData(pBufFile, sizeof(uint64_t)))
        return UINT64_MAX;

    uint64_t u64Val = *(uint64_t *)&pBufFile->abBuf[pBufFile->offBuf];
    pBufFile->offBuf += sizeof(uint64_t);
    return u64Val;
}


/**
 * Resets the given LPC decoder state to the initial state waiting for LFRAME# to be asserted.
 *
 * @returns nothing.
 * @param   pLpcDec                 The LPC decoder state.
 */
static void lpcDecStateReset(PLPCDEC pLpcDec)
{
    pLpcDec->idxState                     = 0;
    pLpcDec->u32Addr                      = 0;
    pLpcDec->bData                        = 0;
    pLpcDec->iDataCycle                   = 0;
    pLpcDec->aenmState[pLpcDec->idxState] = LPCDECSTATE_LFRAME_WAIT_ASSERTED;
}


/**
 * Initializes the given LPC state instance.
 *
 * @returns Status code.
 * @param   pLpcDec                 The LPC decoder state to initialize.
 * @param   u8BitClk                The bit number of the CLK signal in fed samples.
 * @param   u8BitLFrame             The bit number of the LFRAME# signal in fed samples.
 * @param   u8BitLad0               The bit number of the LAD[0] signal in fed samples.
 * @param   u8BitLad1               The bit number of the LAD[1] signal in fed samples.
 * @param   u8BitLad2               The bit number of the LAD[2] signal in fed samples.
 * @param   u8BitLad3               The bit number of the LAD[3] signal in fed samples.
 */
static int lpcDecStateInit(PLPCDEC pLpcDec, uint8_t u8BitClk, uint8_t u8BitLFrame,
                           uint8_t u8BitLad0, uint8_t u8BitLad1, uint8_t u8BitLad2, uint8_t u8BitLad3)
{
    pLpcDec->u8BitLClk    = u8BitClk;
    pLpcDec->u8BitLFrame  = u8BitLFrame;
    pLpcDec->u8BitLad0    = u8BitLad0;
    pLpcDec->u8BitLad1    = u8BitLad1;
    pLpcDec->u8BitLad2    = u8BitLad2;
    pLpcDec->u8BitLad3    = u8BitLad3;
    pLpcDec->fClkLast     = 0; /* We start with a low clock. */
    lpcDecStateReset(pLpcDec);
    return 0;
}


/**
 * Extracts the LAD[3:0] from the given sample and returns them as a nibble in an 8bit unsigned integer.
 */
static inline uint8_t lpcDecStateLadExtractFromSample(PCLPCDEC pLpcDec, uint8_t bSample)
{
    return   ((bSample & (1 << pLpcDec->u8BitLad0)) >> pLpcDec->u8BitLad0)
           | ((bSample & (1 << pLpcDec->u8BitLad1)) >> pLpcDec->u8BitLad1) << 1
           | ((bSample & (1 << pLpcDec->u8BitLad2)) >> pLpcDec->u8BitLad2) << 2
           | ((bSample & (1 << pLpcDec->u8BitLad3)) >> pLpcDec->u8BitLad3) << 3;
}


/**
 * Converts the given LPC decoder state enum to a human readable string.
 *
 * @returns String of the given state.
 * @param   enmState                The state to convert.
 */
static const char *lpcDecStateToStr(LPCDECSTATE enmState)
{
    switch (enmState)
    {
        case LPCDECSTATE_INVALID:
            return "<INVALID>";
        case LPCDECSTATE_LFRAME_WAIT_ASSERTED:
            return "WAIT_LFRAME_ASSERTED";
        case LPCDECSTATE_START:
            return "START";
        case LPCDECSTATE_ADDR:
            return "ADDR";
        case LPCDECSTATE_DATA:
            return "DATA";
        case LPCDECSTATE_TAR:
            return "TAR";
        case LPCDECSTATE_SYNC:
            return "SYNC";
        default:
            break;
    }

    return "<UNKNOWN>";
}


/**
 * Dumps the current state of the LPC decoder.
 *
 * @returns nothing.
 * @param   pLpcDec                 The LPC decoder state.
 * @param   fAbort                  Flag whether an abort was detected.
 */
static void lpcDecStateDump(PCLPCDEC pLpcDec, uint8_t fAbort)
{
    const char *pszTyp = "<INVALID>";
    const char *pszDir = pLpcDec->fWrite ? "Write" : "Read ";

    switch (pLpcDec->bTyp)
    {
        case LPC_DEC_CYC_TYPE_IO:
            pszTyp = "I/O";
            break;
        case LPC_DEC_CYC_TYPE_MEM:
            pszTyp = "Mem";
            break;
        case LPC_DEC_CYC_TYPE_DMA:
            pszTyp = "DMA";
            break;
        case LPC_DEC_CYC_TYPE_RSVD:
            pszTyp = "RESERVED";
            break;
        default:
            printf("Wait WHAT?\n");
            break;
    }

    printf("%" PRIu64 ": %s %s 0x%04x: 0x%02x ", pLpcDec->uSeqNoCycle, pszTyp, pszDir,
                                                 pLpcDec->u32Addr, pLpcDec->bData);
    if (g_fVerbose)
    {
        /* Walk the encountered state machine chain. */
        for (uint32_t i = 0; i < pLpcDec->idxState; i++)
            printf("%s -> ", lpcDecStateToStr(pLpcDec->aenmState[i]));
        printf("%s", lpcDecStateToStr(pLpcDec->aenmState[pLpcDec->idxState]));
        if (fAbort)
            printf(" -> <ABORT>");
    }
    else if (fAbort)
        printf("<ABORT>");
    printf("\n");
}


/**
 * Sets a new LPC deocder state.
 *
 * @returns nothing.
 * @param   pLpcDec                 The LPC decoder state.
 * @param   enmState                The new state to set.
 */
static void lpcDecStateSet(PLPCDEC pLpcDec, LPCDECSTATE enmState)
{
    pLpcDec->idxState++;
    pLpcDec->aenmState[pLpcDec->idxState] = enmState;
}


/**
 * Advances the LPC deocder state machine to the next state.
 *
 * @returns nothing.
 * @param   pLpcDec                 The LPC decoder state.
 */
static void lpcDecStateSampleAdvance(PLPCDEC pLpcDec)
{
    switch (pLpcDec->aenmState[pLpcDec->idxState])
    {
        case LPCDECSTATE_LFRAME_WAIT_ASSERTED:
            /* We are not in any target cycle currently so stop. */
            break;
        case LPCDECSTATE_ADDR:
            if (pLpcDec->fWrite)
            {
                lpcDecStateSet(pLpcDec, LPCDECSTATE_DATA);
                pLpcDec->cDataCycles = 2;
            }
            else /* Reads have a turn around before. */
            {
                lpcDecStateSet(pLpcDec, LPCDECSTATE_TAR);
                pLpcDec->cTarCycles = 2;
            }
            break;
        case LPCDECSTATE_DATA:
            lpcDecStateSet(pLpcDec, LPCDECSTATE_TAR);
            pLpcDec->cTarCycles = 2;
            break;
        case LPCDECSTATE_TAR:
            if (pLpcDec->fWrite)
            {
                if (pLpcDec->aenmState[pLpcDec->idxState - 1] == LPCDECSTATE_DATA)
                    lpcDecStateSet(pLpcDec, LPCDECSTATE_SYNC);
                else
                {
                    lpcDecStateDump(pLpcDec, 0 /*fAbort*/);
                    lpcDecStateReset(pLpcDec); /* Second TAR phase in the cycle. */
                }
            }
            else
            {
                if (pLpcDec->aenmState[pLpcDec->idxState - 1] == LPCDECSTATE_ADDR)
                    lpcDecStateSet(pLpcDec, LPCDECSTATE_SYNC);
                else
                {
                    lpcDecStateDump(pLpcDec, 0 /*fAbort*/);
                    lpcDecStateReset(pLpcDec); /* Second TAR phase in the cycle. */
                }
            }
            break;
        case LPCDECSTATE_SYNC:
            if (pLpcDec->fWrite)
            {
                lpcDecStateSet(pLpcDec, LPCDECSTATE_TAR);
                pLpcDec->cTarCycles = 2;
            }
            else
            {
                lpcDecStateSet(pLpcDec, LPCDECSTATE_DATA);
                pLpcDec->cDataCycles = 2;
            }
            break;
        default:
            printf("Unknown state %u\n", pLpcDec->aenmState[pLpcDec->idxState]);
    }
}


/**
 * Decodes the START phase of the cycle.
 *
 * @returns nothing.
 * @param   pLpcDec                 The LPC decoder state.
 * @param   bLad                    Value of LAD[3:0].
 */
static void lpcDecStateStartDecode(PLPCDEC pLpcDec, uint8_t bLad)
{
    if (pLpcDec->bStartLast == LPC_DEC_START_TARGET_CYCLE)
    {
        /* New target cycle, LAD[3:0] contains type and direction. */
        pLpcDec->bTyp    = LPC_DEC_CYC_TYPE_GET(bLad);
        pLpcDec->fWrite  = !LPC_DEC_CYC_DIR_IS_READ(bLad);
        pLpcDec->u32Addr = 0;
        lpcDecStateSet(pLpcDec, LPCDECSTATE_ADDR);
        switch (pLpcDec->bTyp)
        {
            case LPC_DEC_CYC_TYPE_IO:
                pLpcDec->cAddrCycles = 4;
                break;
            case LPC_DEC_CYC_TYPE_MEM:
                pLpcDec->cAddrCycles = 8;
                break;
            case LPC_DEC_CYC_TYPE_DMA: /** @todo */
            case LPC_DEC_CYC_TYPE_RSVD:
            default:
                printf("Encountered ILLEGAL/unsupported cycle type: %#x\n", pLpcDec->bTyp);
                lpcDecStateReset(pLpcDec);
                break;
        }
    }
    else if (pLpcDec->bStartLast == LPC_DEC_START_ABORT)
        lpcDecStateReset(pLpcDec);
}


/**
 * Decodes an address cycle.
 *
 * @returns nothing.
 * @param   pLpcDec                 The LPC decoder state.
 * @param   bLad                    Value of LAD[3:0].
 */
static void lpcDecStateAddrDecode(PLPCDEC pLpcDec, uint8_t bLad)
{
    pLpcDec->cAddrCycles--;
    pLpcDec->u32Addr |= bLad << (pLpcDec->cAddrCycles * 4);

    if (!pLpcDec->cAddrCycles)
        lpcDecStateSampleAdvance(pLpcDec); /* Go to the next state. */
}


/**
 * Decodes a data cycle.
 *
 * @returns nothing.
 * @param   pLpcDec                 The LPC decoder state.
 * @param   bLad                    Value of LAD[3:0].
 */
static void lpcDecStateDataDecode(PLPCDEC pLpcDec, uint8_t bLad)
{
    pLpcDec->bData |= bLad << (pLpcDec->iDataCycle * 4);
    pLpcDec->iDataCycle++;

    if (pLpcDec->iDataCycle == pLpcDec->cDataCycles)
        lpcDecStateSampleAdvance(pLpcDec);
}


/**
 * Decodes a TAR cycle.
 *
 * @returns nothing.
 * @param   pLpcDec                 The LPC decoder state.
 * @param   bLad                    Value of LAD[3:0].
 */
static void lpcDecStateTarDecode(PLPCDEC pLpcDec, uint8_t bLad)
{
    (void)(bLad);

    pLpcDec->cTarCycles--;
    if (!pLpcDec->cTarCycles)
        lpcDecStateSampleAdvance(pLpcDec);
}


/**
 * Decodes a SYNC cycle.
 *
 * @returns nothing.
 * @param   pLpcDec                 The LPC decoder state.
 * @param   bLad                    Value of LAD[3:0].
 */
static void lpcDecStateSyncDecode(PLPCDEC pLpcDec, uint8_t bLad)
{
    if (bLad == 0)
        lpcDecStateSampleAdvance(pLpcDec);
}


/**
 * Processes the given sample with the LPC decoder state given.
 *
 * @returns Status code.
 * @param   pLpcDec                 The LPC decoder state.
 * @param   uSeqNo                  Sequence number of the sample.
 * @param   bSample                 The new sample to process.
 */
static int lpcDecStateSampleProcess(PLPCDEC pLpcDec, uint64_t uSeqNo, uint8_t bSample)
{
    /* Extract the clock and sample the other signals only on a falling edge. */
    uint8_t fClk = !!(bSample & (1 << pLpcDec->u8BitLClk));
    if (fClk == pLpcDec->fClkLast)
        return 0;

    if (   pLpcDec->fClkLast
        && !fClk)
    {
        /* Extract LFrame# and check whether it is asserted. */
        uint8_t fLFrame = !!(bSample & (1 << pLpcDec->u8BitLFrame));
        uint8_t bLad = lpcDecStateLadExtractFromSample(pLpcDec, bSample);

        if (!fLFrame)
        {
            if (   pLpcDec->aenmState[pLpcDec->idxState] != LPCDECSTATE_LFRAME_WAIT_ASSERTED
                && pLpcDec->aenmState[pLpcDec->idxState] != LPCDECSTATE_START)
                lpcDecStateDump(pLpcDec, 1 /*fAbort*/);
            pLpcDec->bStartLast  = bLad;
            pLpcDec->uSeqNoCycle = uSeqNo;
            lpcDecStateReset(pLpcDec);
            lpcDecStateSet(pLpcDec, LPCDECSTATE_START);
        }
        else
        {
            /* Act according on the current state. */
            switch (pLpcDec->aenmState[pLpcDec->idxState])
            {
                case LPCDECSTATE_LFRAME_WAIT_ASSERTED:
                    /* We are not in any target cycle currently so stop. */
                    break;
                case LPCDECSTATE_START:
                    lpcDecStateStartDecode(pLpcDec, bLad);
                    break;
                case LPCDECSTATE_ADDR:
                    lpcDecStateAddrDecode(pLpcDec, bLad);
                    break;
                case LPCDECSTATE_DATA:
                    lpcDecStateDataDecode(pLpcDec, bLad);
                    break;
                case LPCDECSTATE_TAR:
                    lpcDecStateTarDecode(pLpcDec, bLad);
                    break;
                case LPCDECSTATE_SYNC:
                    lpcDecStateSyncDecode(pLpcDec, bLad);
                    break;
                default:
                    printf("Unknown state %u\n", pLpcDec->aenmState[pLpcDec->idxState]);
            }
        }
    }

    pLpcDec->fClkLast = fClk;
    return 0;
}


int main(int argc, char *argv[])
{
    int ch = 0;
    int idxOption = 0;
    const char *pszFilename = NULL;

    while ((ch = getopt_long (argc, argv, "Hvi:", &g_aOptions[0], &idxOption)) != -1)
    {
        switch (ch)
        {
            case 'h':
            case 'H':
                printf("%s: Low Pin Count Bus protocol decoder\n"
                       "    --input <path/to/saleae/capture>\n"
                       "    --verbose Dumps more information for each cycle like the state transitions encountered\n",
                       argv[0]);
                return 0;
            case 'v':
                g_fVerbose = 1;
                break;
            case 'i':
                pszFilename = optarg;
                break;

            default:
                fprintf(stderr, "Unrecognised option: -%c\n", optopt);
                return 1;
        }
    }

    if (!pszFilename)
    {
        fprintf(stderr, "A filepath to the capture is required!\n");
        return 1;
    }

    PLPCDECFILEBUFREAD pBufFile = NULL;
    int rc = lpcDecFileBufReaderCreate(&pBufFile, pszFilename);
    if (!rc)
    {
        LPCDEC LpcDec;
        lpcDecStateInit(&LpcDec, 0, 1, 5, 4, 3, 2); /** @todo Make configurable */

        while (   !lpcDecFileBufReaderHasEos(pBufFile)
               && !rc)
        {
            uint64_t uSeqNo = lpcDecFileBufReaderGetU64(pBufFile);
            uint8_t bVal = lpcDecFileBufReaderGetU8(pBufFile);
            rc = lpcDecStateSampleProcess(&LpcDec, uSeqNo, bVal);
        }

        lpcDecFileBufReaderClose(pBufFile);
    }
    else
        fprintf(stderr, "The file '%s' could not be opened\n", pszFilename);

    return 0;
}


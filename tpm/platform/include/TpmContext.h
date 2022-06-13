/*
 * Copyright (c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#ifndef TPM_CONTEXT_H
#define TPM_CONTEXT_H

#define MAX_TPM_CONTEXT_COUNT   16

#if defined TPM_CONTEXT_C
// The following arrays are used to save command sessions information so that the
// command handle/session buffer does not have to be preserved for the duration of
// the command. These arrays are indexed by the session index in accordance with
// the order of sessions in the session area of the command.
//
// Array of the authorization session handles
EXTERN TPM_HANDLE       s_sessionHandles[MAX_SESSION_NUM];

// Array of authorization session attributes
EXTERN TPMA_SESSION     s_attributes[MAX_SESSION_NUM];

// Array of handles authorized by the corresponding authorization sessions;
// and if none, then TPM_RH_UNASSIGNED value is used
EXTERN TPM_HANDLE       s_associatedHandles[MAX_SESSION_NUM];

// Array of nonces provided by the caller for the corresponding sessions
EXTERN TPM2B_NONCE      s_nonceCaller[MAX_SESSION_NUM];

// Array of authorization values (HMAC's or passwords) for the corresponding
// sessions
EXTERN TPM2B_AUTH       s_inputAuthValues[MAX_SESSION_NUM];

// Array of pointers to the SESSION structures for the sessions in a command
EXTERN SESSION          *s_usedSessions[MAX_SESSION_NUM];

// Special value to indicate an undefined session index
#define             UNDEFINED_INDEX     (0xFFFF)

// Index of the session used for encryption of a response parameter
EXTERN UINT32           s_encryptSessionIndex;

// Index of the session used for decryption of a command parameter
EXTERN UINT32           s_decryptSessionIndex;

// Index of a session used for audit
EXTERN UINT32           s_auditSessionIndex;

// The cpHash for command audit
#ifdef  TPM_CC_GetCommandAuditDigest
EXTERN TPM2B_DIGEST    s_cpHashForCommandAudit;
#endif

// Flag indicating if NV update is pending for the lockOutAuthEnabled or
// failedTries DA parameter
EXTERN BOOL             s_DAPendingOnNV;

#endif // SESSION_PROCESS_C

//*****************************************************************************
//*** From DA.c
//*****************************************************************************
#if defined TPM_CONTEXT_C
// This variable holds the accumulated time since the last time
// that 'failedTries' was decremented. This value is in millisecond.
#if !ACCUMULATE_SELF_HEAL_TIMER
EXTERN UINT64       s_selfHealTimer;

// This variable holds the accumulated time that the lockoutAuth has been
// blocked.
EXTERN UINT64       s_lockoutTimer;
#endif // ACCUMULATE_SELF_HEAL_TIMER

#endif // DA_C

//*****************************************************************************
//*** From NV.c
//*****************************************************************************
#if defined TPM_CONTEXT_C
// This marks the end of the NV area. This is a run-time variable as it might
// not be compile-time constant.
EXTERN NV_REF   s_evictNvEnd;

// This space is used to hold the index data for an orderly Index. It also contains
// the attributes for the index.
EXTERN BYTE      s_indexOrderlyRam[RAM_INDEX_SPACE];   // The orderly NV Index data

// This value contains the current max counter value. It is written to the end of
// allocatable NV space each time an index is deleted or added. This value is
// initialized on Startup. The indices are searched and the maximum of all the
// current counter indices and this value is the initial value for this.
EXTERN UINT64    s_maxCounter;

// This is space used for the NV Index cache. As with a persistent object, the
// contents of a referenced index are copied into the cache so that the
// NV Index memory scanning and data copying can be reduced.
// Only code that operates on NV Index data should use this cache directly. When
// that action code runs, s_lastNvIndex will contain the index header information.
// It will have been loaded when the handles were verified.
// NOTE: An NV index handle can appear in many commands that do not operate on the
// NV data (e.g. TPM2_StartAuthSession). However, only one NV Index at a time is
// ever directly referenced by any command. If that changes, then the NV Index
// caching needs to be changed to accommodate that. Currently, the code will verify
// that only one NV Index is referenced by the handles of the command.
EXTERN      NV_INDEX         s_cachedNvIndex;
EXTERN      NV_REF           s_cachedNvRef;
EXTERN      BYTE            *s_cachedNvRamRef;

// Initial NV Index/evict object iterator value
#define     NV_REF_INIT     (NV_REF)0xFFFFFFFF

#endif

//*****************************************************************************
//*** From Object.c
//*****************************************************************************
#if defined TPM_CONTEXT_C
// This type is the container for an object.

EXTERN OBJECT           s_objects[MAX_LOADED_OBJECTS];

#endif // OBJECT_C

//*****************************************************************************
//*** From PCR.c
//*****************************************************************************
#if defined TPM_CONTEXT_C
// The following macro is used to define the per-implemented-hash space. This 
// implementation reserves space for all implemented hashes.
#define PCR_ALL_HASH(HASH, Hash)    BYTE    Hash##Pcr[HASH##_DIGEST_SIZE];

typedef struct
{
    FOR_EACH_HASH(PCR_ALL_HASH)
} PCR;

typedef struct
{
    unsigned int    stateSave : 1;              // if the PCR value should be
                                                // saved in state save
    unsigned int    resetLocality : 5;          // The locality that the PCR
                                                // can be reset
    unsigned int    extendLocality : 5;         // The locality that the PCR
                                                // can be extend
} PCR_Attributes;

EXTERN PCR          s_pcrs[IMPLEMENTATION_PCR];
#endif // PCR_C

//*****************************************************************************
//*** From Session.c
//*****************************************************************************
#if defined TPM_CONTEXT_C
// Container for HMAC or policy session tracking information
typedef struct
{
    BOOL                occupied;
    SESSION             session;        // session structure
} SESSION_SLOT;

EXTERN SESSION_SLOT     s_sessions[MAX_LOADED_SESSIONS];

//  The index in contextArray that has the value of the oldest saved session
//  context. When no context is saved, this will have a value that is greater
//  than or equal to MAX_ACTIVE_SESSIONS.
EXTERN UINT32            s_oldestSavedSession;

// The number of available session slot openings.  When this is 1,
// a session can't be created or loaded if the GAP is maxed out.
// The exception is that the oldest saved session context can always
// be loaded (assuming that there is a space in memory to put it)
EXTERN int               s_freeSessionSlots;

#endif // SESSION_C

//*****************************************************************************
//*** From IoBuffers.c
//*****************************************************************************
#if defined TPM_CONTEXT_C
// Each command function is allowed a structure for the inputs to the function and
// a structure for the outputs. The command dispatch code unmarshals the input butter
// to the command action input structure starting at the first byte of
// s_actionIoBuffer. The value of s_actionIoAllocation is the number of UINT64 values
// allocated. It is used to set the pointer for the response structure. The command
// dispatch code will marshal the response values into the final output buffer.
EXTERN UINT64   s_actionIoBuffer[768];      // action I/O buffer
EXTERN UINT32   s_actionIoAllocation;       // number of UIN64 allocated for the
                                            // action input structure
#endif // IO_BUFFER_C

// typedef void(FailFunction)(const char *function, int line, int code);

#if defined TPM_CONTEXT_C
EXTERN UINT32    s_failFunction;
EXTERN UINT32    s_failLine;            // the line in the file at which
                                        // the error was signaled
EXTERN UINT32    s_failCode;            // the error code used

EXTERN FailFunction    *LibFailCallback;

#endif // TPM_FAIL_C


#if defined TPM_CONTEXT_C
  typedef struct
  {
    //*****************************************************************************
    //*****************************************************************************
    //** RAM Global Values
    //*****************************************************************************
    //*****************************************************************************
    //*** Description
    // The values in this section are only extant in RAM or ROM as constant values.

    //*** Crypto Self-Test Values
    ALGORITHM_VECTOR     g_implementedAlgorithms;
    ALGORITHM_VECTOR     g_toTest;

    //*** g_rcIndex[]
    // This array is used to contain the array of values that are added to a return
    // code when it is a parameter-, handle-, or session-related error.
    // This is an implementation choice and the same result can be achieved by using
    // a macro.
    // const UINT16     g_rcIndex[15] INITIALIZER(g_rcIndexInitializer);

    //*** g_exclusiveAuditSession
    // This location holds the session handle for the current exclusive audit
    // session. If there is no exclusive audit session, the location is set to
    // TPM_RH_UNASSIGNED.
    TPM_HANDLE       g_exclusiveAuditSession;

    //*** g_time
    // This is the value in which we keep the current command time. This is initialized
    // at the start of each command. The time is the accumulated time since the last
    // time that the TPM's timer was last powered up. Clock is the accumulated time
    // since the last time that the TPM was cleared. g_time is in mS.
    UINT64          g_time;

    //*** g_timeEpoch
    // This value contains the current clock Epoch. It changes when there is a clock
    // discontinuity. It may be necessary to place this in NV should the timer be able
    // to run across a power down of the TPM but not in all cases (e.g. dead battery).
    // If the nonce is placed in NV, it should go in gp because it should be changing
    // slowly.
    #if CLOCK_STOPS
    CLOCK_NONCE       g_timeEpoch;
    #else
    // #define g_timeEpoch      gp.timeEpoch
    #endif

    //*** g_phEnable
    // This is the platform hierarchy control and determines if the platform hierarchy
    // is available. This value is SET on each TPM2_Startup(). The default value is
    // SET.
    BOOL             g_phEnable;

    //*** g_pcrReConfig
    // This value is SET if a TPM2_PCR_Allocate command successfully executed since
    // the last TPM2_Startup(). If so, then the next shutdown is required to be
    // Shutdown(CLEAR).
    BOOL             g_pcrReConfig;

    //*** g_DRTMHandle
    // This location indicates the sequence object handle that holds the DRTM
    // sequence data. When not used, it is set to TPM_RH_UNASSIGNED. A sequence
    // DRTM sequence is started on either _TPM_Init or _TPM_Hash_Start.
    TPMI_DH_OBJECT   g_DRTMHandle;

    //*** g_DrtmPreStartup
    // This value indicates that an H-CRTM occurred after _TPM_Init but before
    // TPM2_Startup(). The define for PRE_STARTUP_FLAG is used to add the
    // g_DrtmPreStartup value to gp_orderlyState at shutdown. This hack is to avoid
    // adding another NV variable.
    BOOL            g_DrtmPreStartup;

    //*** g_StartupLocality3
    // This value indicates that a TPM2_Startup() occurred at locality 3. Otherwise, it
    // at locality 0. The define for STARTUP_LOCALITY_3 is to
    // indicate that the startup was not at locality 0. This hack is to avoid
    // adding another NV variable.
    BOOL            g_StartupLocality3;

    #if USE_DA_USED
    //*** g_daUsed
    // This location indicates if a DA-protected value is accessed during a boot
    // cycle. If none has, then there is no need to increment 'failedTries' on the
    // next non-orderly startup. This bit is merged with gp.orderlyState when
    // gp.orderly is set to SU_NONE_VALUE
    BOOL                 g_daUsed;
    #endif

    //*** g_updateNV
    // This flag indicates if NV should be updated at the end of a command.
    // This flag is set to UT_NONE at the beginning of each command in ExecuteCommand().
    // This flag is checked in ExecuteCommand() after the detailed actions of a command
    // complete. If the command execution was successful and this flag is not UT_NONE,
    // any pending NV writes will be committed to NV.
    // UT_ORDERLY causes any RAM data to be written to the orderly space for staging
    // the write to NV.
    UPDATE_TYPE          g_updateNV;

    //*** g_powerWasLost
    // This flag is used to indicate if the power was lost. It is SET in _TPM__Init.
    // This flag is cleared by TPM2_Startup() after all power-lost activities are
    // completed.
    // Note: When power is applied, this value can come up as anything. However,
    // _plat__WasPowerLost() will provide the proper indication in that case. So, when
    // power is actually lost, we get the correct answer. When power was not lost, but
    // the power-lost processing has not been completed before the next _TPM_Init(),
    // then the TPM still does the correct thing.
    BOOL             g_powerWasLost;

    //*** g_clearOrderly
    // This flag indicates if the execution of a command should cause the orderly
    // state to be cleared.  This flag is set to FALSE at the beginning of each
    // command in ExecuteCommand() and is checked in ExecuteCommand() after the
    // detailed actions of a command complete but before the check of
    // 'g_updateNV'. If this flag is TRUE, and the orderly state is not
    // SU_NONE_VALUE, then the orderly state in NV memory will be changed to
    // SU_NONE_VALUE or SU_DA_USED_VALUE.
    BOOL             g_clearOrderly;

    //*** g_prevOrderlyState
    // This location indicates how the TPM was shut down before the most recent
    // TPM2_Startup(). This value, along with the startup type, determines if
    // the TPM should do a TPM Reset, TPM Restart, or TPM Resume.
    TPM_SU           g_prevOrderlyState;

    //*** g_nvOk
    // This value indicates if the NV integrity check was successful or not. If not and
    // the failure was severe, then the TPM would have been put into failure mode after
    // it had been re-manufactured. If the NV failure was in the area where the state-save
    // data is kept, then this variable will have a value of FALSE indicating that
    // a TPM2_Startup(CLEAR) is required.
    BOOL             g_nvOk;
    // NV availability is sampled as the start of each command and stored here
    // so that its value remains consistent during the command execution
    TPM_RC           g_NvStatus;

    //*** g_platformUnique
    // This location contains the unique value(s) used to identify the TPM. It is
    // loaded on every _TPM2_Startup()
    // The first value is used to seed the RNG. The second value is used as a vendor
    // authValue. The value used by the RNG would be the value derived from the
    // chip unique value (such as fused) with a dependency on the authorities of the
    // code in the TPM boot path. The second would be derived from the chip unique value
    // with a dependency on the details of the code in the boot path. That is, the
    // first value depends on the various signers of the code and the second depends on
    // what was signed. The TPM vendor should not be able to know the first value but
    // they are expected to know the second.
    TPM2B_AUTH       g_platformUniqueAuthorities; // Reserved for RNG

    TPM2B_AUTH       g_platformUniqueDetails;   // referenced by VENDOR_PERMANENT

    //*********************************************************************************
    //*********************************************************************************
    //** Persistent Global Values
    //*********************************************************************************
    //*********************************************************************************
    //*** Description
    // The values in this section are global values that are persistent across power
    // events. The lifetime of the values determines the structure in which the value
    // is placed.

    //*********************************************************************************
    //*** PERSISTENT_DATA
    //*********************************************************************************
    // This structure holds the persistent values that only change as a consequence
    // of a specific Protected Capability and are not affected by TPM power events
    // (TPM2_Startup() or TPM2_Shutdown().
    PERSISTENT_DATA  gp;

    //*********************************************************************************
    //*********************************************************************************
    //*** ORDERLY_DATA
    //*********************************************************************************
    //*********************************************************************************
    // The data in this structure is saved to NV on each TPM2_Shutdown().
    #if ACCUMULATE_SELF_HEAL_TIMER
    // #define     s_selfHealTimer     go.selfHealTimer
    // #define     s_lockoutTimer      go.lockoutTimer
    #endif  // ACCUMULATE_SELF_HEAL_TIMER

    // #  define drbgDefault go.drbgState

    ORDERLY_DATA     go;

    //*********************************************************************************
    //*********************************************************************************
    //*** STATE_CLEAR_DATA
    //*********************************************************************************
    //*********************************************************************************
    // This structure contains the data that is saved on Shutdown(STATE)
    // and restored on Startup(STATE).  The values are set to their default
    // settings on any Startup(Clear). In other words, the data is only persistent
    // across TPM Resume.
    //
    // If the comments associated with a parameter indicate a default reset value, the
    // value is applied on each Startup(CLEAR).
    STATE_CLEAR_DATA gc;

    //*********************************************************************************
    //*********************************************************************************
    //***  State Reset Data
    //*********************************************************************************
    //*********************************************************************************
    // This structure contains data is that is saved on Shutdown(STATE) and restored on
    // the subsequent Startup(ANY). That is, the data is preserved across TPM Resume
    // and TPM Restart.
    //
    // If a default value is specified in the comments this value is applied on
    // TPM Reset.
    STATE_RESET_DATA gr;

    //*****************************************************************************
    //** From CryptTest.c
    //*****************************************************************************
    // This structure contains the self-test state values for the cryptographic modules.
    CRYPTO_SELF_TEST_STATE   g_cryptoSelfTestState;

    //*****************************************************************************
    //** From Manufacture.c
    //*****************************************************************************
    BOOL              g_manufactured;

    // This value indicates if a TPM2_Startup commands has been
    // receive since the power on event.  This flag is maintained in power
    // simulation module because this is the only place that may reliably set this
    // flag to FALSE.
    BOOL              g_initialized;

    //** Private data

    //*****************************************************************************
    //*** From SessionProcess.c
    //*****************************************************************************
    #if defined SESSION_PROCESS_C || defined GLOBAL_C || defined MANUFACTURE_C || defined TPM_CONTEXT_C
    // The following arrays are used to save command sessions information so that the
    // command handle/session buffer does not have to be preserved for the duration of
    // the command. These arrays are indexed by the session index in accordance with
    // the order of sessions in the session area of the command.
    //
    // Array of the authorization session handles
    TPM_HANDLE       s_sessionHandles[MAX_SESSION_NUM];

    // Array of authorization session attributes
    TPMA_SESSION     s_attributes[MAX_SESSION_NUM];

    // Array of handles authorized by the corresponding authorization sessions;
    // and if none, then TPM_RH_UNASSIGNED value is used
    TPM_HANDLE       s_associatedHandles[MAX_SESSION_NUM];

    // Array of nonces provided by the caller for the corresponding sessions
    TPM2B_NONCE      s_nonceCaller[MAX_SESSION_NUM];

    // Array of authorization values (HMAC's or passwords) for the corresponding
    // sessions
    TPM2B_AUTH       s_inputAuthValues[MAX_SESSION_NUM];

    // Array of pointers to the SESSION structures for the sessions in a command
    SESSION          *s_usedSessions[MAX_SESSION_NUM];

    // Index of the session used for encryption of a response parameter
    UINT32           s_encryptSessionIndex;

    // Index of the session used for decryption of a command parameter
    UINT32           s_decryptSessionIndex;

    // Index of a session used for audit
    UINT32           s_auditSessionIndex;

    // The cpHash for command audit
    #ifdef  TPM_CC_GetCommandAuditDigest
    TPM2B_DIGEST    s_cpHashForCommandAudit;
    #endif

    // Flag indicating if NV update is pending for the lockOutAuthEnabled or
    // failedTries DA parameter
    BOOL             s_DAPendingOnNV;

    #endif // SESSION_PROCESS_C

    //*****************************************************************************
    //*** From DA.c
    //*****************************************************************************
    #if defined DA_C || defined GLOBAL_C || defined MANUFACTURE_C || defined TPM_CONTEXT_C
    // This variable holds the accumulated time since the last time
    // that 'failedTries' was decremented. This value is in millisecond.
    #if !ACCUMULATE_SELF_HEAL_TIMER
    UINT64       s_selfHealTimer;

    // This variable holds the accumulated time that the lockoutAuth has been
    // blocked.
    UINT64       s_lockoutTimer;
    #endif // ACCUMULATE_SELF_HEAL_TIMER

    #endif // DA_C

    //*****************************************************************************
    //*** From NV.c
    //*****************************************************************************
    #if defined NV_C || defined GLOBAL_C || defined TPM_CONTEXT_C
    // This marks the end of the NV area. This is a run-time variable as it might
    // not be compile-time constant.
    NV_REF   s_evictNvEnd;

    // This space is used to hold the index data for an orderly Index. It also contains
    // the attributes for the index.
    BYTE      s_indexOrderlyRam[RAM_INDEX_SPACE];   // The orderly NV Index data

    // This value contains the current max counter value. It is written to the end of
    // allocatable NV space each time an index is deleted or added. This value is
    // initialized on Startup. The indices are searched and the maximum of all the
    // current counter indices and this value is the initial value for this.
    UINT64    s_maxCounter;

    // This is space used for the NV Index cache. As with a persistent object, the
    // contents of a referenced index are copied into the cache so that the
    // NV Index memory scanning and data copying can be reduced.
    // Only code that operates on NV Index data should use this cache directly. When
    // that action code runs, s_lastNvIndex will contain the index header information.
    // It will have been loaded when the handles were verified.
    // NOTE: An NV index handle can appear in many commands that do not operate on the
    // NV data (e.g. TPM2_StartAuthSession). However, only one NV Index at a time is
    // ever directly referenced by any command. If that changes, then the NV Index
    // caching needs to be changed to accommodate that. Currently, the code will verify
    // that only one NV Index is referenced by the handles of the command.
    NV_INDEX         s_cachedNvIndex;
    NV_REF           s_cachedNvRef;
    BYTE            *s_cachedNvRamRef;

    #endif // DA_C

    //*****************************************************************************
    //*** From Object.c
    //*****************************************************************************
    #if defined OBJECT_C || defined GLOBAL_C  || defined TPM_CONTEXT_C
    // This type is the container for an object.

    OBJECT           s_objects[MAX_LOADED_OBJECTS];

    #endif // OBJECT_C

    //*****************************************************************************
    //*** From PCR.c
    //*****************************************************************************
    #if defined PCR_C || defined GLOBAL_C  || defined TPM_CONTEXT_C

    PCR          s_pcrs[IMPLEMENTATION_PCR];

    #endif // PCR_C

    //*****************************************************************************
    //*** From Session.c
    //*****************************************************************************
    #if defined SESSION_C || defined GLOBAL_C  || defined TPM_CONTEXT_C

    SESSION_SLOT     s_sessions[MAX_LOADED_SESSIONS];

    //  The index in contextArray that has the value of the oldest saved session
    //  context. When no context is saved, this will have a value that is greater
    //  than or equal to MAX_ACTIVE_SESSIONS.
    UINT32            s_oldestSavedSession;

    // The number of available session slot openings.  When this is 1,
    // a session can't be created or loaded if the GAP is maxed out.
    // The exception is that the oldest saved session context can always
    // be loaded (assuming that there is a space in memory to put it)
    int               s_freeSessionSlots;

    #endif // SESSION_C

    //*****************************************************************************
    //*** From IoBuffers.c
    //*****************************************************************************
    #if defined IO_BUFFER_C || defined GLOBAL_C  || defined TPM_CONTEXT_C
    // Each command function is allowed a structure for the inputs to the function and
    // a structure for the outputs. The command dispatch code unmarshals the input butter
    // to the command action input structure starting at the first byte of
    // s_actionIoBuffer. The value of s_actionIoAllocation is the number of UINT64 values
    // allocated. It is used to set the pointer for the response structure. The command
    // dispatch code will marshal the response values into the final output buffer.
    UINT64   s_actionIoBuffer[768];      // action I/O buffer
    UINT32   s_actionIoAllocation;       // number of UIN64 allocated for the
                                            // action input structure
    #endif // IO_BUFFER_C

    //*****************************************************************************
    //*** From TPMFail.c
    //*****************************************************************************
    // This value holds the address of the string containing the name of the function
    // in which the failure occurred. This address value is not useful for anything
    // other than helping the vendor to know in which file the failure  occurred.
    BOOL      g_inFailureMode;       // Indicates that the TPM is in failure mode
    #if SIMULATION
    BOOL      g_forceFailureMode;    // flag to force failure mode during test
    #endif

    #if defined TPM_FAIL_C || defined GLOBAL_C  || defined TPM_CONTEXT_C
    UINT32    s_failFunction;
    UINT32    s_failLine;            // the line in the file at which
                                        // the error was signaled
    UINT32    s_failCode;            // the error code used

    FailFunction    *LibFailCallback;

    #endif // TPM_FAIL_C

    //*****************************************************************************
    //*** From ACT_spt.c
    //*****************************************************************************
    // This value is used to indicate if an ACT has been updated since the last
    // TPM2_Startup() (one bit for each ACT). If the ACT is not updated
    // (TPM2_ACT_SetTimeout()) after a startup, then on each TPM2_Shutdown() the TPM will
    // save 1/2 of the current timer value. This prevents an attack on the ACT by saving
    // the counter and then running for a long period of time before doing a TPM Restart.
    // A quick TPM2_Shutdown() after each
    UINT16                       s_ActUpdated;

    //*****************************************************************************
    //*** From CommandCodeAttributes.c
    //*****************************************************************************
    // This array is instanced in CommandCodeAttributes.c when it includes
    // CommandCodeAttributes.h. Don't change the extern to EXTERN.
    // const  TPMA_CC               s_ccAttr[];
    // const  COMMAND_ATTRIBUTES    s_commandAttributes[];


    //*****************************************************************************
    //*** From PlatformData.h
    //*****************************************************************************

    // From Cancel.c
    // Cancel flag.  It is initialized as FALSE, which indicate the command is not
    // being canceled
    int     s_isCanceled;

    // #ifndef HARDWARE_CLOCK
    // typedef uint64_t     clock64_t;
    // This is the value returned the last time that the system clock was read. This
    // is only relevant for a simulator or virtual TPM.
    uint64_t       s_realTimePrevious;

    // These values are used to try to synthesize a long lived version of clock().
    uint64_t        s_lastSystemTime;
    uint64_t        s_lastReportedTime;

    // This is the rate adjusted value that is the equivalent of what would be read from
    // a hardware register that produced rate adjusted time.
    uint64_t        s_tpmTime;

    // This value indicates that the timer was reset
    int             s_timerReset;
    // This value indicates that the timer was stopped. It causes a clock discontinuity.
    int             s_timerStopped;

    // This variable records the time when _plat__TimerReset is called.  This mechanism
    // allow us to subtract the time when TPM is power off from the total
    // time reported by clock() function
    uint64_t        s_initClock;

    // This variable records the timer adjustment factor.
    unsigned int    s_adjustRate;

    // For LocalityPlat.c
    // Locality of current command
    unsigned char   s_locality;

    unsigned char   s_NV[NV_MEMORY_SIZE];
    int             s_NvIsAvailable;
    int             s_NV_unrecoverable;
    int             s_NV_recoverable;

    // For PPPlat.c
    // Physical presence.  It is initialized to FALSE
    int              s_physicalPresence;

    // From Power
    int              s_powerLost;

    // For Entropy.c
    uint32_t         lastEntropy;

    #define MY_DEFINE_ACT(N)   ACT_DATA ACT_##N;
        FOR_EACH_ACT(MY_DEFINE_ACT)

    int              actTicksAllowed;
} TPM_CONTEXT;
#endif

// This is a PoC, so we design an array to simplify the implementation
#if defined TPM_CONTEXT_C
extern UINT32          g_CurrentTpmContextId;
extern UINT32          g_CurrentTpmContextCnt;
extern UINT32          g_TpmContextIdList[MAX_TPM_CONTEXT_COUNT];
extern TPM_CONTEXT     g_TpmContextContentList[MAX_TPM_CONTEXT_COUNT];
#endif


void
SwitchTpmContext(
    uint32_t  contextId
);

uint64_t
GetSwitchTimeUsed(
    void
);

uint64_t
ReadTsc(
  void
);

#endif
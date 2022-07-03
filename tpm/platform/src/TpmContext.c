/*
 * Copyright (c) 2022 Intel Corporation
 * SPDX-License-Identifier: BSD-2-Clause-Patent
 */

#define TPM_CONTEXT_C

#include <stdio.h>
#include "Tpm.h"
#include "PlatformACT.h"
#include "PlatformData.h"
#include "TpmContext.h"

UINT128 g_CurrentTpmContextId = 0;
UINT32 g_CurrentTpmContextCnt = 0;
UINT128 g_TpmContextIdList[MAX_TPM_CONTEXT_COUNT] = {0};
TPM_CONTEXT g_TpmContextContentList[MAX_TPM_CONTEXT_COUNT] = {0};
uint64_t g_TpmContextSwitchTime = 0;

#define COLUME_SIZE (16)
#define DUMP_MAX_BUFFER_SIZE 128

int dump_data(uint8_t *data, int dataSize, char *buffer, int bufferLen)
{
  int i, j, k;

  pAssert(dataSize < COLUME_SIZE);
  pAssert(bufferLen > dataSize * 3 + 1);

  j = 0;
  for (i = 0; i < dataSize; i++)
  {
    k = snprintf(buffer + j, bufferLen - j, "%02x ", data[i]);
    pAssert(k > 0);
    j += k;
  }

  return j;
}

/**
 * @brief Dump data in hex format.
 *
 */
void dump_hex(uint8_t *data, int size)
{
  int i, j;
  int count;
  int left;
  int len;
  char buffer[DUMP_MAX_BUFFER_SIZE] = {0};

  count = size / COLUME_SIZE;
  left = size % COLUME_SIZE;
  for (i = 0; i < count; i++)
  {
    len = 0;

    j = snprintf(buffer + len, DUMP_MAX_BUFFER_SIZE - len, "%04x: ", i * COLUME_SIZE);
    pAssert(j > 0);
    len += j;

    j = dump_data(data + i * COLUME_SIZE, COLUME_SIZE, buffer + len, DUMP_MAX_BUFFER_SIZE - len);
    pAssert(j > 0);

    printf("%s\n", buffer);
    memset(buffer, 0, DUMP_MAX_BUFFER_SIZE);
  }

  if (left != 0)
  {
    len = 0;
    len = snprintf(buffer + len, DUMP_MAX_BUFFER_SIZE - len, "%04x: ", i * COLUME_SIZE);
    pAssert(len > 0);
    len += dump_data(data + i * COLUME_SIZE, left, buffer + len, DUMP_MAX_BUFFER_SIZE - len);
    printf("%s\n", buffer);
  }
}

/**
 * @brief Save the global variables to context or pop the context to the global variables
 * 
 * @param context 
 * @param save 
 */
void _SavePopContext(TPM_CONTEXT *context, BOOL save)
{
// the field should be of primitive-type, such as int, char, etc.
#define SAVE_POP_CONTEXT_FIELD(field) \
  (save ? (context->field = field) : (field = context->field))

// The field should be an array
#define SAVE_POP_CONTEXT_ARRAY(field) \
  (save ? MemoryCopy(context->field, field, sizeof(field)) : MemoryCopy(field, context->field, sizeof(field)))

// The field is a structure.
#define SAVE_POP_CONTEXT_OBJECT(field) \
  (save ? MemoryCopy(&context->field, &field, sizeof(field)) : MemoryCopy(&field, &context->field, sizeof(field)))

  int i = 0;

  //*** Crypto Self-Test Values
  SAVE_POP_CONTEXT_ARRAY(g_implementedAlgorithms);

  SAVE_POP_CONTEXT_ARRAY(g_toTest);

  //*** g_exclusiveAuditSession
  // This location holds the session handle for the current exclusive audit
  // session. If there is no exclusive audit session, the location is set to
  // TPM_RH_UNASSIGNED.
  SAVE_POP_CONTEXT_FIELD(g_exclusiveAuditSession);

  //*** g_time
  // This is the value in which we keep the current command time. This is initialized
  // at the start of each command. The time is the accumulated time since the last
  // time that the TPM's timer was last powered up. Clock is the accumulated time
  // since the last time that the TPM was cleared. g_time is in mS.
  SAVE_POP_CONTEXT_FIELD(g_time);

//*** g_timeEpoch
// This value contains the current clock Epoch. It changes when there is a clock
// discontinuity. It may be necessary to place this in NV should the timer be able
// to run across a power down of the TPM but not in all cases (e.g. dead battery).
// If the nonce is placed in NV, it should go in gp because it should be changing
// slowly.
#if CLOCK_STOPS
  SAVE_POP_CONTEXT_FIELD(g_timeEpoch);
#else
// #define g_timeEpoch      gp.timeEpoch
#endif

  //*** g_phEnable
  // This is the platform hierarchy control and determines if the platform hierarchy
  // is available. This value is SET on each TPM2_Startup(). The default value is
  // SET.
  SAVE_POP_CONTEXT_FIELD(g_phEnable);

  //*** g_pcrReConfig
  // This value is SET if a TPM2_PCR_Allocate command successfully executed since
  // the last TPM2_Startup(). If so, then the next shutdown is required to be
  // Shutdown(CLEAR).
  SAVE_POP_CONTEXT_FIELD(g_pcrReConfig);

  //*** g_DRTMHandle
  // This location indicates the sequence object handle that holds the DRTM
  // sequence data. When not used, it is set to TPM_RH_UNASSIGNED. A sequence
  // DRTM sequence is started on either _TPM_Init or _TPM_Hash_Start.
  SAVE_POP_CONTEXT_FIELD(g_DRTMHandle);

  //*** g_DrtmPreStartup
  // This value indicates that an H-CRTM occurred after _TPM_Init but before
  // TPM2_Startup(). The define for PRE_STARTUP_FLAG is used to add the
  // g_DrtmPreStartup value to gp_orderlyState at shutdown. This hack is to avoid
  // adding another NV variable.
  SAVE_POP_CONTEXT_FIELD(g_DrtmPreStartup);

  //*** g_StartupLocality3
  // This value indicates that a TPM2_Startup() occurred at locality 3. Otherwise, it
  // at locality 0. The define for STARTUP_LOCALITY_3 is to
  // indicate that the startup was not at locality 0. This hack is to avoid
  // adding another NV variable.
  SAVE_POP_CONTEXT_FIELD(g_StartupLocality3);

#if USE_DA_USED
  //*** g_daUsed
  // This location indicates if a DA-protected value is accessed during a boot
  // cycle. If none has, then there is no need to increment 'failedTries' on the
  // next non-orderly startup. This bit is merged with gp.orderlyState when
  // gp.orderly is set to SU_NONE_VALUE
  SAVE_POP_CONTEXT_FIELD(g_daUsed);
#endif

  //*** g_updateNV
  // This flag indicates if NV should be updated at the end of a command.
  // This flag is set to UT_NONE at the beginning of each command in ExecuteCommand().
  // This flag is checked in ExecuteCommand() after the detailed actions of a command
  // complete. If the command execution was successful and this flag is not UT_NONE,
  // any pending NV writes will be committed to NV.
  // UT_ORDERLY causes any RAM data to be written to the orderly space for staging
  // the write to NV.
  SAVE_POP_CONTEXT_FIELD(g_updateNV);

  //*** g_powerWasLost
  // This flag is used to indicate if the power was lost. It is SET in _TPM__Init.
  // This flag is cleared by TPM2_Startup() after all power-lost activities are
  // completed.
  // Note: When power is applied, this value can come up as anything. However,
  // _plat__WasPowerLost() will provide the proper indication in that case. So, when
  // power is actually lost, we get the correct answer. When power was not lost, but
  // the power-lost processing has not been completed before the next _TPM_Init(),
  // then the TPM still does the correct thing.
  SAVE_POP_CONTEXT_FIELD(g_powerWasLost);

  //*** g_clearOrderly
  // This flag indicates if the execution of a command should cause the orderly
  // state to be cleared.  This flag is set to FALSE at the beginning of each
  // command in ExecuteCommand() and is checked in ExecuteCommand() after the
  // detailed actions of a command complete but before the check of
  // 'g_updateNV'. If this flag is TRUE, and the orderly state is not
  // SU_NONE_VALUE, then the orderly state in NV memory will be changed to
  // SU_NONE_VALUE or SU_DA_USED_VALUE.
  SAVE_POP_CONTEXT_FIELD(g_clearOrderly);

  //*** g_prevOrderlyState
  // This location indicates how the TPM was shut down before the most recent
  // TPM2_Startup(). This value, along with the startup type, determines if
  // the TPM should do a TPM Reset, TPM Restart, or TPM Resume.
  SAVE_POP_CONTEXT_FIELD(g_prevOrderlyState);

  //*** g_nvOk
  // This value indicates if the NV integrity check was successful or not. If not and
  // the failure was severe, then the TPM would have been put into failure mode after
  // it had been re-manufactured. If the NV failure was in the area where the state-save
  // data is kept, then this variable will have a value of FALSE indicating that
  // a TPM2_Startup(CLEAR) is required.
  SAVE_POP_CONTEXT_FIELD(g_nvOk);
  // NV availability is sampled as the start of each command and stored here
  // so that its value remains consistent during the command execution
  SAVE_POP_CONTEXT_FIELD(g_NvStatus);

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
  // MemoryCopy2B(&g_platformUniqueAuthorities.b, &context->g_platformUniqueAuthorities.b, sizeof(TPMU_HA));
  SAVE_POP_CONTEXT_OBJECT(g_platformUniqueAuthorities);

  // MemoryCopy2B(&g_platformUniqueDetails.b, &context->g_platformUniqueDetails.b, sizeof(TPMU_HA));
  SAVE_POP_CONTEXT_OBJECT(g_platformUniqueDetails);

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

  // MemoryCopy(&gp, &context->gp, sizeof(PERSISTENT_DATA));
  SAVE_POP_CONTEXT_OBJECT(gp);

//*********************************************************************************
//*********************************************************************************
//*** ORDERLY_DATA
//*********************************************************************************
//*********************************************************************************
// The data in this structure is saved to NV on each TPM2_Shutdown().
#if ACCUMULATE_SELF_HEAL_TIMER
// #define     s_selfHealTimer     go.selfHealTimer
// #define     s_lockoutTimer      go.lockoutTimer
#endif // ACCUMULATE_SELF_HEAL_TIMER

  // #  define drbgDefault go.drbgState

  // MemoryCopy(&go, &context->go, sizeof(ORDERLY_DATA));
  SAVE_POP_CONTEXT_OBJECT(go);

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
  // MemoryCopy(&gc, &context->gc, sizeof(STATE_CLEAR_DATA));
  SAVE_POP_CONTEXT_OBJECT(gc);

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
  // MemoryCopy(&gr, &context->gr, sizeof(STATE_RESET_DATA));
  SAVE_POP_CONTEXT_OBJECT(gr);

  //*****************************************************************************
  //** From CryptTest.c
  //*****************************************************************************
  // This structure contains the self-test state values for the cryptographic modules.
  SAVE_POP_CONTEXT_FIELD(g_cryptoSelfTestState.rng);
  SAVE_POP_CONTEXT_FIELD(g_cryptoSelfTestState.hash);
  SAVE_POP_CONTEXT_FIELD(g_cryptoSelfTestState.sym);
#if ALG_RSA
  SAVE_POP_CONTEXT_FIELD(g_cryptoSelfTestState.rsa);
#endif
#if ALG_ECC
  SAVE_POP_CONTEXT_FIELD(g_cryptoSelfTestState.ecc);
#endif

  //*****************************************************************************
  //** From Manufacture.c
  //*****************************************************************************
  SAVE_POP_CONTEXT_FIELD(g_manufactured);

  // This value indicates if a TPM2_Startup commands has been
  // receive since the power on event.  This flag is maintained in power
  // simulation module because this is the only place that may reliably set this
  // flag to FALSE.
  SAVE_POP_CONTEXT_FIELD(g_initialized);

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
  // MemoryCopy(s_sessionHandles, context->s_sessionHandles, sizeof(s_sessionHandles[MAX_SESSION_NUM]));
  SAVE_POP_CONTEXT_ARRAY(s_sessionHandles);

  // Array of authorization session attributes
  // MemoryCopy(s_attributes, context->s_attributes, sizeof(s_attributes[MAX_SESSION_NUM]));
  SAVE_POP_CONTEXT_ARRAY(s_attributes);

  // Array of handles authorized by the corresponding authorization sessions;
  // and if none, then TPM_RH_UNASSIGNED value is used
  // MemoryCopy(s_associatedHandles, context->s_associatedHandles, sizeof(s_associatedHandles[MAX_SESSION_NUM]));
  SAVE_POP_CONTEXT_ARRAY(s_associatedHandles);

  // Array of nonces provided by the caller for the corresponding sessions
  for (i = 0; i < MAX_SESSION_NUM; i++)
  {
    SAVE_POP_CONTEXT_OBJECT(s_nonceCaller[i]);
  }

  // Array of authorization values (HMAC's or passwords) for the corresponding
  // sessions
  // MemoryCopy(s_inputAuthValues, sizeof(s_inputAuthValues[MAX_SESSION_NUM]));
  for (i = 0; i < MAX_SESSION_NUM; i++)
  {
    SAVE_POP_CONTEXT_OBJECT(s_inputAuthValues[i]);
  }

  // Array of pointers to the SESSION structures for the sessions in a command
  // SESSION *s_usedSessions[MAX_SESSION_NUM];

  // Index of the session used for encryption of a response parameter
  SAVE_POP_CONTEXT_FIELD(s_encryptSessionIndex);

  // Index of the session used for decryption of a command parameter
  SAVE_POP_CONTEXT_FIELD(s_decryptSessionIndex);

  // Index of a session used for audit
  SAVE_POP_CONTEXT_FIELD(s_auditSessionIndex);

// The cpHash for command audit
#ifdef TPM_CC_GetCommandAuditDigest
  SAVE_POP_CONTEXT_OBJECT(s_cpHashForCommandAudit);
#endif

  // Flag indicating if NV update is pending for the lockOutAuthEnabled or
  // failedTries DA parameter
  SAVE_POP_CONTEXT_FIELD(s_DAPendingOnNV);

#endif // SESSION_PROCESS_C

//*****************************************************************************
//*** From DA.c
//*****************************************************************************
#if defined DA_C || defined GLOBAL_C || defined MANUFACTURE_C || defined TPM_CONTEXT_C
// This variable holds the accumulated time since the last time
// that 'failedTries' was decremented. This value is in millisecond.
#if !ACCUMULATE_SELF_HEAL_TIMER
  SAVE_POP_CONTEXT_FIELD(s_selfHealTimer);

  // This variable holds the accumulated time that the lockoutAuth has been
  // blocked.
  SAVE_POP_CONTEXT_FIELD(s_lockoutTimer);
#endif // ACCUMULATE_SELF_HEAL_TIMER

#endif // DA_C

//*****************************************************************************
//*** From NV.c
//*****************************************************************************
#if defined NV_C || defined GLOBAL_C || defined TPM_CONTEXT_C
  // This marks the end of the NV area. This is a run-time variable as it might
  // not be compile-time constant.
  SAVE_POP_CONTEXT_FIELD(s_evictNvEnd);

  // This space is used to hold the index data for an orderly Index. It also contains
  // the attributes for the index.
  SAVE_POP_CONTEXT_ARRAY(s_indexOrderlyRam); // The orderly NV Index data

  // This value contains the current max counter value. It is written to the end of
  // allocatable NV space each time an index is deleted or added. This value is
  // initialized on Startup. The indices are searched and the maximum of all the
  // current counter indices and this value is the initial value for this.
  SAVE_POP_CONTEXT_FIELD(s_maxCounter);

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
  SAVE_POP_CONTEXT_OBJECT(s_cachedNvIndex);

  SAVE_POP_CONTEXT_FIELD(s_cachedNvRef);
  SAVE_POP_CONTEXT_FIELD(s_cachedNvRamRef);

#endif

//*****************************************************************************
//*** From Object.c
//*****************************************************************************
#if defined OBJECT_C || defined GLOBAL_C || defined TPM_CONTEXT_C
  // This type is the container for an object.

  for (i = 0; i < MAX_LOADED_OBJECTS; i++)
  {
    SAVE_POP_CONTEXT_OBJECT(s_objects[i]);
  }

#endif // OBJECT_C

//*****************************************************************************
//*** From PCR.c
//*****************************************************************************
#if defined PCR_C || defined GLOBAL_C || defined TPM_CONTEXT_C
  for (i = 0; i < IMPLEMENTATION_PCR; i++)
  {
    SAVE_POP_CONTEXT_OBJECT(s_pcrs[i]);
  }

#endif // PCR_C

//*****************************************************************************
//*** From Session.c
//*****************************************************************************
#if defined SESSION_C || defined GLOBAL_C || defined TPM_CONTEXT_C

  for (i = 0; i < MAX_LOADED_SESSIONS; i++)
  {
    SAVE_POP_CONTEXT_OBJECT(s_sessions[i]);
  }

  //  The index in contextArray that has the value of the oldest saved session
  //  context. When no context is saved, this will have a value that is greater
  //  than or equal to MAX_ACTIVE_SESSIONS.
  SAVE_POP_CONTEXT_FIELD(s_oldestSavedSession);

  // The number of available session slot openings.  When this is 1,
  // a session can't be created or loaded if the GAP is maxed out.
  // The exception is that the oldest saved session context can always
  // be loaded (assuming that there is a space in memory to put it)
  SAVE_POP_CONTEXT_FIELD(s_freeSessionSlots);

#endif // SESSION_C

//*****************************************************************************
//*** From IoBuffers.c
//*****************************************************************************
#if defined IO_BUFFER_C || defined GLOBAL_C || defined TPM_CONTEXT_C
  // Each command function is allowed a structure for the inputs to the function and
  // a structure for the outputs. The command dispatch code unmarshals the input butter
  // to the command action input structure starting at the first byte of
  // s_actionIoBuffer. The value of s_actionIoAllocation is the number of UINT64 values
  // allocated. It is used to set the pointer for the response structure. The command
  // dispatch code will marshal the response values into the final output buffer.
  SAVE_POP_CONTEXT_ARRAY(s_actionIoBuffer);     // action I/O buffer
  SAVE_POP_CONTEXT_FIELD(s_actionIoAllocation); // number of UIN64 allocated for the
                                                // action input structure
#endif                                          // IO_BUFFER_C

  //*****************************************************************************
  //*** From TPMFail.c
  //*****************************************************************************
  // This value holds the address of the string containing the name of the function
  // in which the failure occurred. This address value is not useful for anything
  // other than helping the vendor to know in which file the failure  occurred.
  SAVE_POP_CONTEXT_FIELD(g_inFailureMode); // Indicates that the TPM is in failure mode
#if SIMULATION
  SAVE_POP_CONTEXT_FIELD(g_forceFailureMode); // flag to force failure mode during test
#endif

#if defined TPM_FAIL_C || defined GLOBAL_C || defined TPM_CONTEXT_C
  SAVE_POP_CONTEXT_FIELD(s_failFunction);
  SAVE_POP_CONTEXT_FIELD(s_failLine); // the line in the file at which
                                      // the error was signaled
  SAVE_POP_CONTEXT_FIELD(s_failCode); // the error code used

  SAVE_POP_CONTEXT_FIELD(LibFailCallback);

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
  SAVE_POP_CONTEXT_FIELD(s_ActUpdated);

  //*****************************************************************************
  //*** From PlatformData.h
  //*****************************************************************************

  SAVE_POP_CONTEXT_FIELD(s_isCanceled);

  // #ifndef HARDWARE_CLOCK
  // typedef uint64_t     clock64_t;
  // This is the value returned the last time that the system clock was read. This
  // is only relevant for a simulator or virtual TPM.
  SAVE_POP_CONTEXT_FIELD(s_realTimePrevious);

  // These values are used to try to synthesize a long lived version of clock().
  SAVE_POP_CONTEXT_FIELD(s_lastSystemTime);
  SAVE_POP_CONTEXT_FIELD(s_lastReportedTime);

  // This is the rate adjusted value that is the equivalent of what would be read from
  // a hardware register that produced rate adjusted time.
  SAVE_POP_CONTEXT_FIELD(s_tpmTime);

  // This value indicates that the timer was reset
  SAVE_POP_CONTEXT_FIELD(s_timerReset);
  // This value indicates that the timer was stopped. It causes a clock discontinuity.
  SAVE_POP_CONTEXT_FIELD(s_timerStopped);

  // This variable records the time when _plat__TimerReset is called.  This mechanism
  // allow us to subtract the time when TPM is power off from the total
  // time reported by clock() function
  SAVE_POP_CONTEXT_FIELD(s_initClock);

  // This variable records the timer adjustment factor.
  SAVE_POP_CONTEXT_FIELD(s_adjustRate);

  // For LocalityPlat.c
  // Locality of current command
  SAVE_POP_CONTEXT_FIELD(s_locality);

  SAVE_POP_CONTEXT_ARRAY(s_NV);
  SAVE_POP_CONTEXT_FIELD(s_NvIsAvailable);
  SAVE_POP_CONTEXT_FIELD(s_NV_unrecoverable);
  SAVE_POP_CONTEXT_FIELD(s_NV_recoverable);

  // For PPPlat.c
  // Physical presence.  It is initialized to FALSE
  SAVE_POP_CONTEXT_FIELD(s_physicalPresence);

  // From Power
  SAVE_POP_CONTEXT_FIELD(s_powerLost);

  // For Entropy.c
  SAVE_POP_CONTEXT_FIELD(lastEntropy);

#define POP_ACT(N) SAVE_POP_CONTEXT_OBJECT(ACT_##N);
  FOR_EACH_ACT(POP_ACT)

  SAVE_POP_CONTEXT_FIELD(actTicksAllowed);
}

void PopTpmContext(
    UINT128 contextId)
{
  int i = 0;
  TPM_CONTEXT *context = NULL;

  // first find out the slot
  for (; i < MAX_TPM_CONTEXT_COUNT; i++)
  {
    if (g_TpmContextIdList[i] == contextId)
    {
      break;
    }
  }

  if (i == MAX_TPM_CONTEXT_COUNT)
  {
    // the contextId doesn't exist
    // so let's find an empty slot.
    for (i = 0; i < MAX_TPM_CONTEXT_COUNT; i++)
    {
      if (g_TpmContextIdList[i] == 0)
      {
        break;
      }
    }

    pAssert(i < MAX_TPM_CONTEXT_COUNT);
    pAssert(g_CurrentTpmContextCnt < MAX_TPM_CONTEXT_COUNT);
    g_TpmContextIdList[i] = contextId;
    g_CurrentTpmContextCnt++;
  }

  context = &g_TpmContextContentList[i];

  _SavePopContext(context, FALSE);
}

void SaveTpmContext(
    UINT128 contextId)
{
  int i = 0;
  TPM_CONTEXT *context = NULL;

  for (; i < MAX_TPM_CONTEXT_COUNT; i++)
  {
    if (g_TpmContextIdList[i] == contextId)
    {
      break;
    }
  }

  if (g_CurrentTpmContextCnt == MAX_TPM_CONTEXT_COUNT && i == MAX_TPM_CONTEXT_COUNT)
  {
    // the slots are full
    // We will handle this situation later.
    // Now we assume this will never happen
    pAssert(FALSE);
  }

  if (i == MAX_TPM_CONTEXT_COUNT)
  {
    // This is a new context. Let's find an empty slot
    for (i = 0; i < MAX_TPM_CONTEXT_COUNT; i++)
    {
      if (g_TpmContextIdList[i] == 0)
      {
        break;
      }
    }

    pAssert(i < MAX_TPM_CONTEXT_COUNT);
    pAssert(g_CurrentTpmContextCnt < MAX_TPM_CONTEXT_COUNT);
    g_TpmContextIdList[i] = contextId;
    g_CurrentTpmContextCnt++;
  }

  context = &g_TpmContextContentList[i];

  _SavePopContext(context, TRUE);
}

uint64_t
ReadTsc(
  void
)
{
  uint32_t LowData;
  uint32_t HiData;

  __asm__ __volatile__ (
    "rdtsc"
    : "=a" (LowData),
      "=d" (HiData)
  );

	return ((uint64_t)HiData << 32) | LowData;
}

uint64_t
GetSwitchTimeUsed(
    void
)
{
  return g_TpmContextSwitchTime;
}

void SwitchTpmContext(
    UINT128 contextId)
{
  uint64_t start, end;

  // if contextId is 0, it means there is no context-switch.
  if (contextId == 0)
  {
    return;
  }

  if (g_CurrentTpmContextId == contextId)
  {
    // we don't need to switch TpmContext
    goto _finish;
  }

  // if this is the first TpmContext, then we don't do save and pop
  if (g_CurrentTpmContextId != 0)
  {
    start = ReadTsc();
    SaveTpmContext(g_CurrentTpmContextId);
    PopTpmContext(contextId);
    end = ReadTsc();
    g_TpmContextSwitchTime += (end - start);
  }

  g_CurrentTpmContextId = contextId;

_finish:
  return;
}

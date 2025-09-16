//
// repo:			windows_ssh_service
// file:            main_windows_ssh_service.c
// path:			src/core/windows_ssh_service/main_windows_ssh_service.c
// created on:		2024 Mar 08
// created by:		Davit Kalantaryan (davit.kalantaryan@desy.de)
//


#include <winexetoservice/export_symbols.h>
#include <cinternal/disable_compiler_warnings.h>
#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>
#include <cinternal/undisable_compiler_warnings.h>

#define READ_BUFFER_SIZE_MIN1   2046
#define READ_BUFFER_SIZE        2047
#define MAX_BUFFER_SIZE_TRM1    4096
#define MAX_BUFFER_SIZE_MIN_1   8191
#define MAX_BUFFER_SIZE         8192
#define CONFIG_FILE_NAME                    "config.conf"
#define CONFIG_FILE_NAME_LEN_PLUS_1          sizeof(CONFIG_FILE_NAME)

#ifndef container_of
#define container_of(_ptr,_type,_member) (_type*)(  ((char*)(_ptr)) + (size_t)( (char*)(&((_type *)0)->_member) )  )
#endif


typedef struct SConfigParams {
    const char* m_pcServiceName;
    const char* m_pcCommandLine;
    const char* m_pcInit;
    const char* m_pcExecFilePath;
    const char* m_pcExecDirectory;
    char*       m_pcBuffer;
    size_t      m_execFilePathLen;
    size_t      m_execDirectoryLen;
    HANDLE      m_hStdOuts;
    HANDLE      m_inputPipe;
    char        m_cOption;  
    bool        m_bIsService; 
    bool        reserved02[sizeof(void*)-sizeof(bool)-sizeof(char)];
} SConfigParams;

typedef struct SOverlappedStr {
    OVERLAPPED                  m_overlapped;
    HANDLE                      m_hEventSource;
    const struct SConfigParams* m_cpSrvParams;
    bool                        m_bContinueOverrlapped;
    char                        m_buffer[READ_BUFFER_SIZE];
}SOverlappedStr;

static DWORD WINAPI ServiceStartThreadProcStatic(_In_ LPVOID a_pArg) CPPUTILS_NOEXCEPT;
static DWORD WINAPI PipeReadThreadProcStatic(_In_ LPVOID a_pArg) CPPUTILS_NOEXCEPT;
static VOID WINAPI ServiceMainFunctionStatic(DWORD a_dwNumServicesArgs, LPSTR* a_lpServiceArgVectors) CPPUTILS_NOEXCEPT;
static DWORD WINAPI MonitoringServiceCtrlEx(DWORD a_dwControl, DWORD a_dwEventType, LPVOID a_lpEventData, LPVOID a_lpContext) CPPUTILS_NOEXCEPT;
static int CreateServiceProcessStatic(const SConfigParams* CPPUTILS_ARG_NN a_cpSrvParams, PROCESS_INFORMATION* CPPUTILS_ARG_NN a_pProcInfo) CPPUTILS_NOEXCEPT;
static const SConfigParams* GetServiceParametersStatic(int a_argc, char* a_argv[]) CPPUTILS_NOEXCEPT;
static void ClearServiceParameters(const SConfigParams* CPPUTILS_ARG_NN a_cpSrvParams) CPPUTILS_NOEXCEPT;
static VOID WINAPI OverlappedCompletionRoutineStatic(_In_ DWORD a_dwErrorCode, _In_ DWORD a_dwNumberOfBytesTransfered, _Inout_ LPOVERLAPPED a_lpOverlapped) CPPUTILS_NOEXCEPT;
static int InstallUninstallServiceStatic(const SConfigParams* CPPUTILS_ARG_NN a_cpSrvParams) CPPUTILS_NOEXCEPT;
static void NTAPI WinInterruptFunction(ULONG_PTR a_arg) CPPUTILS_NOEXCEPT { (void)a_arg; }

static DWORD	s_dwServiceMainThreadId2 = 0;
static DWORD	s_dwServiceStartThreadId = 0;
static DWORD	s_dwExeMainThreadId = 0;
static DWORD	s_dwPipeThreadId = 0;
static SERVICE_STATUS           ssStatus;
static SERVICE_STATUS_HANDLE    sshStatusHandle = CPPUTILS_NULL;
static bool s_bShoodWork = false;
static const SConfigParams* s_pSrvParams = CPPUTILS_NULL;


int main(int a_argc, char* a_argv[])
{
    PROCESS_INFORMATION procInfo;
    HANDLE	serviceStartThreadHandle = CPPUTILS_NULL;
    HANDLE	pipeThreadHandle = CPPUTILS_NULL;
    DWORD dwWaitRet;
    bool bShallCreateProcess;
    int nCreateProcRet;
    const SConfigParams* const pSrvParams = GetServiceParametersStatic(a_argc, a_argv);

    if (!pSrvParams) {
        // todo: report on failure
        return 1;
    }

    s_pSrvParams = pSrvParams; // todo: if windows has data providing to service function, then skip this

    s_bShoodWork = true;
    s_dwExeMainThreadId = GetCurrentThreadId();

    switch (pSrvParams->m_cOption) {
    case 'a':  //  we have usual application
        break;
    case 's':  // we have service
        pipeThreadHandle = CreateThread(CPPUTILS_NULL, 0, &PipeReadThreadProcStatic, (SConfigParams*)pSrvParams, 0, &s_dwPipeThreadId);
        if (!pipeThreadHandle) {
            ClearServiceParameters(pSrvParams);
            ExitProcess(1);
        }
        serviceStartThreadHandle = CreateThread(CPPUTILS_NULL, 0, &ServiceStartThreadProcStatic, (SConfigParams*)pSrvParams, 0, &s_dwServiceStartThreadId);
        if (!serviceStartThreadHandle) {
            s_bShoodWork = false;
            QueueUserAPC(&WinInterruptFunction, pipeThreadHandle, 0);
            WaitForSingleObject(pipeThreadHandle, INFINITE);
            CloseHandle(pipeThreadHandle);
            ClearServiceParameters(pSrvParams);
            ExitProcess(1);
        }
        break;
    default: // we have installation or uninstallation
        nCreateProcRet = InstallUninstallServiceStatic(pSrvParams);
        ClearServiceParameters(pSrvParams);
        return nCreateProcRet;
    }  //  switch (ccOptin) {

    bShallCreateProcess = true;
    procInfo.hProcess = CPPUTILS_NULL;
    procInfo.hThread = CPPUTILS_NULL;

    while (s_bShoodWork) {
        if (bShallCreateProcess) {
            // "ssh -i C:\\Users\\kalantar\\.ssh\\id_rsa -R *:17389:localhost:3389 kalantar@dev001.focust.io"
            nCreateProcRet = CreateServiceProcessStatic(pSrvParams,&procInfo);
            if (nCreateProcRet) {
                //QtUtilsCritical() << "Unable create process"; // todo:
                SleepEx(1000, TRUE);
                continue;
            }
            bShallCreateProcess = false;
        }  //   if (bShallCreateProcess) {

        dwWaitRet = WaitForSingleObjectEx(procInfo.hProcess, INFINITE, TRUE);
        switch (dwWaitRet) {
        case WAIT_OBJECT_0: {
            if (procInfo.hThread) {
                CloseHandle(procInfo.hThread);
            }
            if (procInfo.hProcess) {
                CloseHandle(procInfo.hProcess);
            }
            bShallCreateProcess = true;
            procInfo.hProcess = CPPUTILS_NULL;
            procInfo.hThread = CPPUTILS_NULL;
            if (s_bShoodWork) {
                SleepEx(2000, TRUE);
            }
        }break;
        default:
            break;
        }  //   switch (dwWaitRet) {

    }  //  while (s_bShoodWork) {

    s_dwExeMainThreadId = 0;

    if (procInfo.hProcess) {
        TerminateProcess(procInfo.hProcess,1);
        WaitForSingleObject(procInfo.hProcess, INFINITE);
    }

    if (procInfo.hThread) {
        CloseHandle(procInfo.hThread);
    }
    if (procInfo.hProcess) {
        CloseHandle(procInfo.hProcess);
    }

    if (serviceStartThreadHandle) {
        WaitForSingleObjectEx(serviceStartThreadHandle, INFINITE, TRUE);
        s_dwServiceStartThreadId = 0;
        CloseHandle(serviceStartThreadHandle);
    }  //  if (serviceMainThreadHandle) {

    if (pipeThreadHandle) {
        WaitForSingleObjectEx(pipeThreadHandle, INFINITE, TRUE);
        s_dwPipeThreadId = 0;
        CloseHandle(pipeThreadHandle);
    }  //  if (s_serviveMainThreadHandle) {

    ClearServiceParameters(pSrvParams);

	return 0;
}


static inline bool MonitoringServiceInitializeInline(const SConfigParams* CPPUTILS_ARG_NN a_cpSrvParams) CPPUTILS_NOEXCEPT  {
    if (sshStatusHandle) {
        return true;
    }

    sshStatusHandle = RegisterServiceCtrlHandlerExA(a_cpSrvParams->m_pcServiceName, &MonitoringServiceCtrlEx, (SConfigParams*)a_cpSrvParams);
    if (!sshStatusHandle) return false;
    ssStatus.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
    ssStatus.dwServiceSpecificExitCode = 0;
    ssStatus.dwCurrentState = SERVICE_START_PENDING;
    ssStatus.dwControlsAccepted = SERVICE_ACCEPT_STOP | SERVICE_ACCEPT_SHUTDOWN;
    ssStatus.dwWin32ExitCode = NO_ERROR;
    ssStatus.dwCheckPoint = 0;
    ssStatus.dwWaitHint = 3000;
    SetServiceStatus(sshStatusHandle, &ssStatus);

    return true;
}


static inline VOID UpdateStatusInline(int a_newStatus, int a_check) CPPUTILS_NOEXCEPT  {
    if (a_check < 0)	ssStatus.dwCheckPoint++;
    else			ssStatus.dwCheckPoint = CPPUTILS_STATIC_CAST(DWORD, a_check);
    if (a_newStatus >= 0)	ssStatus.dwCurrentState = CPPUTILS_STATIC_CAST(DWORD, a_newStatus);
    SetServiceStatus(sshStatusHandle, &ssStatus);
    return;
}


static inline void MonitoringServiceMarkAsDoneInline(void) CPPUTILS_NOEXCEPT  {
    ssStatus.dwServiceSpecificExitCode = 0;
    ssStatus.dwCurrentState = SERVICE_STOPPED;
    SetServiceStatus(sshStatusHandle, &ssStatus);
    UpdateStatusInline(SERVICE_STOPPED, 0);
}


static int CreateServiceProcessStatic(const SConfigParams* CPPUTILS_ARG_NN a_cpSrvParams, PROCESS_INFORMATION* CPPUTILS_ARG_NN a_pProcInfo) CPPUTILS_NOEXCEPT
{
    STARTUPINFOA si;
    BOOL bCreateProcRet;
    char* const pcCommandLine = _strdup(a_cpSrvParams->m_pcCommandLine);
    BOOL bHandleInheritance;
    DWORD dwCreationFlags;

    if (!pcCommandLine) {
        // todo: log on low memory
        ExitProcess(1);
    }

    ZeroMemory(&si, sizeof(si));
    si.cb = sizeof(si);

    if (a_cpSrvParams->m_bIsService) {
        si.dwFlags |= (STARTF_USESHOWWINDOW| STARTF_USESTDHANDLES);
        si.wShowWindow = SW_HIDE;
        si.cb = sizeof(si);
        si.hStdOutput = a_cpSrvParams->m_hStdOuts;
        si.hStdError = a_cpSrvParams->m_hStdOuts;
        si.hStdInput = CPPUTILS_NULL;
        bHandleInheritance = TRUE;
        dwCreationFlags = CREATE_NO_WINDOW;
    }
    else {
        //si.hStdInput = GetStdHandle(STD_INPUT_HANDLE);
        bHandleInheritance = FALSE;
        dwCreationFlags = 0;
    }

    bCreateProcRet = CreateProcessA(
        NULL,						// ssh
        pcCommandLine,				// Command line
        NULL,						// Process handle not inheritable
        NULL,						// Thread handle not inheritable
        bHandleInheritance,			// Set handle inheritance to FALSE
        dwCreationFlags,			// No creation flags
        NULL,						// Use parent's environment block
        NULL,						// Use parent's starting directory 
        &si,						// Pointer to STARTUPINFO structure
        a_pProcInfo);	            // Pointer to PROCESS_INFORMATION structure

    free(pcCommandLine);

    return bCreateProcRet ? 0 : 1;
}


static DWORD WINAPI MonitoringServiceCtrlEx(DWORD a_dwControl, DWORD a_dwEventType, LPVOID a_lpEventData, LPVOID a_lpContext) CPPUTILS_NOEXCEPT
{

    const SConfigParams* const cpSrvParams = (SConfigParams*)a_lpContext;
    (void)a_dwEventType;
    (void)a_lpEventData;
    (void)cpSrvParams;

    switch (a_dwControl){
    case SERVICE_CONTROL_STOP:
    case SERVICE_CONTROL_SHUTDOWN: {
        s_bShoodWork = false;
        UpdateStatusInline(SERVICE_STOP_PENDING, -1);
        const DWORD dwThreadId = GetCurrentThreadId();
        if ((dwThreadId != s_dwServiceMainThreadId2) && s_dwServiceMainThreadId2) {
            const HANDLE serviceMainThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, s_dwServiceMainThreadId2);
            if (serviceMainThreadHandle) {
                QueueUserAPC(&WinInterruptFunction, serviceMainThreadHandle, 0);
                CloseHandle(serviceMainThreadHandle);
            }
            else {
                //QtUtilsCritical() << "Unable open thread"; // todo:
            }
        }
        if ((dwThreadId != s_dwServiceStartThreadId)&& s_dwServiceStartThreadId) {
            const HANDLE serviceStartThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, s_dwServiceStartThreadId);
            if (serviceStartThreadHandle) {
                QueueUserAPC(&WinInterruptFunction, serviceStartThreadHandle, 0);
                CloseHandle(serviceStartThreadHandle);
            }
            else {
                //QtUtilsCritical() << "Unable open thread"; // todo:
            }
        }
        if ((dwThreadId != s_dwPipeThreadId)&& s_dwPipeThreadId) {
            const HANDLE pipeThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, s_dwPipeThreadId);
            if (pipeThreadHandle) {
                QueueUserAPC(&WinInterruptFunction, pipeThreadHandle, 0);
                CloseHandle(pipeThreadHandle);
            }
            else {
                //QtUtilsCritical() << "Unable open thread"; // todo:
            }
        }
        if ((dwThreadId != s_dwExeMainThreadId)&& s_dwExeMainThreadId) {
            const HANDLE exeMainThreadHandle = OpenThread(THREAD_ALL_ACCESS, FALSE, s_dwExeMainThreadId);
            if (exeMainThreadHandle) {
                QueueUserAPC(&WinInterruptFunction, exeMainThreadHandle, 0);
                CloseHandle(exeMainThreadHandle);
            }
            else {
                //QtUtilsCritical() << "Unable open thread"; // todo:
            }
        }  //  if (dwThreadId != s_dwMainThreadId) {
    }
    //return NO_ERROR;
    break;
    case SERVICE_CONTROL_INTERROGATE:
        UpdateStatusInline(-1, -1);
        break;
        //return NO_ERROR;
    default:
        return ERROR_CALL_NOT_IMPLEMENTED;
    }  //  switch (a_dwControl){

    return NO_ERROR;

}


static DWORD WINAPI ServiceStartThreadProcStatic(_In_ LPVOID a_pArg) CPPUTILS_NOEXCEPT
{
    const SConfigParams* const cpSrvParams = (SConfigParams*)a_pArg;

    const SERVICE_TABLE_ENTRYA dispatchTable[] =
    {
        { (char*)(cpSrvParams->m_pcServiceName), &ServiceMainFunctionStatic },
        { CPPUTILS_NULL, CPPUTILS_NULL }
    };

    StartServiceCtrlDispatcherA(dispatchTable);

    return 0;
}


static VOID WINAPI ServiceMainFunctionStatic(DWORD a_dwNumServicesArgs, LPSTR* a_lpServiceArgVectors) CPPUTILS_NOEXCEPT
{
    //if ((a_dwNumServicesArgs > 0) && (a_lpServiceArgVectors[0])) {
    //    switch ((a_lpServiceArgVectors[0])[0]) {
    //    case 'u':
    //        g_startReason = StartReason::Update;
    //        break;
    //    case 'i':
    //        g_startReason = StartReason::Install;
    //        break;
    //    default:
    //        g_startReason = StartReason::HostStart;
    //        break;
    //    }
    //}
    //else {
    //    g_startReason = StartReason::HostStart;
    //}

    (void)a_dwNumServicesArgs;
    (void)a_lpServiceArgVectors;

    s_dwServiceMainThreadId2 = GetCurrentThreadId();

    if (!MonitoringServiceInitializeInline(s_pSrvParams)) {
        s_bShoodWork = false;
        return;
    }

    UpdateStatusInline(SERVICE_RUNNING, -1);

    while (s_bShoodWork) {
        SleepEx(INFINITE, TRUE);
    }
    MonitoringServiceMarkAsDoneInline();

}


static DWORD WINAPI PipeReadThreadProcStatic(_In_ LPVOID a_pArg) CPPUTILS_NOEXCEPT
{
    SOverlappedStr ovrlpdStr;
    const SConfigParams* const cpSrvParams = (SConfigParams*)a_pArg;
    
    ZeroMemory(&ovrlpdStr, sizeof(ovrlpdStr));
    ovrlpdStr.m_hEventSource = RegisterEventSourceA(CPPUTILS_NULL, cpSrvParams->m_pcServiceName);

    if (ovrlpdStr.m_hEventSource) {
        
        ovrlpdStr.m_cpSrvParams = cpSrvParams;
        ovrlpdStr.m_bContinueOverrlapped = true;

        if (ReadFileEx(cpSrvParams->m_inputPipe, ovrlpdStr.m_buffer, READ_BUFFER_SIZE_MIN1, &(ovrlpdStr.m_overlapped), &OverlappedCompletionRoutineStatic)) {
            while (s_bShoodWork && (ovrlpdStr.m_bContinueOverrlapped)) {
                SleepEx(INFINITE, TRUE);
            }  //  while (s_bShoodWork && (ovrlpdStr.m_bContinueOverrlapped)) {
        }

        DeregisterEventSource(ovrlpdStr.m_hEventSource);

    }  //  if (ovrlpdStr.m_hEventSource) {

    return 0;
}


static VOID WINAPI OverlappedCompletionRoutineStatic(_In_ DWORD a_dwErrorCode, _In_ DWORD a_dwNumberOfBytesTransfered, _Inout_ LPOVERLAPPED a_lpOverlapped) CPPUTILS_NOEXCEPT
{
    SOverlappedStr* const pOverlappedStr = container_of(a_lpOverlapped, SOverlappedStr, m_overlapped);
    (void)a_dwErrorCode;
    if (a_dwNumberOfBytesTransfered > 0) {
        LPCSTR strings[1] = { pOverlappedStr->m_buffer };
        pOverlappedStr->m_buffer[a_dwNumberOfBytesTransfered] = '\0';

        ReportEventA(pOverlappedStr->m_hEventSource,
            EVENTLOG_INFORMATION_TYPE,
            0,
            0,
            NULL,
            1,
            0,
            strings,
            NULL);
    }  //   if (a_dwNumberOfBytesTransfered > 0) {

    if (s_bShoodWork) {
        ZeroMemory(a_lpOverlapped, sizeof(OVERLAPPED));
        if (!ReadFileEx(pOverlappedStr->m_cpSrvParams->m_inputPipe, pOverlappedStr->m_buffer, READ_BUFFER_SIZE_MIN1, a_lpOverlapped, &OverlappedCompletionRoutineStatic)) {
            pOverlappedStr->m_bContinueOverrlapped = false;
        }  //  if (!ReadFileEx(pOverlappedStr->m_cpSrvParams->m_inputPipe, pOverlappedStr->m_buffer, READ_BUFFER_SIZE_MIN1, a_lpOverlapped, &OverlappedCompletionRoutineStatic)) {
    }  // if (s_bShoodWork) {
}


static int InstallUninstallServiceStatic(const SConfigParams* CPPUTILS_ARG_NN a_cpSrvParams) CPPUTILS_NOEXCEPT
{
    SC_HANDLE schSCManager;
    SC_HANDLE schService;
    
    schSCManager = OpenSCManagerA(CPPUTILS_NULL, CPPUTILS_NULL, SC_MANAGER_ALL_ACCESS);
    if (!schSCManager) {
        // todo: report on error
        s_bShoodWork = false;
        return 1;
    }

    schService = OpenServiceA(schSCManager, a_cpSrvParams->m_pcServiceName, SERVICE_ALL_ACCESS);	// need delete access
    if (schService) {
        SERVICE_STATUS servStat;
        ControlService(schService, SERVICE_CONTROL_STOP, &servStat);
        DeleteService(schService);
    }  //  if (schService) {
    else {
        char* const pcTemporarBuffer = (char*)malloc(32+ (size_t)(a_cpSrvParams->m_execFilePathLen));
        if (!pcTemporarBuffer) {
            CloseServiceHandle(schSCManager);
            fprintf(stderr, "Low memory!\n");
            return 1;
        }
        pcTemporarBuffer[0] = '\"';
        memcpy(pcTemporarBuffer+1, a_cpSrvParams->m_pcExecFilePath, (size_t)(a_cpSrvParams->m_execFilePathLen));
        pcTemporarBuffer[a_cpSrvParams->m_execFilePathLen + 1] = '\"';
        pcTemporarBuffer[a_cpSrvParams->m_execFilePathLen + 2] = ' ';
        pcTemporarBuffer[a_cpSrvParams->m_execFilePathLen + 3] = 's';
        pcTemporarBuffer[a_cpSrvParams->m_execFilePathLen + 4] = '\0';
        schService = CreateServiceA(
            schSCManager,
            a_cpSrvParams->m_pcServiceName,
            a_cpSrvParams->m_pcServiceName,
            SERVICE_ALL_ACCESS,
            SERVICE_WIN32_OWN_PROCESS,
            SERVICE_AUTO_START,
            SERVICE_ERROR_NORMAL,
            pcTemporarBuffer,
            CPPUTILS_NULL,
            CPPUTILS_NULL,
            CPPUTILS_NULL,
            CPPUTILS_NULL,
            CPPUTILS_NULL);
        free(pcTemporarBuffer);
        if (schService) {
            LPCSTR srvArgs[] = { "i", CPPUTILS_NULL };
            SC_ACTION scActions[3];
            scActions[0].Type = SC_ACTION_RESTART;
            scActions[0].Delay = 5000;  // 5 seconds
            scActions[1].Type = SC_ACTION_RESTART;
            scActions[1].Delay = 5000;
            scActions[2].Type = SC_ACTION_RESTART;
            scActions[2].Delay = 5000;

            SERVICE_FAILURE_ACTIONS failureActions = {};
            failureActions.dwResetPeriod = INFINITE;
            failureActions.lpRebootMsg = NULL;
            failureActions.lpCommand = NULL;
            failureActions.cActions = 3;
            failureActions.lpsaActions = scActions;

            if (!ChangeServiceConfig2A(schService, SERVICE_CONFIG_FAILURE_ACTIONS, &failureActions)) {
                fprintf(stderr, "Unable to configure service recovery! Error: %lu\n", GetLastError());
            }

            // start service
            StartServiceA(schService, 1, srvArgs);
        }  //  if (schService) { 
        else {
            CloseServiceHandle(schSCManager);
            fprintf(stderr, "Unable to create service!\n");
            return 1;
        }
    }  //  else of 'if (schService) {'

    CloseServiceHandle(schService);
    CloseServiceHandle(schSCManager);

    return 0;
}


static inline char* MemMemInline(const char* CPPUTILS_ARG_NN a_key, size_t a_keyLen, char* CPPUTILS_ARG_NN a_pWholeBuffer, size_t a_wholeBufferLen) CPPUTILS_NOEXCEPT  {
    size_t countToSearch, i;
    if (a_keyLen > a_wholeBufferLen) {
        return CPPUTILS_NULL;
    }

    countToSearch = a_wholeBufferLen - a_keyLen + 1;
    for (i = 0; i < countToSearch; ++i) {
        if (memcmp(a_key, a_pWholeBuffer + i, a_keyLen) == 0) {
            return a_pWholeBuffer + i;
        }
    }  //  for (i = 0; i < countToSearch; ++i) {

    return CPPUTILS_NULL;
}


static void ClearServiceParameters(const SConfigParams* CPPUTILS_ARG_NN a_pSrvParams) CPPUTILS_NOEXCEPT
{
    if (a_pSrvParams->m_hStdOuts) {
        CloseHandle(a_pSrvParams->m_hStdOuts);
    }

    if (a_pSrvParams->m_inputPipe) {
        CloseHandle(a_pSrvParams->m_inputPipe);
    }

    if (a_pSrvParams->m_pcBuffer) {
        free(a_pSrvParams->m_pcBuffer);
    }

    if (a_pSrvParams->m_pcExecDirectory) {
        free((char*)(a_pSrvParams->m_pcExecDirectory));
    }

    if (a_pSrvParams->m_pcExecFilePath) {
        free((char*)(a_pSrvParams->m_pcExecFilePath));
    }

    free((SConfigParams*)a_pSrvParams);
}


static inline char* FindElementByKeyInline(const char* CPPUTILS_ARG_NN a_key, char* CPPUTILS_ARG_NN a_pWholeBuffer, size_t a_wholeBufferLen) CPPUTILS_NOEXCEPT
{
    const size_t keyLen = strlen(a_key);
    size_t scanBufferLen = a_wholeBufferLen;
    char* pcReturn;
    char* pcLast = CPPUTILS_NULL;
    char* pcTmp = MemMemInline(a_key, keyLen,a_pWholeBuffer, a_wholeBufferLen);

    while (pcTmp) {
        pcTmp += keyLen;
        while (isspace(*pcTmp)) { ++pcTmp; }
        if (pcTmp[0]=='=') {
            break;
        }
        scanBufferLen = a_wholeBufferLen - (size_t)(pcTmp - a_pWholeBuffer);
        pcTmp = MemMemInline(a_key, keyLen, pcTmp, scanBufferLen);
    }  //  while (pcTmp) { 

    if (!pcTmp) {
        return CPPUTILS_NULL;
    }

    ++pcTmp;

    while (isspace(*pcTmp)) {++pcTmp;}

    if (pcTmp[0] == 0) {
        return CPPUTILS_NULL;
    }

    if (((*pcTmp) == '\"')||((*pcTmp) == '\'')) {
        const char aTerm = (*pcTmp);
        pcReturn = ++pcTmp;
        while ((*pcTmp)) { 
            if ((*pcTmp) == aTerm) {
                pcLast = pcTmp; 
            }
            else if (pcTmp[0] == '\n') {
                if (!pcLast) {
                    pcLast = pcTmp;
                }
                break;
            }
            ++pcTmp; 
        }  //   while ((*pcTmp)) { 
    }  //  if (isQuotaUsed) {
    else {
        pcReturn = pcTmp;
        while ((*pcTmp)) {
            if (isspace(*pcTmp)) {
                pcLast = pcTmp;
                break;
            }
            ++pcTmp;
        }  //   while ((*pcTmp)) {
    }  //  else of 'if (isQuotaUsed) {'

    if (pcLast) {
        *pcLast = '\0';
    }

    return pcReturn;
}


static const SConfigParams* GetServiceParametersStatic(int a_argc, char* a_argv[]) CPPUTILS_NOEXCEPT
{
    size_t readCount;
    DWORD dwModuleFnameLen;
    struct _stat fStat;
    char vcBuffer[MAX_BUFFER_SIZE];
    errno_t fopenRet;
    char* pcTmp, * pcExecDirectory;
    FILE* fpConfFile = CPPUTILS_NULL;
    SConfigParams* const pSrvParams = (SConfigParams*)calloc(1, sizeof(SConfigParams));

    if (!pSrvParams) {
        fprintf(stderr,"Low memory!\n");
        return CPPUTILS_NULL;
    }

    pSrvParams->m_cOption = (a_argc > 1) ? a_argv[1][0] : 'i';
    pSrvParams->m_bIsService = ((pSrvParams->m_cOption) == 's');

    dwModuleFnameLen = GetModuleFileNameA(CPPUTILS_NULL, vcBuffer, MAX_BUFFER_SIZE_TRM1);
    if (!dwModuleFnameLen) {
        // todo: report on error
        free(pSrvParams);
        return CPPUTILS_NULL;
    }

    pSrvParams->m_pcExecFilePath = _strdup(vcBuffer);
    if (!(pSrvParams->m_pcExecFilePath)) {
        free(pSrvParams);
        return CPPUTILS_NULL;
    }
    pSrvParams->m_execFilePathLen = (size_t)(dwModuleFnameLen);

    pcTmp = strrchr(vcBuffer, '\\');
    if (!pcTmp) {
        pcTmp = strrchr(vcBuffer, '/');
        if (!pcTmp) {
            // todo: report on error
            free(pSrvParams);
            return CPPUTILS_NULL;
        }
    }

    pSrvParams->m_execDirectoryLen = (size_t)(pcTmp - vcBuffer);
    pSrvParams->m_pcExecDirectory = pcExecDirectory = (char*)malloc(sizeof(char) * (pSrvParams->m_execDirectoryLen + 1));
    if (!(pSrvParams->m_pcExecDirectory)) {
        free(pSrvParams);
        return CPPUTILS_NULL;
    }
    memcpy(pcExecDirectory, vcBuffer, pSrvParams->m_execDirectoryLen);
    pcExecDirectory[pSrvParams->m_execDirectoryLen] = 0;

    if (pSrvParams->m_bIsService) {
        SECURITY_ATTRIBUTES sa;
        ZeroMemory(&sa, sizeof(sa));
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;

        if (!CreatePipe(&(pSrvParams->m_inputPipe), &(pSrvParams->m_hStdOuts), &sa, 0)) {
            free(pSrvParams);
            return CPPUTILS_NULL;
        }

        SetStdHandle(STD_OUTPUT_HANDLE, pSrvParams->m_hStdOuts);
        SetStdHandle(STD_ERROR_HANDLE, pSrvParams->m_hStdOuts);

        // Ensure read handle is not inherited
        SetHandleInformation(pSrvParams->m_inputPipe, HANDLE_FLAG_INHERIT, 0);
    }  //  if (pSrvParams->m_bIsService) {

    memcpy(pcTmp + 1, CONFIG_FILE_NAME, CONFIG_FILE_NAME_LEN_PLUS_1);
    fopenRet = fopen_s(&fpConfFile, vcBuffer, "r");
    if (fopenRet) {
        // todo: report on problem to open the file
        ClearServiceParameters(pSrvParams);
        return CPPUTILS_NULL;
    }

    if (_fstat(_fileno(fpConfFile), &fStat)){
        fclose(fpConfFile);
        ClearServiceParameters(pSrvParams);
        return CPPUTILS_NULL;
    }

    pSrvParams->m_pcBuffer = (char*)malloc(sizeof(char)*((size_t)fStat.st_size+4));
    if (!(pSrvParams->m_pcBuffer)) {
        fclose(fpConfFile);
        ClearServiceParameters(pSrvParams);
        return CPPUTILS_NULL;
    }

    readCount = fread_s(pSrvParams->m_pcBuffer, sizeof(char) * ((size_t)fStat.st_size + 1), sizeof(char), (size_t)fStat.st_size, fpConfFile);
    fclose(fpConfFile);
    if (!readCount) {
        ClearServiceParameters(pSrvParams);
        return CPPUTILS_NULL;
    }
    pSrvParams->m_pcBuffer[readCount] = 0;

    pSrvParams->m_pcServiceName = FindElementByKeyInline("name", pSrvParams->m_pcBuffer, readCount);
    if (!(pSrvParams->m_pcServiceName)) {
        ClearServiceParameters(pSrvParams);
        return CPPUTILS_NULL;
    }

    pSrvParams->m_pcCommandLine = FindElementByKeyInline("exec", pSrvParams->m_pcBuffer, readCount);
    if (!(pSrvParams->m_pcCommandLine)) {
        ClearServiceParameters(pSrvParams);
        return CPPUTILS_NULL;
    }

    pSrvParams->m_pcInit = FindElementByKeyInline("init", pSrvParams->m_pcBuffer, readCount);

    return pSrvParams;
}

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

#define MAX_BUFFER_SIZE_TRM1    4096
#define MAX_BUFFER_SIZE_MIN_1   8191
#define MAX_BUFFER_SIZE         8192
#define CONFIG_FILE_NAME                    "config.conf"
#define LOG_FILE_NAME                       "servicelog.log"
#define CONFIG_FILE_NAME_LEN_PLUS_1          sizeof(CONFIG_FILE_NAME)
#define LOG_FILE_NAME_LEN_PLUS_1            sizeof(LOG_FILE_NAME)


typedef struct SConfigParams {
    const char* m_pcServiceName;
    const char* m_pcCommandLine;
    char*       m_pcBuffer;
    HANDLE      m_hStdOuts;
    HANDLE      m_reserved01;
    char        m_cOption;  
    bool        m_bIsService; 
    bool        reserved02[sizeof(void*)-sizeof(bool)-sizeof(char)];
} SConfigParams;

static DWORD WINAPI ServiceStartThreadProcStatic(_In_ LPVOID a_pArg) CPPUTILS_NOEXCEPT;
static DWORD WINAPI PipeReadThreadProcStatic(_In_ LPVOID a_pArg) CPPUTILS_NOEXCEPT;
static VOID WINAPI ServiceMainFunctionStatic(DWORD a_dwNumServicesArgs, LPSTR* a_lpServiceArgVectors) CPPUTILS_NOEXCEPT;
static DWORD WINAPI MonitoringServiceCtrlEx(DWORD a_dwControl, DWORD a_dwEventType, LPVOID a_lpEventData, LPVOID a_lpContext) CPPUTILS_NOEXCEPT;
static int CreateServiceProcessStatic(const SConfigParams* CPPUTILS_ARG_NN a_cpSrvParams, PROCESS_INFORMATION* CPPUTILS_ARG_NN a_pProcInfo) CPPUTILS_NOEXCEPT;
static const SConfigParams* GetServiceParametersStatic(int a_argc, char* a_argv[]) CPPUTILS_NOEXCEPT;
static void ClearServiceParameters(const SConfigParams* CPPUTILS_ARG_NN a_cpSrvParams) CPPUTILS_NOEXCEPT;
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
        ClearServiceParameters(pSrvParams);
        return 0;
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
    const SConfigParams* const cpSrvParams = (SConfigParams*)a_pArg;

    (void)cpSrvParams;

    return 0;
}


static void ClearServiceParameters(const SConfigParams* CPPUTILS_ARG_NN a_pSrvParams) CPPUTILS_NOEXCEPT
{
    if (a_pSrvParams->m_hStdOuts) {
        CloseHandle(a_pSrvParams->m_hStdOuts);
    }

    if (a_pSrvParams->m_pcBuffer) {
        free(a_pSrvParams->m_pcBuffer);
    }

    free((SConfigParams*)a_pSrvParams);
}


static const SConfigParams* GetServiceParametersStatic(int a_argc, char* a_argv[]) CPPUTILS_NOEXCEPT
{
    SECURITY_ATTRIBUTES sa;
    errno_t fopenRet;
    char* pcTmp, * pcLast;
    FILE* fpConfFile = CPPUTILS_NULL;
    SConfigParams* const pSrvParams = (SConfigParams*)calloc(1, sizeof(SConfigParams));

    if (!pSrvParams) {
        fprintf(stderr,"Low memory!\n");
        return CPPUTILS_NULL;
    }

    pSrvParams->m_pcServiceName = "ssh_port_redirect_service04";

    pSrvParams->m_pcBuffer = (char*)malloc(sizeof(char)*MAX_BUFFER_SIZE);
    if (!(pSrvParams->m_pcBuffer)) {
        free(pSrvParams);
        return CPPUTILS_NULL;
    }

    pSrvParams->m_cOption = (a_argc > 1) ? a_argv[1][0] : 'i';
    pSrvParams->m_bIsService = ((pSrvParams->m_cOption) == 's');

    if (!GetModuleFileNameA(CPPUTILS_NULL, pSrvParams->m_pcBuffer, MAX_BUFFER_SIZE_TRM1)) {
        // todo: report on error
        free(pSrvParams->m_pcBuffer);
        free(pSrvParams);
        return CPPUTILS_NULL;
    }

    pcTmp = strrchr(pSrvParams->m_pcBuffer, '\\');
    if (!pcTmp) {
        pcTmp = strrchr(pSrvParams->m_pcBuffer, '/');
        if (!pcTmp) {
            // todo: report on error
            free(pSrvParams->m_pcBuffer);
            free(pSrvParams);
            return CPPUTILS_NULL;
        }
    }

    if (pSrvParams->m_bIsService) {
        ZeroMemory(&sa, sizeof(sa));
        sa.nLength = sizeof(SECURITY_ATTRIBUTES);
        sa.bInheritHandle = TRUE;
        sa.lpSecurityDescriptor = CPPUTILS_NULL;

        memcpy(pcTmp + 1, LOG_FILE_NAME, LOG_FILE_NAME_LEN_PLUS_1);
        pSrvParams->m_hStdOuts = CreateFileA(
            pSrvParams->m_pcBuffer,
            FILE_APPEND_DATA,
            FILE_SHARE_WRITE | FILE_SHARE_READ,
            &sa,
            OPEN_ALWAYS,
            FILE_ATTRIBUTE_NORMAL,
            NULL
        );
        if ((!pSrvParams->m_hStdOuts) || ((pSrvParams->m_hStdOuts) == INVALID_HANDLE_VALUE)) {
            free(pSrvParams->m_pcBuffer);
            free(pSrvParams);
            return CPPUTILS_NULL;
        }
    }  //  if (pSrvParams->m_bIsService) {

    memcpy(pcTmp + 1, CONFIG_FILE_NAME, CONFIG_FILE_NAME_LEN_PLUS_1);
    fopenRet = fopen_s(&fpConfFile, pSrvParams->m_pcBuffer, "r");
    if (fopenRet) {
        // todo: report on problem to open the file
        CloseHandle(pSrvParams->m_hStdOuts);
        free(pSrvParams->m_pcBuffer);
        free(pSrvParams);
        return CPPUTILS_NULL;
    }

    while (fgets(pSrvParams->m_pcBuffer, MAX_BUFFER_SIZE_MIN_1, fpConfFile)) {
        pcTmp = pSrvParams->m_pcBuffer;
        while (isspace(*pcTmp)) { ++pcTmp; }
        if ((pcTmp[0] == '\0') || (pcTmp[0] == '#')) { continue; }
        pcLast = CPPUTILS_NULL;
        pSrvParams->m_pcCommandLine = pcTmp;
        while ((*pcTmp)) { if (isspace(*pcTmp)) { pcLast = pcTmp; }  ++pcTmp; }
        if (pcLast) {
            *pcLast = '\0';
        }
        break;
    }  //  while (fgets(vcBuffer, MAX_BUFFER_SIZE_MIN_1, fpConfFile)) {

    fclose(fpConfFile);

    if (!(pSrvParams->m_pcCommandLine)) {
        // todo: report that no command is provided
        CloseHandle(pSrvParams->m_hStdOuts);
        free(pSrvParams->m_pcBuffer);
        free(pSrvParams);
        return CPPUTILS_NULL;
    }

    return pSrvParams;
}

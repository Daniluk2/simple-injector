#include <iostream>
#include <windows.h>
#include <psapi.h>

wchar_t proc_name[MAX_PATH];
wchar_t dll_patch[MAX_PATH];

DWORD get_process_pid() {
  HANDLE h_heap = GetProcessHeap();
  DWORD process_count = 1024;
  DWORD* process_list = new DWORD[process_count];
  DWORD cb_alloc = process_count * sizeof(DWORD);
  DWORD cb_returned;
  DWORD targ_pid = 0;

  if (!process_list) {
    std::wcout << L"error allocating memory for process_list!\n";
    delete[] process_list;
    return false;
  }

  if (!K32EnumProcesses(process_list, cb_alloc, &cb_returned)) {
    std::wcout << L"error K32EnumProcesses!\n";
    delete[] process_list;
    return false;
  }

  for (DWORD i = 0; i < process_count; ++i) {
    DWORD pid = process_list[i];
    HANDLE h_process = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, pid);
    if (h_process) {
      WCHAR process_name[MAX_PATH];
      if (K32GetModuleBaseNameW(h_process, nullptr, process_name, MAX_PATH)) {
        if (wcscmp(process_name, proc_name) == 0) {
          std::wcout << L"Found process PID: " << pid << std::endl;
          targ_pid = pid;
          CloseHandle(h_process);
          break;
        }
      }
      CloseHandle(h_process);
    }
  }
  delete[] process_list;

  if (targ_pid == 0) {
    std::wcout << L"process not found!\n";
    return false;
  }

  return targ_pid;
}

bool inject_to_process(DWORD targ_pid) {
  HANDLE h_targproc = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD, FALSE, targ_pid);

  DWORD len = 1024;
  LPWSTR buf = new WCHAR[len];
  LPWSTR part = nullptr;
  if (GetFullPathNameW(dll_patch, len, buf, &part) == 0) {
    std::wcout << L"failed to get full path name!\n";
    delete[] buf;
    return false;
  }

  SIZE_T path_size = (wcslen(buf) + 1) * sizeof(WCHAR);
  LPVOID alloc_mem = VirtualAllocEx(h_targproc, NULL, path_size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);

  if (alloc_mem == NULL) {
    std::wcout << L"failed to allocate memory in target process!\n";
    delete[] buf;
    return false;
  }

  if (!WriteProcessMemory(h_targproc, alloc_mem, buf, path_size, NULL)) {
    std::wcout << L"failed to write DLL path to target process memory!\n";
    VirtualFreeEx(h_targproc, alloc_mem, 0, MEM_RELEASE);
    delete[] buf;
    return false;
  }

  HANDLE h_theard = CreateRemoteThread(h_targproc, NULL, 0, (LPTHREAD_START_ROUTINE)LoadLibraryW, alloc_mem, 0, NULL);
  if (!h_theard) {
    std::wcerr << L"failed to create remote thread!\n";
    VirtualFreeEx(h_targproc, alloc_mem, 0, MEM_RELEASE);
    CloseHandle(h_targproc);
    return false;
  }

  WaitForSingleObject(h_theard, INFINITE);
  CloseHandle(h_theard);
  VirtualFreeEx(h_targproc, alloc_mem, 0, MEM_RELEASE);
  CloseHandle(h_targproc);
  delete[] buf;

  return true;
}

int main()
{
  std::wcout << L"enter the name of the process: ";
  std::wcin.getline(proc_name, MAX_PATH);

  std::wcout << L"enter the name of the DLL: ";
  std::wcin.getline(dll_patch, MAX_PATH);

  DWORD targ_pid = get_process_pid();
  if (targ_pid != 0) {
    if (inject_to_process(targ_pid))
      std::wcout << L"dll injected!\n";
    else
      std::wcout << L"injection failed!\n";
  }else
    std::wcout << L"process not found or injection failed!\n";
  
  return true;
}
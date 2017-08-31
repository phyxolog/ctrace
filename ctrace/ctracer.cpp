#include "stdafx.h"
#include <Psapi.h>
#include "ctracer.h"
#include "disasm\disasm.h"

#pragma comment (lib, "Psapi.lib")

#define CHECK_IS_LOADED if (!is_loaded) return false;
#define DEF_WAIT 100

#if !defined(MakePtr)
	#define MakePtr(cast, ptr, addValue) (cast)( (DWORD)(ptr) + (DWORD)(addValue))
#endif

ctracer::ctracer()
{
	ctx.ContextFlags = CONTEXT_FULL | CONTEXT_DEBUG_REGISTERS;
	is_loaded = false;
}

bool ctracer::init()
{
	memset(&this->si, 0, sizeof si);
	memset(&this->pi, 0, sizeof pi);

	si.cb = sizeof si;
	si.dwFlags = STARTF_USESHOWWINDOW;
	si.wShowWindow = SW_SHOW;

	if (!CreateProcess(NULL, this->file_name, NULL, NULL, false, CREATE_SUSPENDED, NULL, NULL, &si, &pi))
		return false;

	is_loaded = true;

	this->pi.hThread = OpenThread(THREAD_ALL_ACCESS, false, this->pi.dwThreadId);
	if (this->pi.hThread == INVALID_HANDLE_VALUE)
	{
		is_loaded = false;
		return false;
	}

	if (!this->get_context())
	{
		is_loaded = false;
		return false;
	}

	if (!read_memory(this->ctx.Ebx + 8, sizeof DWORD, &this->dw_image_base, false))
		if (!read_memory(this->ctx.Ebx + 8, sizeof DWORD, &this->dw_image_base, true))
		{
			is_loaded = false;
			return false;
		}
	
	return true;
}

bool ctracer::release()
{
	CHECK_IS_LOADED
	is_loaded = false;
	if (!TerminateProcess(this->pi.hProcess, 0))
		return false;

	if (!CloseHandle(this->pi.hProcess))
		return false;

	if (!CloseHandle(this->pi.hThread))
		return false;

	return true;
}

bool ctracer::read_memory(DWORD dw_address, DWORD dw_size, LPVOID lp_buffer, bool b_protect)
{
	CHECK_IS_LOADED
	DWORD dw_old_protect = 0;

	if (b_protect)
		if (!VirtualProtectEx(this->pi.hProcess, (LPVOID)dw_address, dw_size, PAGE_READONLY, &dw_old_protect))
			return false;
	if (!ReadProcessMemory(this->pi.hProcess, (LPVOID)dw_address, lp_buffer, dw_size, NULL))
		return false;
	if (b_protect)
		if (!VirtualProtectEx(this->pi.hProcess, (LPVOID)dw_address, dw_size, dw_old_protect, &dw_old_protect))
			return false;
	return true;
}

bool ctracer::write_memory(DWORD dw_address, DWORD dw_size, LPVOID lp_buffer, bool b_protect)
{
	CHECK_IS_LOADED
	DWORD dw_old_protect = 0;

	if (b_protect)
		if (!VirtualProtectEx(this->pi.hProcess, (LPVOID)dw_address, dw_size, PAGE_READWRITE, &dw_old_protect))
			return false;
	if (!WriteProcessMemory(this->pi.hProcess, (LPVOID)dw_address, lp_buffer, dw_size, NULL))
		return false;
	if (b_protect)
		if (!VirtualProtectEx(pi.hProcess, (LPVOID)dw_address, dw_size, dw_old_protect, &dw_old_protect))
			return false;
	return true;
}

bool ctracer::trace(DWORD dw_address)
{
	BYTE hook[2] = { 0xEB, 0xFE };
	BYTE saved_bytes[2] = { };

	if (!this->read_memory(dw_address, sizeof saved_bytes, &saved_bytes, false))
		if (!this->read_memory(dw_address, sizeof saved_bytes, &saved_bytes, true))
			return false;

	if (!this->write_memory(dw_address, sizeof hook, &hook, false))
		if (!this->write_memory(dw_address, sizeof hook, &hook, true))
			return false;

	if (!this->resume())
		goto some_error;

	while (this->ctx.Eip != dw_address)
	{
		Sleep(DEF_WAIT);

		if (!get_context())
			goto some_error;
	}

	if (!this->suspend())
		goto some_error;

	if (!this->write_memory(dw_address, sizeof saved_bytes, &saved_bytes, false))
		if (!this->write_memory(dw_address, sizeof saved_bytes, &saved_bytes, true))
			return false;

	return true;

some_error:
	if (!this->write_memory(dw_address, sizeof saved_bytes, &saved_bytes, false))
		if (!this->write_memory(dw_address, sizeof saved_bytes, &saved_bytes, true))
			return false;

	return false;
}

bool ctracer::suspend()
{
	CHECK_IS_LOADED
	return SuspendThread(this->pi.hThread) != -1;
}

bool ctracer::resume()
{
	CHECK_IS_LOADED
	return ResumeThread(this->pi.hThread) != -1;
}

BOOL ctracer::get_context()
{
	CHECK_IS_LOADED
	return GetThreadContext(this->pi.hThread, &this->ctx);
}

BOOL ctracer::set_context()
{
	CHECK_IS_LOADED
	return SetThreadContext(this->pi.hThread, &this->ctx);
}

DWORD ctracer::get_image_base()
{
	CHECK_IS_LOADED
	return this->dw_image_base;
}

bool ctracer::dump_process_range(LPVOID lp_start_addr, DWORD dw_length, LPVOID lp_dumped)
{
	CHECK_IS_LOADED
	bool ret = false;
	DWORD  dw_fail = 0, dw_readed2do, dw_block_size;
	MEMORY_BASIC_INFORMATION memory_info = { 0 };

	if (!this->read_memory((DWORD)lp_start_addr, dw_length, lp_dumped, false))
		return false;

	dw_readed2do = dw_length;
	memory_info.BaseAddress = lp_start_addr;

	while (dw_readed2do)
	{
		if (VirtualQueryEx(this->pi.hProcess, memory_info.BaseAddress, &memory_info, sizeof memory_info) == 0)
			return false;

		dw_block_size = min(memory_info.RegionSize, dw_readed2do);

		if (lp_start_addr)
			dw_block_size -= (DWORD)lp_start_addr - (DWORD)memory_info.BaseAddress;

		if (((memory_info.Protect & PAGE_GUARD) != 0) || ((memory_info.Protect & PAGE_NOACCESS) != 0))
		{
			memset(MakePtr(PVOID, lp_dumped, dw_length - dw_readed2do), 0, dw_block_size);
			dw_fail += dw_block_size;
		}
		else
		{
			ret = this->read_memory((DWORD)lp_start_addr ? (DWORD)lp_start_addr : (DWORD)memory_info.BaseAddress, dw_block_size, MakePtr(PVOID, lp_dumped, dw_length - dw_readed2do), false);

			if (lp_start_addr)
				lp_start_addr = NULL;

			if (!ret)
			{
				memset(MakePtr(PVOID, lp_dumped, dw_length - dw_readed2do), 0, dw_block_size);
				dw_fail += dw_block_size;
			}
		}
		memory_info.BaseAddress = MakePtr(PVOID, memory_info.BaseAddress, memory_info.RegionSize);
		dw_readed2do -= dw_block_size;
	}

	return true;
}

bool ctracer::dump_to_file(LPSTR file_path, DWORD entry_point, bool sub_image_base)
{
	CHECK_IS_LOADED
	HANDLE h_file;
	DWORD dw_file_size, dw_size_of_image, dw_real_header_size;
	LPVOID lp_buffer, lp_header_buffer;
	PIMAGE_DOS_HEADER dos_header;
	PIMAGE_NT_HEADERS32 nt_header;
	PIMAGE_SECTION_HEADER section_header;

	h_file = CreateFileA(this->file_name, GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	if (h_file == INVALID_HANDLE_VALUE)
		return false;

	dw_file_size = GetFileSize(h_file, NULL);
	if ((dw_file_size == -1) | (dw_file_size == 0))
	{
		CloseHandle(h_file);
		return false;
	}
	
	lp_buffer = calloc(1, dw_file_size);
	if (lp_buffer == NULL)
	{
		CloseHandle(h_file);
		return false;
	}

	if (!ReadFile(h_file, lp_buffer, dw_file_size, NULL, NULL))
	{
		CloseHandle(h_file);
		return false;
	}

	CloseHandle(h_file);
		
    dos_header = (PIMAGE_DOS_HEADER)lp_buffer;
    nt_header = (PIMAGE_NT_HEADERS32)((LPBYTE)lp_buffer + dos_header->e_lfanew);
	section_header = IMAGE_FIRST_SECTION(nt_header);
	dw_real_header_size = 0xFFFFFFFF;

	int i = nt_header->FileHeader.NumberOfSections;
	do
	{
		section_header->PointerToRawData = section_header->VirtualAddress;
		section_header->SizeOfRawData = section_header->Misc.VirtualSize;
		if (section_header->PointerToRawData)
			dw_real_header_size = __min(dw_real_header_size, section_header->PointerToRawData);
		++section_header;
		--i;
	} while (i != 0);

	dw_real_header_size = (dw_real_header_size > 0x00001000) ? 0x00001000 : dw_real_header_size;
	dw_size_of_image = nt_header->OptionalHeader.SizeOfImage;
	nt_header->OptionalHeader.FileAlignment = nt_header->OptionalHeader.SectionAlignment;
	nt_header->OptionalHeader.SizeOfHeaders = dw_real_header_size;

	if (entry_point != NULL)
		if (sub_image_base)
			nt_header->OptionalHeader.AddressOfEntryPoint = entry_point - this->dw_image_base;
		else
			nt_header->OptionalHeader.AddressOfEntryPoint = entry_point;

	lp_header_buffer = calloc(1, dw_real_header_size);
	if (lp_header_buffer == NULL)
	{
		free(lp_buffer);
		return false;
	}

	memcpy(lp_header_buffer, lp_buffer, dw_real_header_size);
	free(lp_buffer);

	lp_buffer = calloc(1, dw_size_of_image);
	if (lp_buffer == NULL)
	{
		free(lp_header_buffer);
		return false;
	}

	if (!this->dump_process_range((LPVOID)this->dw_image_base, dw_size_of_image, lp_buffer))
	{
		free(lp_buffer);
		free(lp_header_buffer);
		return false;
	}

	h_file = CreateFileA(file_path, GENERIC_READ | GENERIC_WRITE, 0, 0, CREATE_ALWAYS, 0, 0);
	if (!h_file)
	{
		free(lp_buffer);
		free(lp_header_buffer);
		return false;
	}

	if (!WriteFile(h_file, lp_buffer, dw_size_of_image, NULL, NULL))
	{
		CloseHandle(h_file);
		free(lp_buffer);
		free(lp_header_buffer);
		return false;
	}

	free(lp_buffer);
	SetFilePointer(h_file, 0, 0, SEEK_SET);

	if (!WriteFile(h_file, lp_header_buffer, dw_real_header_size, NULL, NULL))
	{
		CloseHandle(h_file);		
		free(lp_header_buffer);
		return false;
	}

	CloseHandle(h_file);		
	free(lp_header_buffer);
	return true;
}

long long ctracer::search_pattern(LPVOID memory_start, DWORD memory_size, LPVOID search_pattern, DWORD pattern_size, LPBYTE wild_card)
{
	CHECK_IS_LOADED
	int i = NULL;
	int j = NULL;
	ULONG_PTR ret = NULL;
	LPVOID lp_buffer = NULL;
	PUCHAR search_buffer = NULL;
	PUCHAR compare_buffer = NULL;
	MEMORY_BASIC_INFORMATION memory_information = { 0 };
	BYTE nWildCard = NULL;

	if (wild_card == NULL)
		wild_card = &nWildCard;

	if (memory_start != NULL && memory_size != NULL)
	{
		lp_buffer = calloc(1, memory_size);
		if (lp_buffer == NULL)
			return NULL;

		if (!this->read_memory((DWORD)memory_start, memory_size, lp_buffer, false))
		{
			if (VirtualQueryEx(this->pi.hProcess, memory_start, &memory_information, sizeof memory_information) != NULL)
			{
				memory_size = (DWORD)((ULONG_PTR)memory_information.BaseAddress + memory_information.RegionSize - (ULONG_PTR)memory_start);
				if (!this->read_memory((DWORD)memory_start, memory_size, lp_buffer, false))
				{
					free(lp_buffer);
					return NULL;
				}
				else
					search_buffer = (PUCHAR)lp_buffer;
			}
			else
			{
				free(lp_buffer);
				return NULL;
			}
		}
		else
			search_buffer = (PUCHAR)lp_buffer;

		__try
		{
			compare_buffer = (PUCHAR)search_pattern;
			for(i = 0; i < (int)memory_size && ret == NULL; i++)
			{
				for(j = 0; j < (int)pattern_size; j++)
					if(compare_buffer[j] != *(PUCHAR)wild_card && search_buffer[i + j] != compare_buffer[j])
						break;

				if(j == (int)pattern_size)
					ret = (ULONG_PTR)memory_start + i;
			}

			free(lp_buffer);
			return ret;
		}
		__except(EXCEPTION_EXECUTE_HANDLER)
		{
			free(lp_buffer);
			return NULL;
		}
	}
	else
		return NULL;
}

char *ctracer::get_current_instruction()
{
	CHECK_IS_LOADED
	uchar lp_buffer[MAXCMDSIZE];
	t_disasm da;

	if (!this->get_context())
		return NULL;

	if (!read_memory(this->ctx.Eip, sizeof lp_buffer, lp_buffer, false))
		if (!read_memory(this->ctx.Eip, sizeof lp_buffer, lp_buffer, true))
			return NULL;

	Preparedisasm();
	Disasm(lp_buffer, MAXCMDSIZE, this->dw_image_base, &da, DA_TEXT, NULL, NULL);
	Finishdisasm();

	int l = lstrlen(da.result);
	char *res = new char[l];

	ZeroMemory(res, l);
	for (int i = 0; i < l; i++)
	{
		if (da.result[i] == 0x20)
			break;
		res[i] = da.result[i];
	}

	return res;
}

unsigned long ctracer::get_current_instruction_size()
{
	CHECK_IS_LOADED
	unsigned char lp_buffer[MAXCMDSIZE];
	unsigned long u_length;
	t_disasm da;

	if (!this->get_context())
		return false;

	if (!read_memory(this->ctx.Eip, sizeof lp_buffer, lp_buffer, false))
		if (!read_memory(this->ctx.Eip, sizeof lp_buffer, lp_buffer, true))
			return false;

	Preparedisasm();
	u_length = Disasm(lp_buffer, MAXCMDSIZE, this->dw_image_base, &da, NULL, NULL, NULL);
	Finishdisasm();

	return u_length;
}

HMODULE ctracer::get_module_handle(LPCSTR module_name)
{
	CHECK_IS_LOADED
	HMODULE *module_array = NULL;
	DWORD module_array_size = 100;
	DWORD num_modules = 0;
	char module_name_copy[MAX_PATH] = {0};
	char module_name_buffer[MAX_PATH] = {0};
 
	if (module_name == NULL)
		goto FAIL_JMP;
 
	for (unsigned int i = 0; module_name[i] != '\0'; ++i)
	{
		if (module_name[i] >= 'A' && module_name[i] <= 'Z')
			module_name_copy[i] = module_name[i] + 0x20;
		else
			module_name_copy[i] = module_name[i];
 
		module_name_copy[i+1] = '\0';
	}
	
	module_array = new HMODULE[module_array_size];
 
	if (module_array == NULL)
		goto FAIL_JMP;
 
	if (!EnumProcessModulesEx(this->pi.hProcess, module_array, module_array_size * sizeof(HMODULE), &num_modules, LIST_MODULES_ALL))
		goto FAIL_JMP;
 
	num_modules /= sizeof(HMODULE);
 
	if (num_modules > module_array_size)
	{
		delete[] module_array;
		module_array = NULL;
		module_array = new HMODULE[num_modules];

		if(module_array == NULL)
			goto FAIL_JMP;
 
		module_array_size = num_modules;
		
		if (!EnumProcessModulesEx(this->pi.hProcess, module_array, module_array_size * sizeof(HMODULE), &num_modules, LIST_MODULES_ALL))
			goto FAIL_JMP;
 
		num_modules /= sizeof(HMODULE);
	}
 
	for (unsigned int i = 0; i <= num_modules; ++i)
	{
		GetModuleBaseName(this->pi.hProcess, module_array[i], module_name_buffer, sizeof(module_name_buffer));
 
		for (size_t j = 0; module_name_buffer[j] != '\0'; ++j)
			if (module_name_buffer[j] >= 'A' && module_name_buffer[j] <= 'Z')
				module_name_buffer[j] += 0x20;
 
		if (strstr(module_name_buffer, module_name_copy) != NULL)
		{
			HMODULE TempReturn = module_array[i]; 
			delete[] module_array; 
			return TempReturn;
		}
 	}
 
FAIL_JMP:	
	if(module_array != NULL)
		delete[] module_array;
 
	return NULL;
}

FARPROC ctracer::get_proc_address(HMODULE h_module, LPCSTR proc_name, unsigned int ordinal, bool use_ordinal)
{
	CHECK_IS_LOADED
	bool is_64 = false;
	MODULEINFO remote_module_info = { 0 };
	UINT_PTR remote_module_base_va = 0;
	IMAGE_DOS_HEADER dos_header = { 0 };
	DWORD sign = 0;
	IMAGE_FILE_HEADER file_header = { 0 };
	IMAGE_OPTIONAL_HEADER64 opt_header64 = { 0 };
	IMAGE_OPTIONAL_HEADER32 opt_header32 = { 0 };
	IMAGE_DATA_DIRECTORY export_directory = { 0 };
	IMAGE_EXPORT_DIRECTORY export_table = { 0 };
	UINT_PTR export_function_table_va = 0;
	UINT_PTR export_name_table_va = 0;
	UINT_PTR export_ordinal_table_va = 0;
	DWORD *export_function_table = NULL;
	DWORD *export_name_table = NULL;
	WORD *export_ordinal_table = NULL;
 
	char temp_char;
	bool done = false;
 
	if (proc_name == NULL && !use_ordinal)
		goto FAIL_JMP;
 
	if (!GetModuleInformation(this->pi.hProcess, h_module, &remote_module_info, sizeof remote_module_info))
		goto FAIL_JMP;
		
	remote_module_base_va = (UINT_PTR)remote_module_info.lpBaseOfDll;

	if (!this->read_memory(remote_module_base_va, sizeof dos_header, &dos_header, false) || dos_header.e_magic != IMAGE_DOS_SIGNATURE)
		if (!this->read_memory(remote_module_base_va, sizeof dos_header, &dos_header, true) || dos_header.e_magic != IMAGE_DOS_SIGNATURE)
			goto FAIL_JMP;

	if (!this->read_memory(remote_module_base_va + dos_header.e_lfanew, sizeof sign, &sign, false) || sign != IMAGE_NT_SIGNATURE)
		if (!this->read_memory(remote_module_base_va + dos_header.e_lfanew, sizeof sign, &sign, true) || sign != IMAGE_NT_SIGNATURE)
			goto FAIL_JMP;
	
	if (!this->read_memory(remote_module_base_va + dos_header.e_lfanew + sizeof sign, sizeof file_header, &file_header, false))
		if (!this->read_memory(remote_module_base_va + dos_header.e_lfanew + sizeof sign, sizeof file_header, &file_header, true))
			goto FAIL_JMP;
 
	if (file_header.SizeOfOptionalHeader == sizeof opt_header64)
		is_64 = true;
	else 
		if (file_header.SizeOfOptionalHeader == sizeof opt_header32)
			is_64 = false;
	else
		goto FAIL_JMP;
 
	if (is_64)
	{
		if (!this->read_memory(remote_module_base_va + dos_header.e_lfanew + sizeof sign + sizeof file_header, file_header.SizeOfOptionalHeader, &opt_header64, false) || opt_header64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
			if (!this->read_memory(remote_module_base_va + dos_header.e_lfanew + sizeof sign + sizeof file_header, file_header.SizeOfOptionalHeader, &opt_header64, true) || opt_header64.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC)
				goto FAIL_JMP;
	}
	else
	{
		if (!this->read_memory(remote_module_base_va + dos_header.e_lfanew + sizeof sign + sizeof file_header, file_header.SizeOfOptionalHeader, &opt_header32, false) || opt_header32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
			if (!this->read_memory(remote_module_base_va + dos_header.e_lfanew + sizeof sign + sizeof file_header, file_header.SizeOfOptionalHeader, &opt_header32, true) || opt_header32.Magic != IMAGE_NT_OPTIONAL_HDR32_MAGIC)
				goto FAIL_JMP;
	}
 
	if (is_64 && opt_header64.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_EXPORT + 1)
	{
		export_directory.VirtualAddress = (opt_header64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress;
		export_directory.Size = (opt_header64.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).Size;
	}
	else 
	if (opt_header32.NumberOfRvaAndSizes >= IMAGE_DIRECTORY_ENTRY_EXPORT + 1)
	{
		export_directory.VirtualAddress = (opt_header32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).VirtualAddress;
		export_directory.Size = (opt_header32.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT]).Size;
	}
	else
		goto FAIL_JMP;
 
	if (!this->read_memory(remote_module_base_va + export_directory.VirtualAddress, sizeof export_table, &export_table, false))
		if (!this->read_memory(remote_module_base_va + export_directory.VirtualAddress, sizeof export_table, &export_table, true))
			goto FAIL_JMP;
 
	export_function_table_va = remote_module_base_va + export_table.AddressOfFunctions;
	export_name_table_va = remote_module_base_va + export_table.AddressOfNames;
	export_ordinal_table_va = remote_module_base_va + export_table.AddressOfNameOrdinals;
 
	export_function_table = new DWORD[export_table.NumberOfFunctions];
	export_name_table = new DWORD[export_table.NumberOfNames];
	export_ordinal_table = new WORD[export_table.NumberOfNames];
 
	if (export_function_table == NULL || export_name_table == NULL || export_ordinal_table == NULL)
		goto FAIL_JMP;

	if (!this->read_memory(export_function_table_va, export_table.NumberOfFunctions * sizeof DWORD, export_function_table, false))
		if (!this->read_memory(export_function_table_va, export_table.NumberOfFunctions * sizeof DWORD, export_function_table, true))
			goto FAIL_JMP;

	if (!this->read_memory(export_name_table_va, export_table.NumberOfNames * sizeof DWORD, export_name_table, false))
		if (!this->read_memory(export_name_table_va, export_table.NumberOfNames * sizeof DWORD, export_name_table, true))
			goto FAIL_JMP;

	if (!this->read_memory(export_ordinal_table_va, export_table.NumberOfNames * sizeof WORD, export_ordinal_table, false))
		if (!this->read_memory(export_ordinal_table_va, export_table.NumberOfNames * sizeof WORD, export_ordinal_table, true))
			goto FAIL_JMP;
 
	if (use_ordinal)
	{
		if (ordinal < export_table.Base || (ordinal - export_table.Base) >= export_table.NumberOfFunctions)
			goto FAIL_JMP;
 
		UINT function_table_index = ordinal - export_table.Base;
 
		if (export_function_table[function_table_index] >= export_directory.VirtualAddress && 
			export_function_table[function_table_index] <= export_directory.VirtualAddress + export_directory.Size)
		{
			done = false;
			string temp_forward_string;
			temp_forward_string.clear();

			for (UINT_PTR i = 0; !done; ++i)
			{
				if (!this->read_memory(remote_module_base_va + export_function_table[function_table_index] + i, sizeof temp_char, &temp_char, false))
					if (!this->read_memory(remote_module_base_va + export_function_table[function_table_index] + i, sizeof temp_char, &temp_char, true))
						goto FAIL_JMP;
 
				temp_forward_string.push_back(temp_char);

				if (temp_char == (char)'\0')
					done = true;
			}
 
			size_t dot = temp_forward_string.find('.');
			if (dot == string::npos)
				goto FAIL_JMP;
 
			string real_module_name, real_function_id;
			real_module_name = temp_forward_string.substr(0, dot - 1);
			real_function_id = temp_forward_string.substr(dot + 1, string::npos);
 
			HMODULE real_module = this->get_module_handle(real_module_name.c_str());
			FARPROC tmp_ret;

			if (real_function_id.at(0) == '#')
			{
				UINT real_ord = 0;
				real_function_id.erase(0, 1);

				for (size_t i = 0; i < real_function_id.size(); ++i)
				{
					if(real_function_id[i] >= '0' && real_function_id[i] <= '9')
					{
						real_ord *= 10;
						real_ord += real_function_id[i] - '0';
					}
					else
						break;
				}
 
				tmp_ret = this->get_proc_address(real_module, NULL, real_ord, true);
			}
			else
				tmp_ret = this->get_proc_address(real_module, real_function_id.c_str(), 0, false);
			
			delete[] export_function_table;
			delete[] export_name_table;
			delete[] export_ordinal_table;
			
			return tmp_ret;
		}
		else
		{
			FARPROC tmp_ret = (FARPROC)(remote_module_base_va + export_function_table[function_table_index]);
				
			delete[] export_function_table;
			delete[] export_name_table;
			delete[] export_ordinal_table;
			
			return tmp_ret;
		}
	} 

	for (DWORD i = 0; i < export_table.NumberOfNames; i++)
	{
		string tmp_func_name;
 
		done = false;
		tmp_func_name.clear();

		for (UINT_PTR j = 0; !done; ++j)
		{
			if (!this->read_memory(remote_module_base_va + export_name_table[i] + j, sizeof temp_char, &temp_char, false))
				if (!this->read_memory(remote_module_base_va + export_name_table[i] + j, sizeof temp_char, &temp_char, true))
					goto FAIL_JMP;
 
			tmp_func_name.push_back(temp_char);

			if (temp_char == (char)'\0')
				done = true;
		}
 
		if (tmp_func_name.find(proc_name) != string::npos)
		{
			if (export_function_table[export_ordinal_table[i]] >= export_directory.VirtualAddress &&
				export_function_table[export_ordinal_table[i]] <= export_directory.VirtualAddress + export_directory.Size)
			{
				done = false;
				string temp_forward_string;
				temp_forward_string.clear();
				
				for (UINT_PTR j = 0; !done; ++j)
				{
					if (!this->read_memory(remote_module_base_va + export_function_table[i] + j, sizeof temp_char, &temp_char, false))
						if (!this->read_memory(remote_module_base_va + export_function_table[i] + j, sizeof temp_char, &temp_char, true))
							goto FAIL_JMP;
 
					temp_forward_string.push_back(temp_char);
					
					if (temp_char == (char)'\0')
						done = true;
				}
 
				size_t dot = temp_forward_string.find('.');
				if (dot == string::npos)
					goto FAIL_JMP;
 
				string real_module_name, real_function_id;
				real_module_name = temp_forward_string.substr(0, dot);
				real_function_id = temp_forward_string.substr(dot + 1, string::npos);
 
				HMODULE real_module = this->get_module_handle(real_module_name.c_str());
				FARPROC tmp_ret;

 				if (real_function_id.at(0) == '#')
				{
					UINT real_ord = 0;
					real_function_id.erase(0, 1);

					for (size_t i = 0; i < real_function_id.size(); ++i)
					{
						if (real_function_id[i] >= '0' && real_function_id[i] <= '9')
						{
							real_ord *= 10;
							real_ord += real_function_id[i] - '0';
						}
						else
							break;
					}
 
					tmp_ret = this->get_proc_address(real_module, NULL, real_ord, true);
				}
				else
					tmp_ret = this->get_proc_address(real_module, real_function_id.c_str(), 0, false);
				
				delete[] export_function_table;
				delete[] export_name_table;
				delete[] export_ordinal_table;
					
				return tmp_ret;
			}
			else
			{
				FARPROC tmp_ret;
				
				tmp_ret = (FARPROC)(remote_module_base_va + export_function_table[export_ordinal_table[i]]);
				
				delete[] export_function_table;
				delete[] export_name_table;
				delete[] export_ordinal_table;
				
				return tmp_ret;
			}
		}
	}
 
FAIL_JMP: 
	if (export_function_table != NULL)
		delete[] export_function_table;
	if (export_name_table != NULL)
		delete[] export_name_table;
	if (export_ordinal_table != NULL)
		delete[] export_ordinal_table;
 
	return NULL;
}
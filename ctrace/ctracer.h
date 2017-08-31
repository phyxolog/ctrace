#ifndef CTRACER_H
#define CTRACER_H

class ctracer {
public:
	ctracer();
	bool init();
	bool release();
	bool read_memory(DWORD dw_address, DWORD dw_size, LPVOID lp_buffer, bool b_protect);
	bool write_memory(DWORD dw_address, DWORD dw_size, LPVOID lp_buffer, bool b_protect);
	bool trace(DWORD dw_address);
	bool suspend();
	bool resume();
	BOOL get_context();
	BOOL set_context();
	DWORD get_image_base();
	bool dump_process_range(LPVOID lp_start_addr, DWORD dw_length, LPVOID lp_dumped);
	bool dump_to_file(LPSTR file_path, DWORD entry_point, bool sub_image_base);
	long long search_pattern(LPVOID memory_start, DWORD memory_size, LPVOID search_pattern, DWORD pattern_size, LPBYTE wild_card);
	char *get_current_instruction();
    unsigned long get_current_instruction_size();
	HMODULE get_module_handle(LPCSTR module_name);
	FARPROC get_proc_address(HMODULE h_module, LPCSTR proc_name, unsigned int ordinal = 0, bool use_ordinal = false);

	PROCESS_INFORMATION pi;
	_CONTEXT ctx;
	LPSTR file_name;

private:
	STARTUPINFO si;
	bool is_loaded;
	DWORD dw_image_base;
};

#endif
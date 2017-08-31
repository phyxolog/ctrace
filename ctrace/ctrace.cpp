#include "stdafx.h"
#include "ctracer.h"

int main(int argc, char *argv[])
{
	ctracer tracer;

	tracer.file_name = "passgen.exe";
	
	if (tracer.init())
		cout << "Trace init!" << endl;
	else
		cout << "Trace init error!" << endl;

	cout << "ImageBase: 0x" << hex << tracer.get_image_base() << endl;

	if (!tracer.trace(tracer.get_image_base() + 0x1B5EA3))
		cout << "Trace error!" << endl;
	else
		cout << "Trace succecfully!" << endl;

	/*
	005B5EA3   .^E9 00CAFBFF    JMP passgen.005728A8
	*/

	/*if (!tracer.trace_over())
		cout << "Trace over error!" << endl;
	else
		cout << "Trace over succecfully!" << endl;*/

	//tracer.trace_over_cond("call");
	//cout << hex << tracer.ctx.Eip << endl;

	if (tracer.dump_to_file("dump1.exe", 0x005728A8, false))
		cout << "Dump OK!" << endl;
	else
		cout << "Dump ERROR!" << endl;

	getchar();

	tracer.release();

	return 0;
}